//! Sitewide settings (superadmin/admin): the runtime TLS configuration for the
//! optional HTTPS-on-443 dashboard listener.
//!
//! The certificate (PEM, public) and private key (PEM, encrypted at rest with
//! the plaintext cipher) live in the singleton `site_settings` row. Changing it
//! bumps `state.tls_reload`, which the listener manager in `web.rs` watches to
//! (re)bind or drop the :443 listener live. The plain HTTP dashboard is never
//! touched.

use axum::extract::State;
use axum::Json;

use flamejob_api::{SiteSettingsUpdate, SiteSettingsView};
use flamejob_core::Capability;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::state::AppState;

type SettingsRow = (
    bool,
    Option<String>,
    Option<Vec<u8>>,
    Option<chrono::DateTime<chrono::Utc>>,
);

async fn fetch_row(state: &AppState) -> Result<SettingsRow, AppError> {
    let row: SettingsRow = sqlx::query_as(
        "SELECT https_enabled, tls_cert_pem, tls_key_enc, updated_at FROM site_settings WHERE id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    Ok(row)
}

fn view_from(state: &AppState, row: &SettingsRow) -> SiteSettingsView {
    let cert_fingerprint = row
        .1
        .as_deref()
        .and_then(|pem| crate::pki::fingerprint_of_pem(pem).ok());
    SiteSettingsView {
        https_enabled: row.0,
        has_cert: row.1.is_some(),
        has_key: row.2.is_some(),
        https_listening: state
            .tls_listening
            .load(std::sync::atomic::Ordering::Relaxed),
        https_bind: state.cfg.web.https_bind.clone(),
        cert_fingerprint,
        updated_at: row.3,
    }
}

#[utoipa::path(
    get, path = "/admin/site-settings", tag = "meta", security(("bearer" = [])),
    responses(
        (status = 200, body = SiteSettingsView, description = "Current sitewide settings"),
        (status = 403, description = "Missing ManageSettings")
    )
)]
pub async fn get_site_settings(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SiteSettingsView>, AppError> {
    auth.require(Capability::ManageSettings)?;
    let row = fetch_row(&state).await?;
    Ok(Json(view_from(&state, &row)))
}

#[utoipa::path(
    put, path = "/admin/site-settings", tag = "meta", security(("bearer" = [])),
    request_body = SiteSettingsUpdate,
    responses(
        (status = 200, body = SiteSettingsView, description = "Updated sitewide settings"),
        (status = 400, description = "Invalid certificate/key, or enabling HTTPS without both"),
        (status = 403, description = "Missing ManageSettings")
    )
)]
pub async fn put_site_settings(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<SiteSettingsUpdate>,
) -> Result<Json<SiteSettingsView>, AppError> {
    auth.require(Capability::ManageSettings)?;
    let row = fetch_row(&state).await?;

    // A provided-but-blank PEM means "keep the existing value", not "clear it".
    let new_cert = body
        .tls_cert_pem
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let new_key = body
        .tls_key_pem
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    // Effective cert/key after applying this update (new value wins, else keep).
    let eff_cert: Option<String> = new_cert.clone().or_else(|| row.1.clone());
    let eff_key: Option<String> = match &new_key {
        Some(k) => Some(k.clone()),
        None => row
            .2
            .as_deref()
            .and_then(|enc| state.cipher.decrypt(enc))
            .and_then(|v| String::from_utf8(v).ok()),
    };

    // Validate: a cert+key pair present on this update must actually load, and
    // enabling HTTPS requires both to be present.
    if body.https_enabled && (eff_cert.is_none() || eff_key.is_none()) {
        return Err(AppError::BadRequest(
            "enabling HTTPS requires both a certificate and a private key".into(),
        ));
    }
    if let (Some(cert), Some(key)) = (&eff_cert, &eff_key) {
        // Only bother validating when something changed or HTTPS is being enabled.
        if new_cert.is_some() || new_key.is_some() || body.https_enabled {
            axum_server::tls_rustls::RustlsConfig::from_pem(
                cert.as_bytes().to_vec(),
                key.as_bytes().to_vec(),
            )
            .await
            .map_err(|e| {
                AppError::BadRequest(format!("certificate/key is not a valid PEM pair: {e}"))
            })?;
        }
    }

    // Persist. Re-encrypt the key only when a new one was supplied.
    let key_enc: Option<Vec<u8>> = match &new_key {
        Some(k) => Some(state.cipher.encrypt(k.as_bytes())),
        None => row.2.clone(),
    };
    let cert_to_store: Option<String> = new_cert.or(row.1.clone());
    sqlx::query(
        "UPDATE site_settings SET https_enabled = $1, tls_cert_pem = $2, tls_key_enc = $3, \
         updated_at = now(), updated_by = $4 WHERE id = 1",
    )
    .bind(body.https_enabled)
    .bind(&cert_to_store)
    .bind(&key_enc)
    .bind(auth.id)
    .execute(&state.db)
    .await?;

    tracing::info!(user = %auth.username, https_enabled = body.https_enabled, "sitewide TLS settings updated");
    // Tell the :443 listener manager to re-read and (re)bind or drop.
    state.tls_reload.send_modify(|v| *v = v.wrapping_add(1));

    let row = fetch_row(&state).await?;
    Ok(Json(view_from(&state, &row)))
}

/// Decrypted TLS material for the listener manager: `Some((cert_pem, key_pem))`
/// only when HTTPS is enabled and both are present and the key decrypts.
pub async fn tls_material(state: &AppState) -> Option<(Vec<u8>, Vec<u8>)> {
    let row = fetch_row(state).await.ok()?;
    if !row.0 {
        return None;
    }
    let cert = row.1?;
    let key = row.2.as_deref().and_then(|enc| state.cipher.decrypt(enc))?;
    Some((cert.into_bytes(), key))
}

#[cfg(test)]
mod tests {
    use crate::crypto::Cipher;

    // The TLS private key is stored encrypted at rest: ciphertext must differ
    // from the PEM and decrypt back to it exactly (same cipher as the stored key).
    #[test]
    fn private_key_encryption_round_trips() {
        let cipher = Cipher::from_bytes([7u8; 32]);
        let key_pem = "-----BEGIN PRIVATE KEY-----\nMIIexampleBASE64\n-----END PRIVATE KEY-----\n";
        let enc = cipher.encrypt(key_pem.as_bytes());
        assert_ne!(
            enc.as_slice(),
            key_pem.as_bytes(),
            "key must not be stored in cleartext"
        );
        let dec = cipher.decrypt(&enc).expect("stored key decrypts");
        assert_eq!(dec, key_pem.as_bytes());
    }
}
