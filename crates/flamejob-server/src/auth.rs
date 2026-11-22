use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use chrono::{Duration, Utc};
use flamejob_core::{roles_have, Capability, Role};
use jsonwebtoken::{decode, encode, Algorithm, Header, Validation};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::AppError;
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub username: String,
    pub roles: Vec<Role>,
    pub exp: i64,
    pub iat: i64,
}

pub fn issue_token(
    state: &AppState,
    id: Uuid,
    username: &str,
    roles: &[Role],
) -> Result<(String, chrono::DateTime<Utc>), AppError> {
    let now = Utc::now();
    let exp = now + Duration::hours(state.cfg.auth.token_ttl_hours.max(1));
    let claims = Claims {
        sub: id,
        username: username.to_string(),
        roles: roles.to_vec(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };
    let token = encode(&Header::new(Algorithm::HS256), &claims, &state.encode_key)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((token, exp))
}

pub fn hash_password(pw: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .and_then(|parsed| Argon2::default().verify_password(pw.as_bytes(), &parsed))
        .is_ok()
}

pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub roles: Vec<Role>,
}

impl AuthUser {
    pub fn require(&self, cap: Capability) -> Result<(), AppError> {
        if roles_have(&self.roles, cap) {
            Ok(())
        } else {
            Err(AppError::Forbidden(format!("missing capability {cap:?}")))
        }
    }
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing bearer token".into()))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("malformed authorization header".into()))?;
        // Personal API keys are prefixed `fj_`; everything else is a login JWT.
        if token.starts_with("fj_") {
            return authenticate_api_key(state, token).await;
        }
        let data = decode::<Claims>(token, &state.decode_key, &Validation::new(Algorithm::HS256))
            .map_err(|e| AppError::Unauthorized(e.to_string()))?;
        let c = data.claims;
        Ok(AuthUser {
            id: c.sub,
            username: c.username,
            roles: c.roles,
        })
    }
}

/// Hex SHA-256 of an API key's full secret — what we store and look up by.
pub fn api_key_hash(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

/// Resolve an `fj_…` API key to its user, enforcing revocation/expiry, and stamp
/// its last-used time. Roles are loaded live, so role changes take effect at once.
async fn authenticate_api_key(state: &AppState, token: &str) -> Result<AuthUser, AppError> {
    let hash = api_key_hash(token);
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT u.id, u.username FROM api_keys k JOIN users u ON u.id = k.user_id \
         WHERE k.key_hash = $1 AND NOT k.revoked AND NOT u.disabled \
           AND (k.expires_at IS NULL OR k.expires_at > now())",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    let (id, username) = row.ok_or_else(|| AppError::Unauthorized("invalid API key".into()))?;
    // Best-effort usage stamp; a failure here must not block the request.
    let _ = sqlx::query("UPDATE api_keys SET last_used_at = now() WHERE key_hash = $1")
        .bind(&hash)
        .execute(&state.db)
        .await;
    let roles = load_roles_for(state, id).await;
    Ok(AuthUser {
        id,
        username,
        roles,
    })
}

async fn load_roles_for(state: &AppState, user_id: Uuid) -> Vec<Role> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT role::text FROM user_roles WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
    rows.iter()
        .filter_map(|(r,)| serde_json::from_value(serde_json::Value::String(r.clone())).ok())
        .collect()
}
