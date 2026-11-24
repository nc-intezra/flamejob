//! HTTP handlers for the directory (AD/LDAP) config page and the login graft.
//!
//! Capability split (config-page Decision B2): `ViewDirectoryConfig` (admin +
//! superadmin) may read the redacted config and run tests; `ManageDirectory`
//! (superadmin only) may save, enable/disable, and edit the SID->role map.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use flamejob_api::{
    DirectoryConfigUpdate, DirectoryConfigView, DirectoryGrantEntry, DirectoryRoleMapEntry,
    DirectoryTestLoginRequest, DirectoryTestLoginResult, DirectoryTestRequest, DirectoryTestResult,
    DirectoryTestStep, GroupQuotaEntry,
};
use flamejob_core::{Capability, Role};

use super::client::{self, DirectoryError};
use super::{load_config, load_role_map, resolve};
use crate::auth::AuthUser;
use crate::error::AppError;
use crate::state::AppState;

fn role_to_str(r: Role) -> &'static str {
    match r {
        Role::Superadmin => "superadmin",
        Role::Admin => "admin",
        Role::Operator => "operator",
        Role::Viewer => "viewer",
    }
}

async fn audit(state: &AppState, actor: Option<Uuid>, action: &str, outcome: &str, detail: &str) {
    let _ = sqlx::query(
        "INSERT INTO audit_events (actor_user_id, action, target_type, outcome, detail) \
         VALUES ($1, $2, 'directory', $3, $4)",
    )
    .bind(actor)
    .bind(action)
    .bind(outcome)
    .bind(serde_json::json!({ "detail": detail }))
    .execute(&state.db)
    .await;
}

fn view_from(
    cfg: &super::DirectoryConfig,
    updated_at: Option<chrono::DateTime<Utc>>,
) -> DirectoryConfigView {
    DirectoryConfigView {
        enabled: cfg.enabled,
        transport: cfg.transport.as_str().to_string(),
        discovery: cfg.discovery.clone(),
        domain: cfg.domain.clone(),
        servers: cfg.servers.clone(),
        use_global_catalog: cfg.use_global_catalog,
        base_dn: cfg.base_dn.clone(),
        bind_dn: cfg.bind_dn.clone(),
        has_bind_password: cfg.bind_password_enc.is_some(),
        user_filter: cfg.user_filter.clone(),
        login_attributes: cfg.login_attributes.clone(),
        has_ca_bundle: cfg.ca_bundle_pem.is_some(),
        verify_hostname: cfg.verify_hostname,
        allow_insecure_tls: cfg.allow_insecure_tls,
        plaintext_ack: cfg.plaintext_ack,
        group_source: cfg.group_source.clone(),
        cache_ttl_secs: cfg.cache_ttl_secs,
        on_directory_down: cfg.on_directory_down.clone(),
        default_role: cfg.default_role,
        jwt_ttl_hours: cfg.jwt_ttl_hours,
        last_test_ok_at: cfg.last_test_ok_at,
        updated_at,
    }
}

async fn updated_at_of(state: &AppState) -> Option<chrono::DateTime<Utc>> {
    sqlx::query_scalar("SELECT updated_at FROM directory_config WHERE id = 1")
        .fetch_one(&state.db)
        .await
        .ok()
}

#[utoipa::path(
    get, path = "/admin/directory/config", tag = "directory", security(("bearer" = [])),
    responses((status = 200, body = DirectoryConfigView), (status = 403, description = "Missing ViewDirectoryConfig"))
)]
pub async fn get_directory_config(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<DirectoryConfigView>, AppError> {
    auth.require(Capability::ViewDirectoryConfig)?;
    let cfg = load_config(&state.db).await?;
    let updated = updated_at_of(&state).await;
    Ok(Json(view_from(&cfg, updated)))
}

#[utoipa::path(
    put, path = "/admin/directory/config", tag = "directory", security(("bearer" = [])),
    request_body = DirectoryConfigUpdate,
    responses((status = 200, body = DirectoryConfigView), (status = 403, description = "Missing ManageDirectory"))
)]
pub async fn put_directory_config(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DirectoryConfigUpdate>,
) -> Result<Json<DirectoryConfigView>, AppError> {
    auth.require(Capability::ManageDirectory)?;

    let transport = match body.transport.as_str() {
        "ldaps" | "starttls" | "plaintext" => body.transport.as_str(),
        _ => {
            return Err(AppError::BadRequest(
                "transport must be ldaps|starttls|plaintext".into(),
            ))
        }
    };
    if !matches!(body.discovery.as_str(), "srv" | "static") {
        return Err(AppError::BadRequest("discovery must be srv|static".into()));
    }
    if !matches!(
        body.on_directory_down.as_str(),
        "fail_closed" | "cache_only"
    ) {
        return Err(AppError::BadRequest(
            "on_directory_down must be fail_closed|cache_only".into(),
        ));
    }

    // Bind password: blank/None keeps the stored one; clear flag removes it; a
    // new value is encrypted at rest with the shared cipher.
    let new_pw = body
        .bind_password
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let pw_enc: Option<Vec<u8>> = if body.clear_bind_password {
        None
    } else if let Some(pw) = new_pw {
        Some(state.cipher.encrypt(pw.as_bytes()))
    } else {
        // Keep existing.
        sqlx::query_scalar("SELECT bind_password_enc FROM directory_config WHERE id = 1")
            .fetch_one(&state.db)
            .await?
    };

    let default_role_str = body.default_role.map(|r| role_to_str(r).to_string());

    sqlx::query(
        "UPDATE directory_config SET transport=$1, discovery=$2, domain=$3, servers=$4, \
         use_global_catalog=$5, base_dn=$6, bind_dn=$7, bind_password_enc=$8, user_filter=$9, \
         login_attributes=$10, ca_bundle_pem=$11, verify_hostname=$12, allow_insecure_tls=$13, \
         plaintext_ack=$14, group_source=$15, cache_ttl_secs=$16, on_directory_down=$17, \
         default_role=$18::role, jwt_ttl_hours=$19, updated_by=$20, updated_at=now() WHERE id=1",
    )
    .bind(transport)
    .bind(&body.discovery)
    .bind(&body.domain)
    .bind(&body.servers)
    .bind(body.use_global_catalog)
    .bind(&body.base_dn)
    .bind(&body.bind_dn)
    .bind(&pw_enc)
    .bind(&body.user_filter)
    .bind(&body.login_attributes)
    .bind(&body.ca_bundle_pem)
    .bind(body.verify_hostname)
    .bind(body.allow_insecure_tls)
    .bind(body.plaintext_ack)
    .bind(&body.group_source)
    .bind(body.cache_ttl_secs)
    .bind(&body.on_directory_down)
    .bind(&default_role_str)
    .bind(body.jwt_ttl_hours)
    .bind(auth.id)
    .execute(&state.db)
    .await?;

    audit(
        &state,
        Some(auth.id),
        "directory.config.update",
        "ok",
        "config saved",
    )
    .await;
    let cfg = load_config(&state.db).await?;
    Ok(Json(view_from(&cfg, updated_at_of(&state).await)))
}

#[utoipa::path(
    post, path = "/admin/directory/test", tag = "directory", security(("bearer" = [])),
    request_body = DirectoryTestRequest,
    responses((status = 200, body = DirectoryTestResult), (status = 403, description = "Missing ViewDirectoryConfig"))
)]
pub async fn test_directory(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DirectoryTestRequest>,
) -> Result<Json<DirectoryTestResult>, AppError> {
    auth.require(Capability::ViewDirectoryConfig)?;
    let cfg = load_config(&state.db).await?;
    let steps = client::test_connection(&cfg, &state.cipher, body.sample_user.as_deref()).await;
    let service_bind_ok = steps.iter().any(|s| s.name == "service-bind" && s.ok);
    let ok = !steps.is_empty() && steps.iter().all(|s| s.ok);
    // A fresh passing service bind gates "enable" (lockout safety).
    if service_bind_ok {
        let _ = sqlx::query("UPDATE directory_config SET last_test_ok_at = now() WHERE id = 1")
            .execute(&state.db)
            .await;
    }
    audit(
        &state,
        Some(auth.id),
        "directory.test",
        if ok { "ok" } else { "fail" },
        "connection test",
    )
    .await;
    Ok(Json(DirectoryTestResult {
        ok,
        steps: steps
            .into_iter()
            .map(|s| DirectoryTestStep {
                name: s.name,
                ok: s.ok,
                detail: s.detail,
            })
            .collect(),
    }))
}

#[utoipa::path(
    post, path = "/admin/directory/test-login", tag = "directory", security(("bearer" = [])),
    request_body = DirectoryTestLoginRequest,
    responses((status = 200, body = DirectoryTestLoginResult), (status = 403, description = "Missing ManageDirectory"))
)]
pub async fn test_login_directory(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DirectoryTestLoginRequest>,
) -> Result<Json<DirectoryTestLoginResult>, AppError> {
    // Handles a real user password, so require the write capability.
    auth.require(Capability::ManageDirectory)?;
    let cfg = load_config(&state.db).await?;
    match client::authenticate(&cfg, &state.cipher, &body.username, &body.password).await {
        Ok(user) => {
            let role_map = load_role_map(&state.db).await?;
            let roles = resolve::resolve_roles(&user.group_sids, &role_map, cfg.default_role);
            Ok(Json(DirectoryTestLoginResult {
                ok: true,
                detail: format!("authenticated via {}", user.server),
                dn: Some(user.dn),
                sid: user.sid,
                group_sids: user.group_sids,
                roles,
            }))
        }
        Err(e) => Ok(Json(DirectoryTestLoginResult {
            ok: false,
            detail: describe_dir_error(&e),
            dn: None,
            sid: None,
            group_sids: Vec::new(),
            roles: Vec::new(),
        })),
    }
}

#[derive(Debug, Deserialize)]
pub struct EnableParams {
    #[serde(default)]
    pub force: bool,
}

#[utoipa::path(
    post, path = "/admin/directory/enable", tag = "directory", security(("bearer" = [])),
    responses((status = 200, body = DirectoryConfigView), (status = 400, description = "Not test-gated or incomplete config"), (status = 403, description = "Missing ManageDirectory"))
)]
pub async fn enable_directory(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<EnableParams>,
) -> Result<Json<DirectoryConfigView>, AppError> {
    auth.require(Capability::ManageDirectory)?;
    let cfg = load_config(&state.db).await?;

    // Required fields to actually authenticate.
    if cfg.base_dn.as_deref().unwrap_or("").is_empty()
        || cfg.bind_dn.as_deref().unwrap_or("").is_empty()
        || cfg.bind_password_enc.is_none()
        || cfg.servers.is_empty()
    {
        return Err(AppError::BadRequest(
            "cannot enable: base DN, service bind DN + password, and at least one server are required".into(),
        ));
    }
    if cfg.transport == super::Transport::Plaintext && !cfg.plaintext_ack {
        return Err(AppError::BadRequest(
            "plaintext transport must be acknowledged before enabling".into(),
        ));
    }
    // Lockout safety: require a recent passing service-bind test unless forced.
    let fresh = cfg
        .last_test_ok_at
        .map(|t| Utc::now() - t < Duration::minutes(30))
        .unwrap_or(false);
    if !fresh && !params.force {
        return Err(AppError::BadRequest(
            "run a successful connection test first (or pass ?force=true)".into(),
        ));
    }

    sqlx::query("UPDATE directory_config SET enabled = true, updated_by = $1, updated_at = now() WHERE id = 1")
        .bind(auth.id)
        .execute(&state.db)
        .await?;
    audit(
        &state,
        Some(auth.id),
        "directory.enable",
        "ok",
        "directory auth enabled",
    )
    .await;
    let cfg = load_config(&state.db).await?;
    Ok(Json(view_from(&cfg, updated_at_of(&state).await)))
}

#[utoipa::path(
    post, path = "/admin/directory/disable", tag = "directory", security(("bearer" = [])),
    responses((status = 200, body = DirectoryConfigView), (status = 403, description = "Missing ManageDirectory"))
)]
pub async fn disable_directory(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<DirectoryConfigView>, AppError> {
    auth.require(Capability::ManageDirectory)?;
    sqlx::query("UPDATE directory_config SET enabled = false, updated_by = $1, updated_at = now() WHERE id = 1")
        .bind(auth.id)
        .execute(&state.db)
        .await?;
    audit(
        &state,
        Some(auth.id),
        "directory.disable",
        "ok",
        "directory auth disabled",
    )
    .await;
    let cfg = load_config(&state.db).await?;
    Ok(Json(view_from(&cfg, updated_at_of(&state).await)))
}

// ---- SID -> role map admin ----

#[utoipa::path(
    get, path = "/admin/directory/role-map", tag = "directory", security(("bearer" = [])),
    responses((status = 200, body = [DirectoryRoleMapEntry]), (status = 403, description = "Missing ViewDirectoryConfig"))
)]
pub async fn list_role_map(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<DirectoryRoleMapEntry>>, AppError> {
    auth.require(Capability::ViewDirectoryConfig)?;
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT group_sid, role::text, group_cn FROM directory_role_map ORDER BY group_sid, role",
    )
    .fetch_all(&state.db)
    .await?;
    let out = rows
        .into_iter()
        .filter_map(|(sid, role, cn)| {
            serde_json::from_value::<Role>(serde_json::Value::String(role))
                .ok()
                .map(|role| DirectoryRoleMapEntry {
                    group_sid: sid,
                    role,
                    group_cn: cn,
                })
        })
        .collect();
    Ok(Json(out))
}

#[utoipa::path(
    post, path = "/admin/directory/role-map", tag = "directory", security(("bearer" = [])),
    request_body = DirectoryRoleMapEntry,
    responses((status = 200, description = "Added"), (status = 403, description = "Missing ManageDirectory"))
)]
pub async fn add_role_map(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(entry): Json<DirectoryRoleMapEntry>,
) -> Result<Json<DirectoryRoleMapEntry>, AppError> {
    auth.require(Capability::ManageDirectory)?;
    let sid = entry.group_sid.trim();
    if sid.is_empty() {
        return Err(AppError::BadRequest("group_sid is required".into()));
    }
    sqlx::query(
        "INSERT INTO directory_role_map (group_sid, role, group_cn, created_by) \
         VALUES ($1, $2::role, $3, $4) ON CONFLICT (group_sid, role) DO UPDATE SET group_cn = EXCLUDED.group_cn",
    )
    .bind(sid)
    .bind(role_to_str(entry.role))
    .bind(&entry.group_cn)
    .bind(auth.id)
    .execute(&state.db)
    .await?;
    audit(&state, Some(auth.id), "directory.role_map.add", "ok", sid).await;
    Ok(Json(entry))
}

#[utoipa::path(
    delete, path = "/admin/directory/role-map", tag = "directory", security(("bearer" = [])),
    request_body = DirectoryRoleMapEntry,
    responses((status = 200, description = "Removed"), (status = 403, description = "Missing ManageDirectory"))
)]
pub async fn delete_role_map(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(entry): Json<DirectoryRoleMapEntry>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require(Capability::ManageDirectory)?;
    sqlx::query("DELETE FROM directory_role_map WHERE group_sid = $1 AND role = $2::role")
        .bind(entry.group_sid.trim())
        .bind(role_to_str(entry.role))
        .execute(&state.db)
        .await?;
    audit(
        &state,
        Some(auth.id),
        "directory.role_map.remove",
        "ok",
        entry.group_sid.trim(),
    )
    .await;
    Ok(Json(serde_json::json!({ "removed": true })))
}

fn describe_dir_error(e: &DirectoryError) -> String {
    match e {
        DirectoryError::Config(m) => format!("config error: {m}"),
        DirectoryError::Unreachable(m) => format!("directory unreachable: {m}"),
        DirectoryError::NoSuchUser => "no such user".into(),
        DirectoryError::BadCredentials(m) => m.clone(),
    }
}

/// Attempt a directory login as part of the `/auth/login` provider chain.
///
/// Returns `Ok(None)` when directory auth is disabled (so the caller falls back
/// to local auth). On a verified directory login it shadow-upserts the user,
/// syncs `user_roles` to the resolved set, and returns `(user_id, roles)`.
/// Honors `on_directory_down`: fail-closed denies when the directory is
/// unreachable; default-deny denies when the user maps to no role.
pub async fn try_directory_login(
    state: &AppState,
    username: &str,
    password: &str,
) -> Result<Option<(Uuid, Vec<Role>)>, AppError> {
    let cfg = load_config(&state.db).await?;
    if !cfg.enabled {
        return Ok(None);
    }
    let user = match client::authenticate(&cfg, &state.cipher, username, password).await {
        Ok(u) => u,
        Err(DirectoryError::Unreachable(m)) => {
            audit(state, None, "directory.login", "unreachable", &m).await;
            // fail_closed (default) denies; cache_only would serve a cached
            // resolution — a tracked follow-up (no runtime cache in PR1).
            return Err(AppError::Unauthorized("directory unreachable".into()));
        }
        Err(e) => {
            audit(
                state,
                None,
                "directory.login",
                "denied",
                &describe_dir_error(&e),
            )
            .await;
            return Err(AppError::Unauthorized("invalid credentials".into()));
        }
    };

    let role_map = load_role_map(&state.db).await?;
    let roles = resolve::resolve_roles(&user.group_sids, &role_map, cfg.default_role);
    if roles.is_empty() {
        audit(
            state,
            None,
            "directory.login",
            "denied",
            "no mapped role (default deny)",
        )
        .await;
        return Err(AppError::Forbidden(
            "your directory groups grant no flamejob role".into(),
        ));
    }

    // Shadow-upsert the user and sync roles in one transaction.
    let mut tx = state.db.begin().await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, source, external_sid, disabled) VALUES ($1, 'directory', $2, false) \
         ON CONFLICT (username) DO UPDATE SET source='directory', external_sid=EXCLUDED.external_sid, disabled=false \
         RETURNING id",
    )
    .bind(username)
    .bind(&user.sid)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for r in &roles {
        sqlx::query("INSERT INTO user_roles (user_id, role) VALUES ($1, $2::role)")
            .bind(id)
            .bind(role_to_str(*r))
            .execute(&mut *tx)
            .await?;
    }
    // Cache the resolved group SIDs so job submission / scheduling can resolve
    // pool eligibility (PR2) without re-querying the directory each time.
    sqlx::query("DELETE FROM user_dir_groups WHERE user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for sid in &user.group_sids {
        sqlx::query(
            "INSERT INTO user_dir_groups (user_id, group_sid) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(sid)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    audit(
        state,
        Some(id),
        "directory.login",
        "ok",
        &format!("roles={roles:?}"),
    )
    .await;
    Ok(Some((id, roles)))
}

// ---- directory group -> pool grants (ManageDirectory) ----

#[utoipa::path(
    get, path = "/admin/directory/grants", tag = "directory", security(("bearer" = [])),
    responses((status = 200, body = [DirectoryGrantEntry]), (status = 403, description = "Missing ViewDirectoryConfig"))
)]
pub async fn list_grants(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<DirectoryGrantEntry>>, AppError> {
    auth.require(Capability::ViewDirectoryConfig)?;
    let rows: Vec<(String, Uuid, String)> = sqlx::query_as(
        "SELECT g.group_sid, g.pool_id, p.name FROM directory_agent_grants g \
         JOIN agent_pools p ON p.id = g.pool_id ORDER BY g.group_sid, p.name",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(group_sid, pool_id, pool_name)| DirectoryGrantEntry {
                group_sid,
                pool_id,
                pool_name: Some(pool_name),
                group_cn: None,
            })
            .collect(),
    ))
}

#[utoipa::path(
    post, path = "/admin/directory/grants", tag = "directory", security(("bearer" = [])),
    request_body = DirectoryGrantEntry,
    responses((status = 200, description = "Granted"), (status = 403, description = "Missing ManageDirectory"))
)]
pub async fn add_grant(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(entry): Json<DirectoryGrantEntry>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require(Capability::ManageDirectory)?;
    let sid = entry.group_sid.trim();
    if sid.is_empty() {
        return Err(AppError::BadRequest("group_sid is required".into()));
    }
    sqlx::query(
        "INSERT INTO directory_agent_grants (group_sid, pool_id, created_by) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(sid)
    .bind(entry.pool_id)
    .bind(auth.id)
    .execute(&state.db)
    .await
    .map_err(|_| AppError::BadRequest("unknown pool".into()))?;
    audit(&state, Some(auth.id), "directory.grant.add", "ok", sid).await;
    Ok(Json(serde_json::json!({ "granted": true })))
}

#[utoipa::path(
    delete, path = "/admin/directory/grants", tag = "directory", security(("bearer" = [])),
    request_body = DirectoryGrantEntry,
    responses((status = 200, description = "Revoked"), (status = 403, description = "Missing ManageDirectory"))
)]
pub async fn remove_grant(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(entry): Json<DirectoryGrantEntry>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require(Capability::ManageDirectory)?;
    sqlx::query("DELETE FROM directory_agent_grants WHERE group_sid = $1 AND pool_id = $2")
        .bind(entry.group_sid.trim())
        .bind(entry.pool_id)
        .execute(&state.db)
        .await?;
    audit(
        &state,
        Some(auth.id),
        "directory.grant.remove",
        "ok",
        entry.group_sid.trim(),
    )
    .await;
    Ok(Json(serde_json::json!({ "revoked": true })))
}

// ---- per-group fair-share quotas (PR3) ----

#[utoipa::path(
    get, path = "/admin/directory/quotas", tag = "directory", security(("bearer" = [])),
    responses((status = 200, body = [GroupQuotaEntry]), (status = 403, description = "Missing ViewDirectoryConfig"))
)]
pub async fn list_quotas(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<GroupQuotaEntry>>, AppError> {
    auth.require(Capability::ViewDirectoryConfig)?;
    type QuotaRow = (String, i32, i32, Option<i32>, Option<i32>, Option<String>);
    let rows: Vec<QuotaRow> = sqlx::query_as(
        "SELECT group_sid, weight, floor_slots, ceil_slots, max_submit_jobs, group_cn \
         FROM group_quota ORDER BY group_sid",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(group_sid, weight, floor_slots, ceil_slots, max_submit_jobs, group_cn)| {
                    GroupQuotaEntry {
                        group_sid,
                        weight,
                        floor_slots,
                        ceil_slots,
                        max_submit_jobs,
                        group_cn,
                    }
                },
            )
            .collect(),
    ))
}

#[utoipa::path(
    put, path = "/admin/directory/quotas", tag = "directory", security(("bearer" = [])),
    request_body = GroupQuotaEntry,
    responses((status = 200, description = "Saved"), (status = 403, description = "Missing ManageDirectory"))
)]
pub async fn put_quota(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(q): Json<GroupQuotaEntry>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require(Capability::ManageDirectory)?;
    let sid = q.group_sid.trim();
    if sid.is_empty() {
        return Err(AppError::BadRequest("group_sid is required".into()));
    }
    if q.weight <= 0 {
        return Err(AppError::BadRequest("weight must be > 0".into()));
    }
    if q.floor_slots < 0
        || q.ceil_slots.is_some_and(|c| c < 0)
        || q.max_submit_jobs.is_some_and(|m| m < 0)
    {
        return Err(AppError::BadRequest("slot limits must be >= 0".into()));
    }
    sqlx::query(
        "INSERT INTO group_quota (group_sid, weight, floor_slots, ceil_slots, max_submit_jobs, group_cn, updated_by, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now()) \
         ON CONFLICT (group_sid) DO UPDATE SET weight = EXCLUDED.weight, floor_slots = EXCLUDED.floor_slots, \
           ceil_slots = EXCLUDED.ceil_slots, max_submit_jobs = EXCLUDED.max_submit_jobs, \
           group_cn = EXCLUDED.group_cn, updated_by = EXCLUDED.updated_by, updated_at = now()",
    )
    .bind(sid)
    .bind(q.weight)
    .bind(q.floor_slots)
    .bind(q.ceil_slots)
    .bind(q.max_submit_jobs)
    .bind(&q.group_cn)
    .bind(auth.id)
    .execute(&state.db)
    .await?;
    audit(&state, Some(auth.id), "directory.quota.update", "ok", sid).await;
    Ok(Json(serde_json::json!({ "saved": true })))
}

#[utoipa::path(
    delete, path = "/admin/directory/quotas", tag = "directory", security(("bearer" = [])),
    request_body = GroupQuotaEntry,
    responses((status = 200, description = "Removed"), (status = 403, description = "Missing ManageDirectory"))
)]
pub async fn delete_quota(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(q): Json<GroupQuotaEntry>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require(Capability::ManageDirectory)?;
    sqlx::query("DELETE FROM group_quota WHERE group_sid = $1")
        .bind(q.group_sid.trim())
        .execute(&state.db)
        .await?;
    audit(
        &state,
        Some(auth.id),
        "directory.quota.remove",
        "ok",
        q.group_sid.trim(),
    )
    .await;
    Ok(Json(serde_json::json!({ "removed": true })))
}
