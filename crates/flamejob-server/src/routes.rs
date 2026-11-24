use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::Html;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use flamejob_api::*;
use flamejob_core::{Capability, JobState, TaskState};
use flamejob_db::models::HashlistRow;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use uuid::Uuid;

/// Maximum size of a single file upload accepted by `POST /files`, enforced as
/// the route's `DefaultBodyLimit` (overriding axum's 2 MB default). The handler
/// streams the body to disk, so this bounds the request, not memory. Surfaced to
/// the dashboard (via the injected config) so the ingest pane can gauge each
/// file against the per-request ceiling before uploading.
pub const MAX_FILE_UPLOAD_BYTES: usize = 8 * 1024 * 1024 * 1024; // 8 GiB

/// Compact binary-unit byte formatting (GiB/MiB/KiB) for human-facing messages,
/// matching the dashboard's `fmtBytesBin`.
fn human_bytes(n: i64) -> String {
    const GIB: i64 = 1024 * 1024 * 1024;
    const MIB: i64 = 1024 * 1024;
    const KIB: i64 = 1024;
    if n >= GIB {
        format!("{:.1} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

use crate::auth::{self, AuthUser};
use crate::error::AppError;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let cors = cors_layer(&state);
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/docs", get(api_docs))
        .route("/devices", get(list_devices))
        .route("/devices/:name/history", get(device_history))
        .route("/agents", get(crate::agent::list_agents))
        .route("/agent/enroll", post(crate::agent::enroll))
        .route("/agent/stream", get(crate::agent::agent_stream))
        .route("/agent/files/:id", get(crate::agent::download_file))
        .route("/admin/agent-claims", post(crate::agent::create_claim))
        .route(
            "/admin/site-settings",
            get(crate::settings::get_site_settings).put(crate::settings::put_site_settings),
        )
        .route("/openapi.json", get(openapi))
        .route("/auth/login", post(login))
        .route("/auth/me", get(me))
        .route("/auth/api-keys", get(list_api_keys).post(create_api_key))
        .route("/auth/api-keys/:id", delete(revoke_api_key))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/clear", post(clear_finished_jobs))
        .route("/jobs/history", get(list_job_history))
        .route("/jobs/:id", get(get_job).patch(patch_job))
        .route("/jobs/:id/tasks", get(list_job_tasks))
        .route("/jobs/:id/pause", post(pause_job))
        .route("/jobs/:id/resume", post(resume_job))
        .route("/jobs/:id/cancel", post(cancel_job))
        .route("/jobs/:id/pin", post(pin_job).delete(unpin_job))
        .route("/hashlists", get(list_hashlists).post(create_hashlist))
        .route("/hashlists/:id/cracked", get(list_cracked))
        .route("/hashlists/:id/hashes", post(import_hashes))
        .route(
            "/files",
            // Wordlists are large; lift axum's 2 MB default body cap for uploads
            // (the handler streams the body to disk, so this isn't held in memory).
            get(list_files)
                .post(upload_file)
                .layer(DefaultBodyLimit::max(MAX_FILE_UPLOAD_BYTES)),
        )
        .route("/files/usage", get(storage_usage))
        .route("/files/:id", delete(delete_file))
        .route("/events", get(events))
        .route("/admin/users", post(create_user))
        .layer(cors)
        .with_state(state)
}

/// CORS for the API so the browser-served dashboard (a different origin, e.g.
/// `:9443`) can call it. Bearer-token auth still gates every protected route;
/// with no configured origins we allow any (no credentials/cookies are used).
fn cors_layer(state: &AppState) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any);
    let origins = &state.cfg.web.allowed_origins;
    if origins.is_empty() {
        base.allow_origin(Any)
    } else {
        let list: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|o| o.parse::<HeaderValue>().ok())
            .collect();
        base.allow_origin(AllowOrigin::list(list))
    }
}

/// Interactive, browseable API reference (RapiDoc) bound to `/openapi.json`.
async fn api_docs() -> Html<&'static str> {
    Html(include_str!("web/docs.html"))
}

// ---- meta ----

async fn healthz() -> &'static str {
    "ok"
}

async fn metrics(State(state): State<AppState>) -> String {
    state.metrics.render()
}

async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(crate::openapi::document())
}

// ---- auth ----

#[utoipa::path(
    post, path = "/auth/login", tag = "auth", request_body = LoginRequest,
    responses(
        (status = 200, description = "Issued JWT and roles", body = LoginResponse),
        (status = 401, description = "Invalid credentials")
    )
)]
async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let row: Option<(Uuid, Option<String>)> =
        sqlx::query_as("SELECT id, password_hash FROM users WHERE username = $1 AND NOT disabled")
            .bind(&body.username)
            .fetch_optional(&state.db)
            .await?;
    let (id, Some(hash)) =
        row.ok_or_else(|| AppError::Unauthorized("invalid credentials".into()))?
    else {
        return Err(AppError::Unauthorized("invalid credentials".into()));
    };
    if !auth::verify_password(&body.password, &hash) {
        return Err(AppError::Unauthorized("invalid credentials".into()));
    }
    let roles = load_roles(&state, id).await?;
    let (token, expires_at) = auth::issue_token(&state, id, &body.username, &roles)?;
    Ok(Json(LoginResponse {
        token,
        expires_at,
        roles,
    }))
}

#[utoipa::path(
    get, path = "/auth/me", tag = "auth", security(("bearer" = [])),
    responses((status = 200, body = MeResponse), (status = 401, description = "Unauthenticated"))
)]
async fn me(auth: AuthUser) -> Json<MeResponse> {
    Json(MeResponse {
        id: auth.id,
        username: auth.username,
        roles: auth.roles,
    })
}

// ---- API keys (per-user, revocable) ----

/// Mint a fresh secret: `fj_` + 160 random bits (hex). Returns the full secret,
/// a non-secret display prefix, and the SHA-256 hash to store.
fn generate_api_key() -> (String, String, String) {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    let secret = format!("fj_{}", hex::encode(bytes));
    let prefix = secret[..10].to_string(); // "fj_" + first 7 hex chars
    let hash = auth::api_key_hash(&secret);
    (secret, prefix, hash)
}

#[utoipa::path(
    post, path = "/auth/api-keys", tag = "auth", security(("bearer" = [])),
    request_body = ApiKeyCreate,
    responses(
        (status = 200, description = "Key created — secret shown once", body = ApiKeyCreated),
        (status = 401, description = "Unauthenticated")
    )
)]
async fn create_api_key(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ApiKeyCreate>,
) -> Result<Json<ApiKeyCreated>, AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("key name is required".into()));
    }
    // Default to a 1-year lifetime; `0` (or negative) means it never expires.
    let days = body.expires_in_days.unwrap_or(365);
    let expires_at = (days > 0).then(|| Utc::now() + chrono::Duration::days(days));
    let (secret, prefix, hash) = generate_api_key();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO api_keys (user_id, name, prefix, key_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(auth.id)
    .bind(name)
    .bind(&prefix)
    .bind(&hash)
    .bind(expires_at)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(ApiKeyCreated {
        id,
        name: name.to_string(),
        prefix,
        key: secret,
        expires_at,
    }))
}

#[utoipa::path(
    get, path = "/auth/api-keys", tag = "auth", security(("bearer" = [])),
    responses(
        (status = 200, description = "The caller's keys (secrets never returned)", body = [ApiKeyView]),
        (status = 401, description = "Unauthenticated")
    )
)]
async fn list_api_keys(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<ApiKeyView>>, AppError> {
    type Row = (
        Uuid,
        String,
        String,
        chrono::DateTime<Utc>,
        Option<chrono::DateTime<Utc>>,
        Option<chrono::DateTime<Utc>>,
        bool,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, name, prefix, created_at, expires_at, last_used_at, revoked \
         FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(auth.id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(id, name, prefix, created_at, expires_at, last_used_at, revoked)| ApiKeyView {
                    id,
                    name,
                    prefix,
                    created_at,
                    expires_at,
                    last_used_at,
                    revoked,
                },
            )
            .collect(),
    ))
}

#[utoipa::path(
    delete, path = "/auth/api-keys/{id}", tag = "auth", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "API key id")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 404, description = "Not found or already revoked")
    )
)]
async fn revoke_api_key(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let res = sqlx::query(
        "UPDATE api_keys SET revoked = true WHERE id = $1 AND user_id = $2 AND NOT revoked",
    )
    .bind(id)
    .bind(auth.id)
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("api key not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn load_roles(state: &AppState, user_id: Uuid) -> Result<Vec<flamejob_core::Role>, AppError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT role::text FROM user_roles WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&state.db)
            .await?;
    Ok(rows.iter().filter_map(|(r,)| parse_role(r)).collect())
}

// ---- jobs ----

#[utoipa::path(
    get, path = "/jobs", tag = "jobs", security(("bearer" = [])),
    responses((status = 200, body = Vec<JobView>, description = "All jobs, queue order"))
)]
async fn list_jobs(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<JobView>>, AppError> {
    auth.require(Capability::ViewJobs)?;
    let rows: Vec<JobAgg> =
        sqlx::query_as(&format!("{JOB_SELECT} ORDER BY j.priority, j.created_at"))
            .fetch_all(&state.db)
            .await?;
    let running = running_agents_by_job(&state).await;
    Ok(Json(
        rows.into_iter()
            .map(|r| {
                let mut v = job_view(r);
                if let Some(names) = running.get(&v.id) {
                    v.running_agents = names.clone();
                }
                v
            })
            .collect(),
    ))
}

#[utoipa::path(
    post, path = "/jobs", tag = "jobs", security(("bearer" = [])), request_body = JobCreate,
    responses((status = 201, body = JobView), (status = 403, description = "Missing SubmitJobs"))
)]
async fn create_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<JobCreate>,
) -> Result<(StatusCode, Json<JobView>), AppError> {
    auth.require(Capability::SubmitJobs)?;
    let id = Uuid::new_v4();
    let priority = body.priority.unwrap_or(100);
    let config =
        serde_json::to_value(&body.config).map_err(|e| AppError::BadRequest(e.to_string()))?;
    sqlx::query(
        "INSERT INTO jobs (id, name, owner_user_id, hashlist_id, attack_mode, config, priority) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(&body.name)
    .bind(auth.id)
    .bind(body.hashlist_id)
    .bind(body.attack_mode)
    .bind(config)
    .bind(priority)
    .execute(&state.db)
    .await?;
    let total: i32 = sqlx::query_scalar("SELECT total FROM hashlists WHERE id = $1")
        .bind(body.hashlist_id)
        .fetch_optional(&state.db)
        .await?
        .unwrap_or(0);
    state.publish(Event::JobUpdated {
        job_id: id,
        state: JobState::Queued,
    });
    let view = JobView {
        id,
        name: body.name,
        hashlist_id: body.hashlist_id,
        state: JobState::Queued,
        priority,
        created_at: Utc::now(),
        est_completion: None,
        progress: 0.0,
        speed: 0,
        cracked: 0,
        total,
        pinned_agent_id: None,
        pinned_agent: None,
        running_agents: Vec::new(),
    };
    Ok((StatusCode::CREATED, Json(view)))
}

/// POST /jobs/clear — remove all finished jobs (and, by cascade, their tasks)
/// from the queue. Cracked hashes and hashlists are untouched. Before deleting,
/// each finished job is recorded in `job_history` so it stays visible in the
/// dashboard's "Completed" tab and its cracked plaintext remains reachable via
/// the preserved `hashlist_id`. Requires `SubmitJobs` (superadmin and operator).
#[utoipa::path(
    post, path = "/jobs/clear", tag = "jobs", security(("bearer" = [])),
    responses(
        (status = 200, body = ClearedJobs, description = "Finished jobs removed"),
        (status = 403, description = "Missing SubmitJobs")
    )
)]
async fn clear_finished_jobs(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ClearedJobs>, AppError> {
    auth.require(Capability::SubmitJobs)?;
    // Archive finished jobs into the durable history BEFORE deleting them, so the
    // "Completed" tab can still find them and re-open their cracked hashes. Done
    // in a transaction with the delete so a job is never lost without a matching
    // history row. Re-clearing a previously archived id refreshes its snapshot.
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO job_history \
           (id, name, hashlist_id, owner_user_id, attack_mode, state, created_at, finished_at) \
         SELECT id, name, hashlist_id, owner_user_id, attack_mode, state, created_at, finished_at \
         FROM jobs WHERE state IN ('completed','exhausted','cancelled','error') \
         ON CONFLICT (id) DO UPDATE SET \
           state = EXCLUDED.state, finished_at = EXCLUDED.finished_at, archived_at = now()",
    )
    .execute(&mut *tx)
    .await?;
    let cleared = sqlx::query(
        "DELETE FROM jobs WHERE state IN ('completed','exhausted','cancelled','error')",
    )
    .execute(&mut *tx)
    .await?
    .rows_affected() as i64;
    tx.commit().await?;
    tracing::info!(user = %auth.username, cleared, "cleared finished jobs (archived to history)");
    Ok(Json(ClearedJobs { cleared }))
}

/// GET /jobs/history — finished jobs for the dashboard's "Completed" tab.
///
/// Returns the union of (a) jobs still in the live queue in a terminal state and
/// (b) jobs that were cleared and now live only in `job_history`. Cracked/total
/// counts are read live from the hashlist in both cases, so a completed job's
/// cracked evidence stays accurate and reachable (via `hashlist_id`) even after
/// the live job row is gone. Requires `ViewJobs`; seeing the plaintext itself
/// still requires `ViewPlaintext` on `/hashlists/{id}/cracked`.
#[utoipa::path(
    get, path = "/jobs/history", tag = "jobs", security(("bearer" = [])),
    responses(
        (status = 200, body = Vec<JobHistoryView>, description = "Finished jobs, newest first"),
        (status = 403, description = "Missing ViewJobs")
    )
)]
async fn list_job_history(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<flamejob_api::JobHistoryView>>, AppError> {
    auth.require(Capability::ViewJobs)?;
    let rows: Vec<JobHistAgg> = sqlx::query_as(
        "SELECT j.id, j.name, j.hashlist_id, j.state::text, h.cracked, h.total, \
                j.created_at, j.finished_at, false AS archived \
           FROM jobs j JOIN hashlists h ON h.id = j.hashlist_id \
          WHERE j.state IN ('completed','exhausted','cancelled','error') \
         UNION ALL \
         SELECT a.id, a.name, a.hashlist_id, a.state::text, h.cracked, h.total, \
                a.created_at, a.finished_at, true AS archived \
           FROM job_history a JOIN hashlists h ON h.id = a.hashlist_id \
          WHERE a.id NOT IN (SELECT id FROM jobs) \
          ORDER BY finished_at DESC NULLS LAST, created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    let out = rows
        .into_iter()
        .map(|r| flamejob_api::JobHistoryView {
            id: r.0,
            name: r.1,
            hashlist_id: r.2,
            state: parse_job_state(&r.3),
            cracked: r.4,
            total: r.5,
            created_at: r.6,
            finished_at: r.7,
            archived: r.8,
        })
        .collect();
    Ok(Json(out))
}

type JobHistAgg = (
    Uuid,
    String,
    Uuid,
    String,
    i32,
    i32,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
    bool,
);

#[utoipa::path(
    get, path = "/jobs/{id}", tag = "jobs", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "Job id")),
    responses((status = 200, body = JobView), (status = 404, description = "Not found"))
)]
async fn get_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<JobView>, AppError> {
    auth.require(Capability::ViewJobs)?;
    let row: Option<JobAgg> = sqlx::query_as(&format!("{JOB_SELECT} WHERE j.id = $1"))
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    let row = row.ok_or_else(|| AppError::NotFound("job not found".into()))?;
    let mut v = job_view(row);
    if let Some(names) = running_agents_by_job(&state).await.get(&v.id) {
        v.running_agents = names.clone();
    }
    Ok(Json(v))
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct PatchJob {
    pub priority: i32,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct PinRequest {
    /// Agent id to pin this job to; the job's chunks will only run on this agent.
    pub agent_id: Uuid,
}

#[utoipa::path(
    patch, path = "/jobs/{id}", tag = "jobs", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "Job id")), request_body = PatchJob,
    responses((status = 204, description = "Priority updated"))
)]
async fn patch_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchJob>,
) -> Result<StatusCode, AppError> {
    auth.require(Capability::SubmitJobs)?;
    sqlx::query("UPDATE jobs SET priority = $1 WHERE id = $2")
        .bind(body.priority)
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/jobs/{id}/pause", tag = "jobs", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "Job id")),
    responses((status = 202, description = "Pause requested"))
)]
async fn pause_job(s: State<AppState>, a: AuthUser, p: Path<Uuid>) -> Result<StatusCode, AppError> {
    set_job_state(s, a, p, JobState::Paused).await
}
#[utoipa::path(
    post, path = "/jobs/{id}/resume", tag = "jobs", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "Job id")),
    responses((status = 202, description = "Resume requested (re-queues)"))
)]
async fn resume_job(
    s: State<AppState>,
    a: AuthUser,
    p: Path<Uuid>,
) -> Result<StatusCode, AppError> {
    set_job_state(s, a, p, JobState::Queued).await
}
#[utoipa::path(
    post, path = "/jobs/{id}/cancel", tag = "jobs", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "Job id")),
    responses((status = 202, description = "Cancel requested"))
)]
async fn cancel_job(
    s: State<AppState>,
    a: AuthUser,
    p: Path<Uuid>,
) -> Result<StatusCode, AppError> {
    set_job_state(s, a, p, JobState::Cancelled).await
}

async fn set_job_state(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    to: JobState,
) -> Result<StatusCode, AppError> {
    auth.require(Capability::SubmitJobs)?;
    let to_str = serde_json::to_value(to)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "queued".into());
    // Leaving the running state: drop the stale ETA so a paused/cancelled/
    // re-queued job doesn't keep showing a now-past completion estimate.
    sqlx::query("UPDATE jobs SET state = $1::job_state, est_completion = NULL WHERE id = $2")
        .bind(to_str)
        .bind(id)
        .execute(&state.db)
        .await?;
    state.publish(Event::JobUpdated {
        job_id: id,
        state: to,
    });
    Ok(StatusCode::ACCEPTED)
}

#[utoipa::path(
    post, path = "/jobs/{id}/pin", tag = "jobs", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "Job id")),
    request_body = PinRequest,
    responses(
        (status = 202, description = "Job pinned to the agent"),
        (status = 404, description = "Job or agent not found")
    )
)]
async fn pin_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<PinRequest>,
) -> Result<StatusCode, AppError> {
    auth.require(Capability::ManageAgents)?;
    // Validate the agent exists so we never pin to a dangling id.
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM agents WHERE id = $1")
        .bind(req.agent_id)
        .fetch_optional(&state.db)
        .await?;
    exists.ok_or_else(|| AppError::NotFound("agent not found".into()))?;
    let updated = sqlx::query("UPDATE jobs SET pinned_agent_id = $1 WHERE id = $2")
        .bind(req.agent_id)
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if updated == 0 {
        return Err(AppError::NotFound("job not found".into()));
    }
    Ok(StatusCode::ACCEPTED)
}

#[utoipa::path(
    delete, path = "/jobs/{id}/pin", tag = "jobs", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "Job id")),
    responses((status = 202, description = "Job unpinned (runs on any agent)"))
)]
async fn unpin_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    auth.require(Capability::ManageAgents)?;
    sqlx::query("UPDATE jobs SET pinned_agent_id = NULL WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

// ---- hashlists ----

#[utoipa::path(
    get, path = "/hashlists", tag = "hashlists", security(("bearer" = [])),
    responses((status = 200, body = Vec<HashlistView>))
)]
async fn list_hashlists(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<HashlistView>>, AppError> {
    auth.require(Capability::ViewJobs)?;
    let rows: Vec<HashlistRow> = sqlx::query_as(
        "SELECT id, name, hash_type, total, cracked, created_at FROM hashlists ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.iter()
            .map(|r| HashlistView {
                id: r.id,
                name: r.name.clone(),
                hash_type: r.hash_type,
                total: r.total,
                cracked: r.cracked,
            })
            .collect(),
    ))
}

#[utoipa::path(
    post, path = "/hashlists", tag = "hashlists", security(("bearer" = [])),
    request_body = HashlistCreate, responses((status = 201, body = HashlistView))
)]
async fn create_hashlist(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<HashlistCreate>,
) -> Result<(StatusCode, Json<HashlistView>), AppError> {
    auth.require(Capability::Ingest)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO hashlists (id, name, hash_type, created_by) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(&body.name)
        .bind(body.hash_type)
        .bind(auth.id)
        .execute(&state.db)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(HashlistView {
            id,
            name: body.name,
            hash_type: body.hash_type,
            total: 0,
            cracked: 0,
        }),
    ))
}

// ---- admin ----

#[utoipa::path(
    post, path = "/admin/users", tag = "auth", security(("bearer" = [])),
    request_body = UserCreate,
    responses((status = 201, description = "User created"), (status = 403, description = "Missing ManageUsers"))
)]
async fn create_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UserCreate>,
) -> Result<StatusCode, AppError> {
    auth.require(Capability::ManageUsers)?;
    let id = Uuid::new_v4();
    let hash = auth::hash_password(&body.password)?;
    sqlx::query(
        "INSERT INTO users (id, username, source, password_hash) VALUES ($1, $2, 'local', $3)",
    )
    .bind(id)
    .bind(&body.username)
    .bind(&hash)
    .execute(&state.db)
    .await?;
    for role in &body.roles {
        let role_str = serde_json::to_value(role)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        sqlx::query("INSERT INTO user_roles (user_id, role) VALUES ($1, $2::role)")
            .bind(id)
            .bind(role_str)
            .execute(&state.db)
            .await?;
    }
    Ok(StatusCode::CREATED)
}

#[utoipa::path(
    get, path = "/hashlists/{id}/cracked", tag = "hashlists", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "Hashlist id")),
    responses((status = 200, body = Vec<CrackedHash>), (status = 403, description = "Missing ViewPlaintext"))
)]
async fn list_cracked(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<CrackedHash>>, AppError> {
    auth.require(Capability::ViewPlaintext)?;
    let rows: Vec<(String, Option<String>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT hash, salt, plain FROM hashes WHERE hashlist_id = $1 AND plain IS NOT NULL",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    let out = rows
        .into_iter()
        .map(|(hash, salt, plain)| {
            let plain = plain
                .and_then(|b| state.cipher.decrypt(&b))
                .and_then(|v| String::from_utf8(v).ok())
                .unwrap_or_default();
            CrackedHash { hash, salt, plain }
        })
        .collect();
    Ok(Json(out))
}

#[allow(clippy::type_complexity)]
#[utoipa::path(
    get, path = "/devices", tag = "telemetry", security(("bearer" = [])),
    responses((status = 200, body = Vec<DeviceView>, description = "Current device snapshot"))
)]
async fn list_devices(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<flamejob_api::DeviceView>>, AppError> {
    auth.require(Capability::ViewStats)?;
    // The current_devices snapshot is fed by both the local collector and the
    // remote-agent telemetry ingest, so it shows every device in one place.
    let rows: Vec<(
        String,
        String,
        Option<i32>,
        Option<i32>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<i32>,
        Option<i32>,
        Option<i32>,
        Option<i32>,
        Option<i64>,
    )> = sqlx::query_as(
        "SELECT name, kind, temp, util, mem_used, mem_total, pstate, power_w, fan, \
         clock_mhz, mem_clock_mhz, hashrate FROM current_devices ORDER BY kind DESC, name",
    )
    .fetch_all(&state.db)
    .await?;
    if rows.is_empty() {
        // No sample persisted yet (fresh start): fall back to the in-memory snapshot.
        return Ok(Json(state.devices.read().await.clone()));
    }
    let out = rows
        .into_iter()
        .map(|r| flamejob_api::DeviceView {
            name: r.0,
            kind: r.1,
            temp: r.2.unwrap_or(0),
            util: r.3.unwrap_or(0),
            mem_used: r.4.unwrap_or(0),
            mem_total: r.5.unwrap_or(0),
            pstate: r.6.unwrap_or_default(),
            power_w: r.7.unwrap_or(0),
            fan: r.8.unwrap_or(0),
            clock_mhz: r.9.unwrap_or(0),
            mem_clock_mhz: r.10.unwrap_or(0),
            hashrate: r.11.unwrap_or(0),
        })
        .collect();
    Ok(Json(out))
}

#[allow(clippy::type_complexity)]
#[utoipa::path(
    get, path = "/devices/{name}/history", tag = "telemetry", security(("bearer" = [])),
    params(("name" = String, Path, description = "Device name")),
    responses((status = 200, body = Vec<DeviceSample>, description = "Recent samples, newest first"))
)]
async fn device_history(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(name): Path<String>,
) -> Result<Json<Vec<DeviceSample>>, AppError> {
    auth.require(Capability::ViewStats)?;
    let limit = state.cfg.telemetry.history_limit.clamp(1, 10_000);
    let rows: Vec<(
        chrono::DateTime<chrono::Utc>,
        Option<i32>,
        Option<i32>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<i32>,
        Option<i32>,
        Option<i32>,
        Option<i32>,
        Option<i64>,
    )> = sqlx::query_as(
        "SELECT ts, temp, util, mem_used, mem_total, pstate, power_w, fan, clock_mhz, mem_clock_mhz, hashrate \
         FROM metric_samples WHERE name = $1 ORDER BY ts DESC LIMIT $2",
    )
    .bind(&name)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let out = rows
        .into_iter()
        .map(|r| DeviceSample {
            ts: r.0,
            temp: r.1.unwrap_or(0),
            util: r.2.unwrap_or(0),
            mem_used: r.3.unwrap_or(0),
            mem_total: r.4.unwrap_or(0),
            pstate: r.5.unwrap_or_default(),
            power_w: r.6.unwrap_or(0),
            fan: r.7.unwrap_or(0),
            clock_mhz: r.8.unwrap_or(0),
            mem_clock_mhz: r.9.unwrap_or(0),
            hashrate: r.10.unwrap_or(0),
        })
        .collect();
    Ok(Json(out))
}

/// Maximum hash-import body, matching the wordlist upload cap (§7). The body is
/// streamed line-by-line (never buffered whole), so a large hashlist imports
/// without holding gigabytes in memory.
const MAX_HASH_UPLOAD: usize = 8 * 1024 * 1024 * 1024; // 8 GiB
/// Rows per INSERT (Postgres caps bind params at 65535; 2 per row).
const HASH_INSERT_BATCH: usize = 1000;

async fn insert_hash_batch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    batch: &mut Vec<String>,
) -> Result<(), sqlx::Error> {
    if batch.is_empty() {
        return Ok(());
    }
    let mut qb = sqlx::QueryBuilder::new("INSERT INTO hashes (hashlist_id, hash) ");
    qb.push_values(batch.iter(), |mut b, hash| {
        b.push_bind(id).push_bind(hash);
    });
    qb.build().execute(&mut **tx).await?;
    batch.clear();
    Ok(())
}

#[utoipa::path(
    post, path = "/hashlists/{id}/hashes", tag = "hashlists", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "Hashlist id")),
    request_body(content = String, content_type = "text/plain", description = "One hash per line (up to 8 GiB)"),
    responses((status = 200, body = HashlistView))
)]
async fn import_hashes(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    body: Body,
) -> Result<Json<HashlistView>, AppError> {
    auth.require(Capability::Ingest)?;
    let hash_type: Option<i32> =
        sqlx::query_scalar("SELECT hash_type FROM hashlists WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let hash_type = hash_type.ok_or_else(|| AppError::NotFound("hashlist not found".into()))?;

    // Stream the body, splitting on newlines and inserting in batched
    // transactions. `pending` holds only the current partial line between chunks.
    let mut tx = state.db.begin().await?;
    let mut stream = body.into_data_stream();
    let mut pending: Vec<u8> = Vec::new();
    let mut batch: Vec<String> = Vec::with_capacity(HASH_INSERT_BATCH);
    let mut total: usize = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AppError::BadRequest(e.to_string()))?;
        total += chunk.len();
        if total > MAX_HASH_UPLOAD {
            return Err(AppError::BadRequest(
                "hash upload exceeds 8 GiB limit".into(),
            ));
        }
        pending.extend_from_slice(&chunk);
        let mut line_start = 0;
        for i in 0..pending.len() {
            if pending[i] == b'\n' {
                let line = String::from_utf8_lossy(&pending[line_start..i]);
                let line = line.trim();
                if !line.is_empty() {
                    batch.push(line.to_string());
                }
                line_start = i + 1;
            }
        }
        pending.drain(..line_start); // keep only the trailing partial line
        while batch.len() >= HASH_INSERT_BATCH {
            let mut chunk_rows: Vec<String> = batch.drain(..HASH_INSERT_BATCH).collect();
            insert_hash_batch(&mut tx, id, &mut chunk_rows).await?;
        }
    }
    // Final line without a trailing newline.
    let tail = String::from_utf8_lossy(&pending);
    let tail = tail.trim();
    if !tail.is_empty() {
        batch.push(tail.to_string());
    }
    insert_hash_batch(&mut tx, id, &mut batch).await?;
    tx.commit().await?;
    let (total, cracked): (i64, i64) =
        sqlx::query_as("SELECT count(*), count(plain) FROM hashes WHERE hashlist_id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    sqlx::query("UPDATE hashlists SET total = $1, cracked = $2 WHERE id = $3")
        .bind(total as i32)
        .bind(cracked as i32)
        .bind(id)
        .execute(&state.db)
        .await?;
    let name: String = sqlx::query_scalar("SELECT name FROM hashlists WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(HashlistView {
        id,
        name,
        hash_type,
        total: total as i32,
        cracked: cracked as i32,
    }))
}

#[utoipa::path(
    get, path = "/files", tag = "files", security(("bearer" = [])),
    responses((status = 200, body = Vec<FileView>))
)]
async fn list_files(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<FileView>>, AppError> {
    auth.require(Capability::ViewJobs)?;
    let rows: Vec<(Uuid, String, String, i64, String)> = sqlx::query_as(
        "SELECT id, name, kind::text, size_bytes, sha256 FROM files ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, name, kind, size_bytes, sha256)| FileView {
                id,
                name,
                kind,
                size_bytes,
                sha256,
            })
            .collect(),
    ))
}

/// Disk capacity + free space for the volume that holds `path`, by matching the
/// deepest mount point that is a prefix of the directory. Returns `(total,
/// available)` in bytes, or `None` if no mount matched (e.g. an unusual layout).
fn volume_usage_for(path: &std::path::Path) -> Option<(u64, u64)> {
    use sysinfo::Disks;
    // Canonicalize the nearest existing ancestor so the prefix match works even
    // before the uploads dir has been created.
    let mut probe = path.to_path_buf();
    let canon = loop {
        if let Ok(c) = std::fs::canonicalize(&probe) {
            break c;
        }
        match probe.parent() {
            Some(p) => probe = p.to_path_buf(),
            None => break std::path::PathBuf::from("/"),
        }
    };
    let disks = Disks::new_with_refreshed_list();
    let mut best: Option<(usize, u64, u64)> = None;
    for d in disks.list() {
        let mp = d.mount_point();
        if canon.starts_with(mp) {
            let len = mp.as_os_str().len();
            if best.is_none_or(|(bl, _, _)| len > bl) {
                best = Some((len, d.total_space(), d.available_space()));
            }
        }
    }
    best.map(|(_, total, avail)| (total, avail))
}

#[utoipa::path(
    get, path = "/files/usage", tag = "files", security(("bearer" = [])),
    responses((status = 200, body = StorageUsageView, description = "Total uploaded-file storage vs quota and disk"))
)]
async fn storage_usage(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<StorageUsageView>, AppError> {
    auth.require(Capability::Ingest)?;
    let (files_bytes, file_count): (i64, i64) =
        sqlx::query_as("SELECT COALESCE(SUM(size_bytes), 0)::bigint, COUNT(*)::bigint FROM files")
            .fetch_one(&state.db)
            .await?;
    let uploads = PathBuf::from(&state.cfg.hashcat.data_dir).join("files");
    let path_str = uploads.display().to_string();
    // Disk sampling is a blocking syscall sweep; keep it off the async executor.
    let (disk_total, disk_available) =
        tokio::task::spawn_blocking(move || volume_usage_for(&uploads))
            .await
            .ok()
            .flatten()
            .unwrap_or((0, 0));
    Ok(Json(StorageUsageView {
        files_bytes,
        file_count,
        quota_bytes: state.cfg.hashcat.files_quota_bytes as i64,
        disk_total_bytes: disk_total as i64,
        disk_available_bytes: disk_available as i64,
        path: path_str,
    }))
}

#[utoipa::path(
    post, path = "/files", tag = "files", security(("bearer" = [])),
    request_body(content_type = "multipart/form-data", description = "Fields: file (binary), kind (wordlist|rule|mask|other)"),
    responses((status = 201, body = FileView))
)]
async fn upload_file(
    State(state): State<AppState>,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<FileView>), AppError> {
    use tokio::io::AsyncWriteExt;
    auth.require(Capability::Ingest)?;

    let id = Uuid::new_v4();
    let dir = PathBuf::from(&state.cfg.hashcat.data_dir).join("files");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let path = dir.join(id.to_string());

    let mut name: Option<String> = None;
    let mut kind = "other".to_string();
    let mut hasher = Sha256::new();
    let mut size_bytes: i64 = 0;
    let mut wrote_file = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
    {
        let field_name = field.name().map(|s| s.to_string());
        match field_name.as_deref() {
            Some("kind") => {
                kind = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(e.to_string()))?;
            }
            Some("file") => {
                name = field.file_name().map(|s| s.to_string());
                // Stream the body straight to disk, hashing as we go, so even a
                // multi-gigabyte wordlist never has to sit in memory at once.
                let mut out = tokio::fs::File::create(&path)
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| AppError::BadRequest(e.to_string()))?
                {
                    out.write_all(&chunk)
                        .await
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    hasher.update(&chunk);
                    size_bytes += chunk.len() as i64;
                }
                out.flush()
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                wrote_file = true;
            }
            _ => {}
        }
    }
    if !matches!(kind.as_str(), "wordlist" | "rule" | "mask" | "other") {
        kind = "other".to_string();
    }
    let name = match name {
        Some(n) if wrote_file => n,
        _ => {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(AppError::BadRequest("missing file field".into()));
        }
    };
    // Enforce the total-storage quota (0 = unlimited): if adding this file would
    // push the stored corpus past the cap, drop the just-written file and reject.
    // Checked after streaming because multipart doesn't give the size up front;
    // the bytes are already on disk, so remove them before returning.
    let quota = state.cfg.hashcat.files_quota_bytes as i64;
    if quota > 0 {
        let used: i64 =
            sqlx::query_scalar("SELECT COALESCE(SUM(size_bytes), 0)::bigint FROM files")
                .fetch_one(&state.db)
                .await?;
        if used + size_bytes > quota {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(AppError::InsufficientStorage(format!(
                "storage quota exceeded: {} in use + {} would exceed the {} limit",
                human_bytes(used),
                human_bytes(size_bytes),
                human_bytes(quota),
            )));
        }
    }
    let sha256 = hex::encode(hasher.finalize());
    sqlx::query(
        "INSERT INTO files (id, name, kind, path, size_bytes, sha256, uploaded_by) \
         VALUES ($1, $2, $3::file_kind, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(&name)
    .bind(&kind)
    .bind(path.display().to_string())
    .bind(size_bytes)
    .bind(&sha256)
    .bind(auth.id)
    .execute(&state.db)
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(FileView {
            id,
            name,
            kind,
            size_bytes,
            sha256,
        }),
    ))
}

#[utoipa::path(
    delete, path = "/files/{id}", tag = "files", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "File id")),
    responses((status = 204, description = "Deleted"))
)]
async fn delete_file(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    auth.require(Capability::Ingest)?;
    let path: Option<String> = sqlx::query_scalar("SELECT path FROM files WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    sqlx::query("DELETE FROM files WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    if let Some(p) = path {
        let _ = tokio::fs::remove_file(p).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get, path = "/events", tag = "meta", security(("bearer" = [])),
    responses((status = 200, description = "Server-sent event stream of Event payloads", body = Event))
)]
async fn events(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<
    Sse<impl tokio_stream::Stream<Item = Result<SseEvent, std::convert::Infallible>>>,
    AppError,
> {
    auth.require(Capability::ViewJobs)?;
    let rx = state.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| {
        let ev = msg.ok()?;
        SseEvent::default()
            .event(ev.kind())
            .json_data(&ev)
            .ok()
            .map(Ok)
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ---- helpers ----

fn parse_role(s: &str) -> Option<flamejob_core::Role> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

fn parse_job_state(s: &str) -> JobState {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap_or(JobState::Queued)
}

const JOB_SELECT: &str = "SELECT j.id, j.name, j.hashlist_id, j.state::text, j.priority, j.created_at, \
    j.est_completion, \
    COALESCE((SELECT SUM(CASE WHEN t.state='done' THEN GREATEST(t.keyspace_len,1)::float8 \
        ELSE t.progress*GREATEST(t.keyspace_len,1)::float8 END) \
        / NULLIF(SUM(GREATEST(t.keyspace_len,1)),0) FROM tasks t WHERE t.job_id=j.id),0)::float8 AS progress, \
    COALESCE((SELECT SUM(speed) FROM tasks t WHERE t.job_id=j.id AND t.state='running'),0)::int8 AS speed, \
    h.cracked, h.total, j.pinned_agent_id, ap.name \
    FROM jobs j JOIN hashlists h ON h.id=j.hashlist_id \
    LEFT JOIN agents ap ON ap.id=j.pinned_agent_id";

type JobAgg = (
    Uuid,
    String,
    Uuid,
    String,
    i32,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
    f64,
    i64,
    i32,
    i32,
    Option<Uuid>,
    Option<String>,
);

fn job_view(r: JobAgg) -> JobView {
    JobView {
        id: r.0,
        name: r.1,
        hashlist_id: r.2,
        state: parse_job_state(&r.3),
        priority: r.4,
        created_at: r.5,
        est_completion: r.6,
        progress: r.7,
        speed: r.8,
        cracked: r.9,
        total: r.10,
        pinned_agent_id: r.11,
        pinned_agent: r.12,
        // Filled in by the handler from the live agent hub (see running_agents).
        running_agents: Vec::new(),
    }
}

/// Resolve, per job, the names of the agent(s) (or the local host) currently
/// running its chunks. Agent tasks are looked up in the live hub; when the
/// local runner is in use, running chunks are attributed to the configured
/// local host name. Returns job_id -> distinct agent names (in first-seen order).
async fn running_agents_by_job(state: &AppState) -> std::collections::HashMap<Uuid, Vec<String>> {
    use std::collections::HashMap;
    let assignments = state.agents.assignments().await; // task_id -> agent name
    let local_mode = state.cfg.scheduler.runner != "remote";
    let local_name = state.cfg.scheduler.local_agent_name.clone();
    let running: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT job_id, id FROM tasks WHERE state = 'running'")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
    let mut out: HashMap<Uuid, Vec<String>> = HashMap::new();
    for (job_id, task_id) in running {
        let name = assignments
            .get(&task_id)
            .cloned()
            .or_else(|| local_mode.then(|| local_name.clone()));
        if let Some(name) = name {
            let v = out.entry(job_id).or_default();
            if !v.contains(&name) {
                v.push(name);
            }
        }
    }
    out
}

fn parse_task_state(s: &str) -> TaskState {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap_or(TaskState::Pending)
}

#[utoipa::path(
    get, path = "/jobs/{id}/tasks", tag = "jobs", security(("bearer" = [])),
    params(("id" = Uuid, Path, description = "Job id")),
    responses((status = 200, body = Vec<TaskView>, description = "Chunk tasks, keyspace order"))
)]
async fn list_job_tasks(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<TaskView>>, AppError> {
    auth.require(Capability::ViewJobs)?;
    let rows: Vec<(Uuid, Uuid, String, f64, i64, i64, i64)> = sqlx::query_as(
        "SELECT id, job_id, state::text, progress, speed, keyspace_offset, keyspace_len \
         FROM tasks WHERE job_id = $1 ORDER BY keyspace_offset",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, job_id, st, progress, speed, off, len)| TaskView {
                id,
                job_id,
                state: parse_task_state(&st),
                progress,
                speed,
                keyspace_offset: off,
                keyspace_len: len,
                eta: None,
            })
            .collect(),
    ))
}
