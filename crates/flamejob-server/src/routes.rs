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
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use uuid::Uuid;

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
        .route("/openapi.json", get(openapi))
        .route("/auth/login", post(login))
        .route("/auth/me", get(me))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/clear", post(clear_finished_jobs))
        .route("/jobs/:id", get(get_job).patch(patch_job))
        .route("/jobs/:id/tasks", get(list_job_tasks))
        .route("/jobs/:id/pause", post(pause_job))
        .route("/jobs/:id/resume", post(resume_job))
        .route("/jobs/:id/cancel", post(cancel_job))
        .route("/hashlists", get(list_hashlists).post(create_hashlist))
        .route("/hashlists/:id/cracked", get(list_cracked))
        .route("/hashlists/:id/hashes", post(import_hashes))
        .route(
            "/files",
            // Wordlists are large; lift axum's 2 MB default body cap for uploads
            // (the handler streams the body to disk, so this isn't held in memory).
            get(list_files)
                .post(upload_file)
                .layer(DefaultBodyLimit::max(8 * 1024 * 1024 * 1024)),
        )
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
    Ok(Json(rows.into_iter().map(job_view).collect()))
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
    };
    Ok((StatusCode::CREATED, Json(view)))
}

/// POST /jobs/clear — remove all finished jobs (and, by cascade, their tasks)
/// from the queue. Cracked hashes and hashlists are untouched. Requires
/// `SubmitJobs` (superadmin and operator).
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
    let cleared = sqlx::query(
        "DELETE FROM jobs WHERE state IN ('completed','exhausted','cancelled','error')",
    )
    .execute(&state.db)
    .await?
    .rows_affected() as i64;
    tracing::info!(user = %auth.username, cleared, "cleared finished jobs");
    Ok(Json(ClearedJobs { cleared }))
}

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
    Ok(Json(job_view(row)))
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct PatchJob {
    pub priority: i32,
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
    sqlx::query("UPDATE jobs SET state = $1::job_state WHERE id = $2")
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
    h.cracked, h.total \
    FROM jobs j JOIN hashlists h ON h.id=j.hashlist_id";

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
    }
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
