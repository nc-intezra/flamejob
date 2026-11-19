use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use flamejob_api::*;
use flamejob_core::{Capability, JobState};
use flamejob_db::models::{HashlistRow, JobRow};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::auth::{self, AuthUser};
use crate::error::AppError;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/openapi.json", get(openapi))
        .route("/auth/login", post(login))
        .route("/auth/me", get(me))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/:id", get(get_job).patch(patch_job))
        .route("/jobs/:id/pause", post(pause_job))
        .route("/jobs/:id/resume", post(resume_job))
        .route("/jobs/:id/cancel", post(cancel_job))
        .route("/hashlists", get(list_hashlists).post(create_hashlist))
        .route("/hashlists/:id/cracked", get(list_cracked))
        .route("/hashlists/:id/hashes", post(import_hashes))
        .route("/files", get(list_files).post(upload_file))
        .route("/files/:id", delete(delete_file))
        .route("/events", get(events))
        .route("/admin/users", post(create_user))
        .with_state(state)
}

// ---- meta ----

async fn healthz() -> &'static str {
    "ok"
}

async fn metrics(State(state): State<AppState>) -> String {
    state.metrics.render()
}

async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    use utoipa::OpenApi;
    Json(ApiDoc::openapi())
}

// ---- auth ----

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

async fn list_jobs(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<JobView>>, AppError> {
    auth.require(Capability::ViewJobs)?;
    let rows: Vec<JobRow> = sqlx::query_as(
        "SELECT id, name, owner_user_id, hashlist_id, attack_mode, config, priority, \
         state::text AS state, est_completion, error, created_at, started_at, finished_at \
         FROM jobs ORDER BY priority, created_at",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.iter().map(job_view).collect()))
}

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
    state.publish(Event::JobUpdated {
        job_id: id,
        state: JobState::Queued,
    });
    let view = JobView {
        id,
        name: body.name,
        state: JobState::Queued,
        priority,
        created_at: Utc::now(),
        est_completion: None,
    };
    Ok((StatusCode::CREATED, Json(view)))
}

async fn get_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<JobView>, AppError> {
    auth.require(Capability::ViewJobs)?;
    let row: Option<JobRow> = sqlx::query_as(
        "SELECT id, name, owner_user_id, hashlist_id, attack_mode, config, priority, \
         state::text AS state, est_completion, error, created_at, started_at, finished_at \
         FROM jobs WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let row = row.ok_or_else(|| AppError::NotFound("job not found".into()))?;
    Ok(Json(job_view(&row)))
}

#[derive(serde::Deserialize)]
struct PatchJob {
    priority: i32,
}

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

async fn pause_job(s: State<AppState>, a: AuthUser, p: Path<Uuid>) -> Result<StatusCode, AppError> {
    set_job_state(s, a, p, JobState::Paused).await
}
async fn resume_job(
    s: State<AppState>,
    a: AuthUser,
    p: Path<Uuid>,
) -> Result<StatusCode, AppError> {
    set_job_state(s, a, p, JobState::Queued).await
}
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

async fn import_hashes(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    body: String,
) -> Result<Json<HashlistView>, AppError> {
    auth.require(Capability::Ingest)?;
    let hash_type: Option<i32> =
        sqlx::query_scalar("SELECT hash_type FROM hashlists WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let hash_type = hash_type.ok_or_else(|| AppError::NotFound("hashlist not found".into()))?;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        sqlx::query("INSERT INTO hashes (hashlist_id, hash) VALUES ($1, $2)")
            .bind(id)
            .bind(line)
            .execute(&state.db)
            .await?;
    }
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

async fn upload_file(
    State(state): State<AppState>,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<FileView>), AppError> {
    auth.require(Capability::Ingest)?;
    let mut name: Option<String> = None;
    let mut kind = "other".to_string();
    let mut data: Vec<u8> = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
    {
        match field.name() {
            Some("kind") => {
                kind = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(e.to_string()))?;
            }
            Some("file") => {
                name = field.file_name().map(|s| s.to_string());
                data = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::BadRequest(e.to_string()))?
                    .to_vec();
            }
            _ => {}
        }
    }
    if !matches!(kind.as_str(), "wordlist" | "rule" | "mask" | "other") {
        kind = "other".to_string();
    }
    let name = name.ok_or_else(|| AppError::BadRequest("missing file field".into()))?;
    let id = Uuid::new_v4();
    let dir = PathBuf::from(&state.cfg.hashcat.data_dir).join("files");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let path = dir.join(id.to_string());
    tokio::fs::write(&path, &data)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let sha256 = hex::encode(Sha256::digest(&data));
    let size_bytes = data.len() as i64;
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

fn job_view(r: &JobRow) -> JobView {
    JobView {
        id: r.id,
        name: r.name.clone(),
        state: parse_job_state(&r.state),
        priority: r.priority,
        created_at: r.created_at,
        est_completion: r.est_completion,
    }
}
