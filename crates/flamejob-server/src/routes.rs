use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use flamejob_api::*;
use flamejob_core::{Capability, JobState, TaskState};
use flamejob_db::models::HashlistRow;
use uuid::Uuid;

use crate::auth::{self, AuthUser};
use crate::error::AppError;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/devices", get(list_devices))
        .route("/openapi.json", get(openapi))
        .route("/auth/login", post(login))
        .route("/auth/me", get(me))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/:id", get(get_job).patch(patch_job))
        .route("/jobs/:id/tasks", get(list_job_tasks))
        .route("/jobs/:id/pause", post(pause_job))
        .route("/jobs/:id/resume", post(resume_job))
        .route("/jobs/:id/cancel", post(cancel_job))
        .route("/hashlists", get(list_hashlists).post(create_hashlist))
        .route("/hashlists/:id/cracked", get(list_cracked))
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
    let rows: Vec<JobAgg> =
        sqlx::query_as(&format!("{JOB_SELECT} ORDER BY j.priority, j.created_at"))
            .fetch_all(&state.db)
            .await?;
    Ok(Json(rows.into_iter().map(job_view).collect()))
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
    let total: i32 = sqlx::query_scalar("SELECT total FROM hashlists WHERE id = $1")
        .bind(body.hashlist_id)
        .fetch_optional(&state.db)
        .await?
        .unwrap_or(0);
    let view = JobView {
        id,
        name: body.name,
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

async fn list_devices(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<flamejob_api::DeviceView>>, AppError> {
    auth.require(Capability::ViewStats)?;
    Ok(Json(state.devices.read().await.clone()))
}

// ---- helpers ----

fn parse_role(s: &str) -> Option<flamejob_core::Role> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

fn parse_job_state(s: &str) -> JobState {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap_or(JobState::Queued)
}

const JOB_SELECT: &str = "SELECT j.id, j.name, j.state::text, j.priority, j.created_at, \
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
        state: parse_job_state(&r.2),
        priority: r.3,
        created_at: r.4,
        est_completion: r.5,
        progress: r.6,
        speed: r.7,
        cracked: r.8,
        total: r.9,
    }
}

fn parse_task_state(s: &str) -> TaskState {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap_or(TaskState::Pending)
}

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
