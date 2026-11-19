use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

/// Enum columns are read as text (`state::text`) in Phase 1 to keep the row
/// models free of custom sqlx type mappings; the server converts to the
/// flamejob-core enums.
#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub source: String,
    pub password_hash: Option<String>,
    pub display_name: Option<String>,
    pub disabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct JobRow {
    pub id: Uuid,
    pub name: String,
    pub owner_user_id: Uuid,
    pub hashlist_id: Uuid,
    pub attack_mode: i16,
    pub config: serde_json::Value,
    pub priority: i32,
    pub state: String,
    pub est_completion: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct TaskRow {
    pub id: Uuid,
    pub job_id: Uuid,
    pub runner_id: Option<String>,
    pub keyspace_offset: i64,
    pub keyspace_len: i64,
    pub state: String,
    pub progress: f64,
    pub speed: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct HashlistRow {
    pub id: Uuid,
    pub name: String,
    pub hash_type: i32,
    pub total: i32,
    pub cracked: i32,
    pub created_at: DateTime<Utc>,
}
