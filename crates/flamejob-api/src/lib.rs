//! flamejob-api: the wire contract. Every DTO derives `ToSchema`; `ApiDoc`
//! aggregates them so the OpenAPI document is generated from these types.
use chrono::{DateTime, Utc};
use flamejob_core::{JobState, Role, TaskState};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

pub mod agent;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    #[schema(value_type = Vec<String>)]
    pub roles: Vec<Role>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MeResponse {
    pub id: Uuid,
    pub username: String,
    #[schema(value_type = Vec<String>)]
    pub roles: Vec<Role>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JobConfig {
    pub wordlist_file_id: Option<Uuid>,
    #[serde(default)]
    pub rule_file_ids: Vec<Uuid>,
    pub mask: Option<String>,
    #[serde(default)]
    pub extra_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JobCreate {
    pub name: String,
    pub hashlist_id: Uuid,
    pub attack_mode: i16,
    pub priority: Option<i32>,
    pub config: JobConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JobView {
    pub id: Uuid,
    pub name: String,
    #[schema(value_type = String)]
    pub state: JobState,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub est_completion: Option<DateTime<Utc>>,
    pub progress: f64,
    pub speed: i64,
    pub cracked: i32,
    pub total: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TaskView {
    pub id: Uuid,
    pub job_id: Uuid,
    #[schema(value_type = String)]
    pub state: TaskState,
    pub progress: f64,
    pub speed: i64,
    pub keyspace_offset: i64,
    pub keyspace_len: i64,
    pub eta: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HashlistCreate {
    pub name: String,
    pub hash_type: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HashlistView {
    pub id: Uuid,
    pub name: String,
    pub hash_type: i32,
    pub total: i32,
    pub cracked: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CrackedHash {
    pub hash: String,
    pub salt: Option<String>,
    pub plain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FileView {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub size_bytes: i64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserCreate {
    pub username: String,
    pub password: String,
    #[schema(value_type = Vec<String>)]
    pub roles: Vec<Role>,
}

/// Result of clearing finished jobs from the queue.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClearedJobs {
    /// Number of finished jobs (and their tasks) removed.
    pub cleared: i64,
}

/// RFC 7807 problem+json error body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Problem {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeviceView {
    pub name: String,
    pub kind: String,
    pub temp: i32,
    pub util: i32,
    pub mem_used: i64,
    pub mem_total: i64,
    pub pstate: String,
    pub power_w: i32,
    pub fan: i32,
    /// Core/graphics clock in MHz.
    pub clock_mhz: i32,
    /// Memory clock in MHz.
    pub mem_clock_mhz: i32,
    pub hashrate: i64,
}

/// One historical telemetry sample for a device, from `metric_samples`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeviceSample {
    pub ts: DateTime<Utc>,
    pub temp: i32,
    pub util: i32,
    pub mem_used: i64,
    pub mem_total: i64,
    pub pstate: String,
    pub power_w: i32,
    pub fan: i32,
    pub clock_mhz: i32,
    pub mem_clock_mhz: i32,
    pub hashrate: i64,
}

/// Server-sent event payloads streamed from `GET /events`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type")]
pub enum Event {
    JobUpdated {
        job_id: Uuid,
        #[schema(value_type = String)]
        state: JobState,
    },
    TaskUpdated {
        job_id: Uuid,
        task_id: Uuid,
        progress: f64,
        speed: i64,
        eta: Option<DateTime<Utc>>,
    },
    HashCracked {
        hashlist_id: Uuid,
        hash: String,
    },
}

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Event::JobUpdated { .. } => "JobUpdated",
            Event::TaskUpdated { .. } => "TaskUpdated",
            Event::HashCracked { .. } => "HashCracked",
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "flamejob",
        version = "1.0.0",
        description = "Distributed hashcat queue API"
    ),
    components(schemas(
        LoginRequest,
        LoginResponse,
        MeResponse,
        JobConfig,
        JobCreate,
        JobView,
        TaskView,
        HashlistCreate,
        HashlistView,
        CrackedHash,
        FileView,
        UserCreate,
        ClearedJobs,
        Problem,
        Event,
        DeviceView,
        DeviceSample,
        agent::AgentClaimCreate,
        agent::AgentClaim,
        agent::EnrollRequest,
        agent::EnrollResponse,
        agent::AgentInfo
    ))
)]
pub struct ApiDoc;
