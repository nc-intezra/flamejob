//! Phase 3 distributed-agent protocol: the enrollment DTOs (HTTP) and the
//! WebSocket task protocol shared by flamejobd and flamejob-agent.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

// ---- enrollment (HTTP) ----

/// Admin-created one-time claim token used once to enroll an agent.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentClaimCreate {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentClaim {
    pub claim_token: String,
    pub name: String,
}

/// Enrollment request: a one-time claim token plus the agent's CSR (PEM). The
/// agent keeps the matching private key; only the CSR leaves the worker.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EnrollRequest {
    pub claim_token: String,
    pub name: String,
    pub csr_pem: String,
}

/// Enrollment response: the CA-signed client certificate and the CA cert so the
/// agent can verify the server in turn (mutual TLS).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EnrollResponse {
    pub agent_id: Uuid,
    pub cert_pem: String,
    pub ca_pem: String,
}

/// A view of an enrolled agent for the admin/ops API.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentInfo {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub enrolled_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

// ---- WebSocket task protocol ----

/// A chunk of work dispatched to an agent. Self-contained for mask attacks:
/// the hash lines travel inline so the agent needs no server filesystem access.
/// Wordlist/rule attacks pass file paths the agent is expected to have locally
/// (bulk wordlist sync is a later phase).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub task_id: Uuid,
    pub hash_type: i32,
    pub attack_mode: i16,
    /// Raw `hash` or `hash:salt` lines.
    pub hashes: Vec<String>,
    /// Mask string (attack mode 3) or wordlist path.
    pub primary: String,
    pub rules: Vec<String>,
    pub keyspace_offset: i64,
    pub keyspace_len: i64,
    pub extra_args: Vec<String>,
}

/// A cracked hash reported by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackedItem {
    pub hash: String,
    pub plain: String,
}

/// A telemetry sample reported by an agent (mirrors the server's DeviceView).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetric {
    pub name: String,
    pub kind: String,
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

/// Agent → server messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMsg {
    /// First frame: identify and present the issued client certificate.
    Hello { name: String, cert_pem: String },
    /// Advertise free capacity (number of tasks the agent can accept).
    Ready { slots: u32 },
    /// Reply to ComputeKeyspace.
    Keyspace { req_id: Uuid, value: u64 },
    /// Live progress for a running task.
    Progress {
        task_id: Uuid,
        progress: f64,
        speed: i64,
        recovered: i64,
        state: String,
    },
    /// Cracked hashes for a task.
    Cracked {
        task_id: Uuid,
        items: Vec<CrackedItem>,
    },
    /// Device telemetry from the worker node.
    Metrics { samples: Vec<AgentMetric> },
    /// Terminal state for a task.
    TaskDone { task_id: Uuid, state: String },
    /// A keyspace probe or task run failed.
    Error {
        task_id: Option<Uuid>,
        message: String,
    },
}

/// Server → agent messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Accepted; the agent is enrolled and authenticated.
    Welcome { agent_id: Uuid },
    /// Compute `hashcat --keyspace` for this task and reply with Keyspace.
    ComputeKeyspace { req_id: Uuid, task: AgentTask },
    /// Run this chunk and stream Progress/Cracked/TaskDone.
    Assign { task: AgentTask },
    /// Stop a running task.
    Cancel { task_id: Uuid },
    /// Liveness ping.
    Heartbeat,
    /// Authentication or enrollment check failed; the socket will close.
    Rejected { reason: String },
}
