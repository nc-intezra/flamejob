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
    /// The hashlist this job cracks (use `GET /hashlists/{id}/cracked`).
    pub hashlist_id: Uuid,
    #[schema(value_type = String)]
    pub state: JobState,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub est_completion: Option<DateTime<Utc>>,
    pub progress: f64,
    pub speed: i64,
    pub cracked: i32,
    pub total: i32,
    /// Agent this job is pinned to (runs only there), if any. Set via
    /// `POST /jobs/{id}/pin`; requires the ManageAgents capability.
    pub pinned_agent_id: Option<Uuid>,
    /// Display name of the pinned agent, resolved from `pinned_agent_id`.
    pub pinned_agent: Option<String>,
    /// Names of the agent(s) (or the local host) currently running this job's
    /// chunks — for showing where a job is executing.
    #[serde(default)]
    pub running_agents: Vec<String>,
}

/// A finished job as shown in the dashboard's "Completed" tab. Covers jobs that
/// are still in the live queue in a terminal state AND jobs that were removed by
/// "Clear finished" (kept in `job_history`). The `hashlist_id` stays valid in
/// both cases, so the cracked plaintext remains reachable via
/// `GET /hashlists/{id}/cracked`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JobHistoryView {
    pub id: Uuid,
    pub name: String,
    /// The hashlist this job cracked (use `GET /hashlists/{id}/cracked`).
    pub hashlist_id: Uuid,
    #[schema(value_type = String)]
    pub state: JobState,
    pub cracked: i32,
    pub total: i32,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    /// `true` when the job has been cleared from the live queue and now exists
    /// only in `job_history`; `false` while it is still a terminal live job.
    pub archived: bool,
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

/// Total-storage usage for the dashboard's upload-corpus gauge: how much all
/// uploaded files occupy, against the configured quota (if any) and the physical
/// volume behind `data_dir/files` for context. `quota_bytes == 0` means no quota
/// is configured (unlimited); `disk_total_bytes == 0` means the volume couldn't
/// be sampled.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StorageUsageView {
    /// Sum of all uploaded files (wordlists/rules/masks/other), in bytes.
    pub files_bytes: i64,
    /// Number of uploaded files.
    pub file_count: i64,
    /// Configured total-storage cap in bytes; 0 = unlimited.
    pub quota_bytes: i64,
    /// Capacity of the volume holding the uploads directory, in bytes (0 if
    /// it couldn't be sampled).
    pub disk_total_bytes: i64,
    /// Free space on that volume, in bytes.
    pub disk_available_bytes: i64,
    /// The uploads directory the figures describe.
    pub path: String,
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

/// Sitewide settings as shown to a superadmin/admin. The private key is never
/// returned; only whether one is stored and the certificate's fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SiteSettingsView {
    /// Whether the HTTPS-on-443 dashboard listener is enabled.
    pub https_enabled: bool,
    /// Whether a certificate is stored.
    pub has_cert: bool,
    /// Whether a private key is stored.
    pub has_key: bool,
    /// Whether the :443 listener is actually serving right now (false if enabled
    /// but the bind failed, e.g. the process lacks permission for port 443).
    pub https_listening: bool,
    /// Address the HTTPS listener binds (e.g. `0.0.0.0:443`).
    pub https_bind: String,
    /// SHA-256 fingerprint of the stored certificate, for display.
    pub cert_fingerprint: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Update to the sitewide settings. A `null`/omitted `tls_cert_pem` or
/// `tls_key_pem` keeps the currently stored value; send a new PEM to replace it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SiteSettingsUpdate {
    pub https_enabled: bool,
    #[serde(default)]
    pub tls_cert_pem: Option<String>,
    #[serde(default)]
    pub tls_key_pem: Option<String>,
}

// ---- Directory (AD/LDAP) — Phase 5 ----

/// Directory connection config as shown to an admin/superadmin. The service
/// bind password is never returned — only whether one is stored.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DirectoryConfigView {
    pub enabled: bool,
    /// `ldaps` | `starttls` | `plaintext`.
    pub transport: String,
    /// `srv` | `static`.
    pub discovery: String,
    pub domain: Option<String>,
    pub servers: Vec<String>,
    pub use_global_catalog: bool,
    pub base_dn: Option<String>,
    pub bind_dn: Option<String>,
    /// Whether a service bind password is stored (the secret is never returned).
    pub has_bind_password: bool,
    pub user_filter: String,
    pub login_attributes: Vec<String>,
    pub has_ca_bundle: bool,
    pub verify_hostname: bool,
    pub allow_insecure_tls: bool,
    pub plaintext_ack: bool,
    pub group_source: String,
    pub cache_ttl_secs: i32,
    pub on_directory_down: String,
    #[schema(value_type = Option<String>)]
    pub default_role: Option<Role>,
    pub jwt_ttl_hours: i32,
    pub last_test_ok_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Update to the directory connection config. A blank/omitted `bind_password`
/// keeps the stored one; set `clear_bind_password` to remove it. `enabled` is
/// NOT set here — use the separate enable/disable endpoints (test-before-enable).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DirectoryConfigUpdate {
    pub transport: String,
    pub discovery: String,
    pub domain: Option<String>,
    pub servers: Vec<String>,
    pub use_global_catalog: bool,
    pub base_dn: Option<String>,
    pub bind_dn: Option<String>,
    #[serde(default)]
    pub bind_password: Option<String>,
    #[serde(default)]
    pub clear_bind_password: bool,
    pub user_filter: String,
    pub login_attributes: Vec<String>,
    #[serde(default)]
    pub ca_bundle_pem: Option<String>,
    pub verify_hostname: bool,
    pub allow_insecure_tls: bool,
    pub plaintext_ack: bool,
    pub group_source: String,
    pub cache_ttl_secs: i32,
    pub on_directory_down: String,
    #[schema(value_type = Option<String>)]
    pub default_role: Option<Role>,
    pub jwt_ttl_hours: i32,
}

/// Request body for a staged connection test (runs against the saved config).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DirectoryTestRequest {
    /// Optional identifier to run the user search filter against.
    #[serde(default)]
    pub sample_user: Option<String>,
}

/// One stage of a connection test.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DirectoryTestStep {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// Staged connection-test result.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DirectoryTestResult {
    pub ok: bool,
    pub steps: Vec<DirectoryTestStep>,
}

/// Dry-run of a full user login (superadmin): search-then-bind + resolution.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DirectoryTestLoginRequest {
    pub username: String,
    pub password: String,
}

/// Result of a login dry-run: the resolved SID, groups and mapped roles.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DirectoryTestLoginResult {
    pub ok: bool,
    pub detail: String,
    pub dn: Option<String>,
    pub sid: Option<String>,
    pub group_sids: Vec<String>,
    #[schema(value_type = Vec<String>)]
    pub roles: Vec<Role>,
}

/// A `group_sid -> role` mapping row (group_cn is display-only).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DirectoryRoleMapEntry {
    pub group_sid: String,
    #[schema(value_type = String)]
    pub role: Role,
    pub group_cn: Option<String>,
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

/// Request to mint a new API key.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyCreate {
    /// Human-readable label to recognise the key later.
    pub name: String,
    /// Days until the key expires. Omit for the default (365); `0` means the key
    /// never expires and must be revoked to disable.
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

/// A key as listed to its owner — never includes the secret.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyView {
    pub id: Uuid,
    pub name: String,
    /// Non-secret display prefix, e.g. `fj_1a2b3c4d`.
    pub prefix: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// Response to key creation — the only time the full secret is returned.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyCreated {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    /// The full secret (`fj_…`). Shown once; store it now, it cannot be recovered.
    pub key: String,
    pub expires_at: Option<DateTime<Utc>>,
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
    // NOTE: `version` here is a placeholder; the server overrides it at serve
    // time with the live crate version (see flamejob-server openapi::document),
    // so the document served at /openapi.json always matches the release.
    info(
        title = "flamejob",
        version = "1.6.0",
        description = "Distributed hashcat queue API"
    ),
    components(schemas(
        LoginRequest,
        LoginResponse,
        MeResponse,
        JobConfig,
        JobCreate,
        JobView,
        JobHistoryView,
        TaskView,
        HashlistCreate,
        HashlistView,
        CrackedHash,
        FileView,
        UserCreate,
        ApiKeyCreate,
        ApiKeyView,
        ApiKeyCreated,
        ClearedJobs,
        SiteSettingsView,
        SiteSettingsUpdate,
        DirectoryConfigView,
        DirectoryConfigUpdate,
        DirectoryTestRequest,
        DirectoryTestResult,
        DirectoryTestStep,
        DirectoryTestLoginRequest,
        DirectoryTestLoginResult,
        DirectoryRoleMapEntry,
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
