use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{Result, TaskState};

/// The unit of work a Runner executes. In Phase 1 the LocalRunner runs it as a
/// hashcat subprocess; in Phase 3 a RemoteRunner ships it to an agent.
#[derive(Debug, Clone)]
pub struct RunnerTask {
    pub task_id: Uuid,
    pub hash_type: i32,
    pub attack_mode: i16,
    pub hash_file: String,
    /// Wordlist path or mask, depending on attack mode.
    pub primary: String,
    pub rules: Vec<String>,
    pub keyspace_offset: i64,
    pub keyspace_len: i64,
    pub extra_args: Vec<String>,
}

/// A status sample derived from hashcat's `--status-json` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusUpdate {
    pub task_id: Uuid,
    pub progress: f64,
    pub speed: i64,
    pub recovered: i64,
    pub eta: Option<chrono::DateTime<chrono::Utc>>,
    pub state: TaskState,
}

pub type StatusSink = mpsc::Sender<StatusUpdate>;

#[derive(Debug, Clone)]
pub struct RunHandle {
    pub task_id: Uuid,
}

#[async_trait]
pub trait Runner: Send + Sync {
    async fn keyspace(&self, task: &RunnerTask) -> Result<u64>;
    async fn start(&self, task: &RunnerTask, tx: StatusSink) -> Result<RunHandle>;
    async fn pause(&self, handle: &RunHandle) -> Result<()>;
    async fn resume(&self, handle: &RunHandle) -> Result<()>;
    async fn cancel(&self, handle: &RunHandle) -> Result<()>;
}
