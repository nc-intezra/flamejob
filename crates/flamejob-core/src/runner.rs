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

    /// How many chunk tasks may be in flight concurrently right now.
    ///
    /// The scheduler uses this to fan a single job's chunks across the available
    /// compute: for the local runner it is a fixed parallelism, for the remote
    /// runner it tracks the fleet's current slot capacity and so grows and
    /// shrinks as agents connect, disconnect and report free slots. The default
    /// of `1` preserves strictly serial, one-chunk-at-a-time execution.
    async fn capacity(&self) -> usize {
        1
    }
}
