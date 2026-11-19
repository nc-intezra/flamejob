//! Phase 1 scheduler with server-side keyspace chunking.
//!
//! A job's keyspace (from `hashcat --keyspace`) is divided into chunk tasks,
//! each run with `--skip`/`--limit`. On the single box chunks run one at a time;
//! the same task rows are what Phase 3 will distribute across agents. A job
//! finishes early as soon as every hash is cracked.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use flamejob_api::{Event, JobConfig};
use flamejob_core::{JobState, RunHandle, Runner, RunnerTask, StatusUpdate, TaskState};
use flamejob_runner::LocalRunner;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::state::AppState;

/// Per-job inputs shared by every chunk of that job.
struct JobInputs {
    hash_type: i32,
    attack_mode: i16,
    hash_file: String,
    primary: String,
    rules: Vec<String>,
    extra_args: Vec<String>,
    total_keyspace: i64,
}

pub struct Scheduler {
    state: AppState,
    runner: Arc<dyn Runner>,
    running: Mutex<HashMap<Uuid, RunHandle>>, // job_id -> current chunk handle
    inputs: Mutex<HashMap<Uuid, Arc<JobInputs>>>, // job_id -> shared inputs
    retries: Mutex<HashMap<Uuid, u32>>,       // task_id -> attempts
    max_retries: u32,
    chunk_size: i64,
    max_chunks: i64,
}

pub fn spawn(state: AppState) {
    let runner: Arc<dyn Runner> = Arc::new(LocalRunner::new(
        state.cfg.hashcat.binary.clone(),
        state.cfg.hashcat.workload,
        state.cfg.hashcat.data_dir.clone(),
    ));
    let chunk_size = state.cfg.scheduler.chunk_size;
    let max_chunks = state.cfg.scheduler.max_chunks.max(1);
    let sched = Arc::new(Scheduler {
        state,
        runner,
        running: Mutex::new(HashMap::new()),
        inputs: Mutex::new(HashMap::new()),
        retries: Mutex::new(HashMap::new()),
        max_retries: 2,
        chunk_size,
        max_chunks,
    });
    metrics::gauge!("flamejob_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
    tokio::spawn(sched.run());
}

fn task_state_str(s: TaskState) -> &'static str {
    match s {
        TaskState::Pending => "pending",
        TaskState::Running => "running",
        TaskState::Paused => "paused",
        TaskState::Done => "done",
        TaskState::Failed => "failed",
    }
}

/// Split `total` keyspace into (offset, len) chunks. total <= 0 (unknown) yields
/// a single full-run chunk (len 0 => no --skip/--limit).
fn plan_chunks(total: i64, chunk_size: i64, max_chunks: i64) -> Vec<(i64, i64)> {
    if total <= 0 || chunk_size <= 0 {
        return vec![(0, 0)];
    }
    let mut size = chunk_size;
    let count = (total + size - 1) / size;
    if count > max_chunks {
        size = (total + max_chunks - 1) / max_chunks;
    }
    let mut chunks = Vec::new();
    let mut off = 0;
    while off < total {
        let len = size.min(total - off);
        chunks.push((off, len));
        off += len;
    }
    chunks
}

impl Scheduler {
    async fn run(self: Arc<Self>) {
        loop {
            if let Err(e) = self.tick().await {
                tracing::warn!(error = %e, "scheduler tick failed");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn tick(self: &Arc<Self>) -> anyhow::Result<()> {
        // Reconcile cancel/pause against the live chunk process.
        let ids: Vec<Uuid> = self.running.lock().await.keys().copied().collect();
        for job_id in ids {
            let st = self.job_state(job_id).await;
            if st == "cancelled" || st == "paused" {
                let handle = self.running.lock().await.get(&job_id).cloned();
                if let Some(h) = handle {
                    let _ = self.runner.cancel(&h).await;
                }
            }
        }
        // One job at a time on the single box. Resume an in-flight job's next
        // chunk before claiming a new job, so a job's chunks run to completion.
        if self.running.lock().await.is_empty() {
            if let Some(job_id) = self.resumable_job().await {
                if self.inputs.lock().await.contains_key(&job_id) {
                    self.start_next_chunk(job_id).await;
                } else {
                    // Inputs lost (e.g. restart mid-job): re-queue to rebuild.
                    let _ = sqlx::query("UPDATE jobs SET state = 'queued' WHERE id = $1")
                        .bind(job_id)
                        .execute(&self.state.db)
                        .await;
                }
            } else {
                self.claim_and_start().await?;
            }
        }
        self.refresh_metrics().await;
        Ok(())
    }

    async fn claim_and_start(self: &Arc<Self>) -> anyhow::Result<bool> {
        let mut tx = self.state.db.begin().await?;
        let row: Option<(Uuid, Uuid, i16, serde_json::Value)> = sqlx::query_as(
            "SELECT id, hashlist_id, attack_mode, config FROM jobs \
             WHERE state = 'queued' ORDER BY priority, created_at \
             FOR UPDATE SKIP LOCKED LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some((job_id, hashlist_id, attack_mode, config)) = row else {
            tx.rollback().await?;
            return Ok(false);
        };
        sqlx::query("UPDATE jobs SET state = 'assigned' WHERE id = $1")
            .bind(job_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        if let Err(e) = self.launch(job_id, hashlist_id, attack_mode, config).await {
            tracing::error!(%job_id, error = %e, "failed to launch job");
            let _ = sqlx::query(
                "UPDATE jobs SET state = 'error', error = $2, finished_at = now() WHERE id = $1",
            )
            .bind(job_id)
            .bind(e.to_string())
            .execute(&self.state.db)
            .await;
            self.cleanup(job_id).await;
        }
        Ok(true)
    }

    async fn launch(
        self: &Arc<Self>,
        job_id: Uuid,
        hashlist_id: Uuid,
        attack_mode: i16,
        config: serde_json::Value,
    ) -> anyhow::Result<()> {
        let inputs = Arc::new(
            self.prepare_inputs(job_id, hashlist_id, attack_mode, config)
                .await?,
        );
        let chunks = plan_chunks(inputs.total_keyspace, self.chunk_size, self.max_chunks);

        // Fresh set of chunk tasks (also clears a previous run on re-queue).
        sqlx::query("DELETE FROM tasks WHERE job_id = $1")
            .bind(job_id)
            .execute(&self.state.db)
            .await?;
        for (off, len) in &chunks {
            sqlx::query(
                "INSERT INTO tasks (id, job_id, runner_id, keyspace_offset, keyspace_len, state) \
                 VALUES ($1, $2, 'local', $3, $4, 'pending')",
            )
            .bind(Uuid::new_v4())
            .bind(job_id)
            .bind(off)
            .bind(len)
            .execute(&self.state.db)
            .await?;
        }
        self.inputs.lock().await.insert(job_id, inputs);
        sqlx::query("UPDATE jobs SET state = 'running', started_at = now() WHERE id = $1")
            .bind(job_id)
            .execute(&self.state.db)
            .await?;
        self.state.publish(Event::JobUpdated {
            job_id,
            state: JobState::Running,
        });
        tracing::info!(%job_id, chunks = chunks.len(), "job running (chunked)");
        self.start_next_chunk(job_id).await;
        Ok(())
    }

    async fn prepare_inputs(
        &self,
        job_id: Uuid,
        hashlist_id: Uuid,
        attack_mode: i16,
        config: serde_json::Value,
    ) -> anyhow::Result<JobInputs> {
        let cfg: JobConfig = serde_json::from_value(config)?;
        let hash_type: i32 = sqlx::query_scalar("SELECT hash_type FROM hashlists WHERE id = $1")
            .bind(hashlist_id)
            .fetch_one(&self.state.db)
            .await?;

        let hashes: Vec<(String, Option<String>)> =
            sqlx::query_as("SELECT hash, salt FROM hashes WHERE hashlist_id = $1")
                .bind(hashlist_id)
                .fetch_all(&self.state.db)
                .await?;
        let data_dir = PathBuf::from(&self.state.cfg.hashcat.data_dir);
        let hash_file = data_dir.join("jobs").join(format!("{job_id}.hashes"));
        if let Some(parent) = hash_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut body = String::new();
        for (h, s) in &hashes {
            match s {
                Some(salt) if !salt.is_empty() => {
                    body.push_str(h);
                    body.push(':');
                    body.push_str(salt);
                }
                _ => body.push_str(h),
            }
            body.push('\n');
        }
        tokio::fs::write(&hash_file, body).await?;

        let primary = if let Some(mask) = cfg.mask.clone() {
            mask
        } else if let Some(wid) = cfg.wordlist_file_id {
            file_path(&self.state.db, wid)
                .await?
                .ok_or_else(|| anyhow!("wordlist file {wid} not found"))?
        } else {
            return Err(anyhow!("job has neither wordlist nor mask"));
        };
        let mut rules = Vec::new();
        for rid in &cfg.rule_file_ids {
            if let Some(p) = file_path(&self.state.db, *rid).await? {
                rules.push(p);
            }
        }

        let hash_file = hash_file.display().to_string();
        let probe = RunnerTask {
            task_id: Uuid::nil(),
            hash_type,
            attack_mode,
            hash_file: hash_file.clone(),
            primary: primary.clone(),
            rules: rules.clone(),
            keyspace_offset: 0,
            keyspace_len: 0,
            extra_args: cfg.extra_args.clone(),
        };
        let total_keyspace = self
            .runner
            .keyspace(&probe)
            .await
            .map(|k| k as i64)
            .unwrap_or(0);

        Ok(JobInputs {
            hash_type,
            attack_mode,
            hash_file,
            primary,
            rules,
            extra_args: cfg.extra_args,
            total_keyspace,
        })
    }

    /// Start the lowest-offset pending chunk, or finalize the job if none remain.
    /// Returns true if a chunk was started.
    async fn start_next_chunk(self: &Arc<Self>, job_id: Uuid) -> bool {
        let inputs = match self.inputs.lock().await.get(&job_id).cloned() {
            Some(i) => i,
            None => return false,
        };
        let next: Option<(Uuid, i64, i64)> = sqlx::query_as(
            "SELECT id, keyspace_offset, keyspace_len FROM tasks \
             WHERE job_id = $1 AND state = 'pending' ORDER BY keyspace_offset LIMIT 1",
        )
        .bind(job_id)
        .fetch_optional(&self.state.db)
        .await
        .ok()
        .flatten();
        let Some((task_id, offset, len)) = next else {
            let (total, cracked) = self.counts(job_id).await;
            let st = if total > 0 && cracked >= total {
                "completed"
            } else {
                "exhausted"
            };
            self.set_job_terminal(job_id, st, None).await;
            return false;
        };

        let task = RunnerTask {
            task_id,
            hash_type: inputs.hash_type,
            attack_mode: inputs.attack_mode,
            hash_file: inputs.hash_file.clone(),
            primary: inputs.primary.clone(),
            rules: inputs.rules.clone(),
            keyspace_offset: offset,
            keyspace_len: len,
            extra_args: inputs.extra_args.clone(),
        };
        let _ = self.set_task(task_id, "running").await;
        let (tx, rx) = mpsc::channel(64);
        match self.runner.start(&task, tx).await {
            Ok(handle) => {
                self.running.lock().await.insert(job_id, handle);
                let me = self.clone();
                tokio::spawn(me.consume(job_id, task_id, rx));
                tracing::info!(%job_id, %task_id, offset, len, "chunk running");
                true
            }
            Err(e) => {
                tracing::error!(%job_id, %task_id, error = %e, "chunk failed to start");
                let _ = self.set_task(task_id, "failed").await;
                self.set_job_terminal(job_id, "error", Some("chunk failed to start"))
                    .await;
                false
            }
        }
    }

    async fn consume(
        self: Arc<Self>,
        job_id: Uuid,
        task_id: Uuid,
        mut rx: mpsc::Receiver<StatusUpdate>,
    ) {
        let mut last = TaskState::Running;
        while let Some(u) = rx.recv().await {
            let _ = sqlx::query(
                "UPDATE tasks SET progress = $1, speed = $2, state = $3::task_state, updated_at = now() WHERE id = $4",
            )
            .bind(u.progress)
            .bind(u.speed)
            .bind(task_state_str(u.state))
            .bind(task_id)
            .execute(&self.state.db)
            .await;
            let eta = self
                .compute_job_eta(job_id, task_id, u.progress, u.speed)
                .await
                .or(u.eta);
            if let Some(eta) = eta {
                let _ = sqlx::query("UPDATE jobs SET est_completion = $1 WHERE id = $2")
                    .bind(eta)
                    .bind(job_id)
                    .execute(&self.state.db)
                    .await;
            }
            self.state.publish(Event::TaskUpdated {
                job_id,
                task_id,
                progress: u.progress,
                speed: u.speed,
                eta: u.eta,
            });
            last = u.state;
        }
        self.finalize_chunk(job_id, task_id, last).await;
    }

    async fn finalize_chunk(self: &Arc<Self>, job_id: Uuid, task_id: Uuid, last: TaskState) {
        match self.job_state(job_id).await.as_str() {
            "cancelled" => {
                let _ = self.set_task(task_id, "failed").await;
                self.cleanup(job_id).await;
                return;
            }
            "paused" => {
                let _ = self.set_task(task_id, "paused").await;
                self.cleanup(job_id).await;
                return;
            }
            _ => {}
        }

        let _ = self.import_cracked(job_id, task_id).await;

        // Finish early if every hash is cracked.
        let (total, cracked) = self.counts(job_id).await;
        if total > 0 && cracked >= total {
            let _ = self.set_task(task_id, "done").await;
            self.set_job_terminal(job_id, "completed", None).await;
            return;
        }

        if last == TaskState::Done {
            let _ = self.set_task(task_id, "done").await;
            let pending: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM tasks WHERE job_id = $1 AND state = 'pending'",
            )
            .bind(job_id)
            .fetch_one(&self.state.db)
            .await
            .unwrap_or(0);
            if pending == 0 {
                // Last chunk done: finalize the whole job.
                let (total, cracked) = self.counts(job_id).await;
                let st = if total > 0 && cracked >= total {
                    "completed"
                } else {
                    "exhausted"
                };
                self.set_job_terminal(job_id, st, None).await;
            } else {
                // Release the slot; the tick loop starts the next pending chunk.
                self.running.lock().await.remove(&job_id);
            }
        } else {
            let attempts = {
                let mut m = self.retries.lock().await;
                let e = m.entry(task_id).or_insert(0);
                *e += 1;
                *e
            };
            if attempts <= self.max_retries {
                let _ = self.set_task(task_id, "pending").await; // re-run this chunk
                tracing::warn!(%job_id, %task_id, attempts, "chunk failed; retrying");
                self.running.lock().await.remove(&job_id);
            } else {
                let _ = self.set_task(task_id, "failed").await;
                self.set_job_terminal(job_id, "error", Some("chunk failed after retries"))
                    .await;
            }
        }
    }

    /// Per-job ETA: remaining keyspace across all not-done chunks (the running
    /// chunk counted by its remaining fraction) divided by current speed.
    async fn compute_job_eta(
        &self,
        job_id: Uuid,
        current_task: Uuid,
        progress: f64,
        speed: i64,
    ) -> Option<DateTime<Utc>> {
        if speed <= 0 {
            return None;
        }
        let rows: Vec<(Uuid, String, i64)> =
            sqlx::query_as("SELECT id, state::text, keyspace_len FROM tasks WHERE job_id = $1")
                .bind(job_id)
                .fetch_all(&self.state.db)
                .await
                .ok()?;
        let mut remaining = 0f64;
        for (id, state, len) in rows {
            if state == "done" || len <= 0 {
                continue;
            }
            if id == current_task {
                remaining += len as f64 * (1.0 - progress.clamp(0.0, 1.0));
            } else {
                remaining += len as f64;
            }
        }
        if remaining <= 0.0 {
            return None;
        }
        let secs = remaining / speed as f64;
        Some(Utc::now() + chrono::Duration::milliseconds((secs * 1000.0) as i64))
    }

    async fn resumable_job(&self) -> Option<Uuid> {
        sqlx::query_scalar(
            "SELECT j.id FROM jobs j WHERE j.state = 'running' \
             AND EXISTS (SELECT 1 FROM tasks t WHERE t.job_id = j.id AND t.state = 'pending') \
             ORDER BY j.priority, j.created_at LIMIT 1",
        )
        .fetch_optional(&self.state.db)
        .await
        .ok()
        .flatten()
    }

    async fn set_job_terminal(&self, job_id: Uuid, state: &str, error: Option<&str>) {
        let _ = sqlx::query(
            "UPDATE jobs SET state = $2::job_state, error = $3, finished_at = now() WHERE id = $1",
        )
        .bind(job_id)
        .bind(state)
        .bind(error)
        .execute(&self.state.db)
        .await;
        if let Ok(js) =
            serde_json::from_value::<JobState>(serde_json::Value::String(state.to_string()))
        {
            self.state.publish(Event::JobUpdated { job_id, state: js });
        }
        self.cleanup(job_id).await;
        tracing::info!(%job_id, state, "job finalized");
    }

    async fn cleanup(&self, job_id: Uuid) {
        self.running.lock().await.remove(&job_id);
        self.inputs.lock().await.remove(&job_id);
    }

    async fn counts(&self, job_id: Uuid) -> (i32, i32) {
        sqlx::query_as(
            "SELECT h.total, h.cracked FROM hashlists h JOIN jobs j ON j.hashlist_id = h.id WHERE j.id = $1",
        )
        .bind(job_id)
        .fetch_one(&self.state.db)
        .await
        .unwrap_or((0, 0))
    }

    async fn job_state(&self, job_id: Uuid) -> String {
        sqlx::query_scalar("SELECT state::text FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&self.state.db)
            .await
            .unwrap_or_else(|_| "error".into())
    }

    async fn set_task(&self, task_id: Uuid, state: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE tasks SET state = $2::task_state, updated_at = now() WHERE id = $1")
            .bind(task_id)
            .bind(state)
            .execute(&self.state.db)
            .await
            .map(|_| ())
    }

    async fn import_cracked(&self, job_id: Uuid, task_id: Uuid) -> anyhow::Result<()> {
        let data_dir = PathBuf::from(&self.state.cfg.hashcat.data_dir);
        let outfile = LocalRunner::outfile_path(&data_dir, task_id);
        let content = match tokio::fs::read_to_string(&outfile).await {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        let hashlist_id: Uuid = sqlx::query_scalar("SELECT hashlist_id FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&self.state.db)
            .await?;
        for line in content.lines() {
            let line = line.trim();
            let Some((hash, plain)) = line.rsplit_once(':') else {
                continue;
            };
            let ct = self.state.cipher.encrypt(plain.as_bytes());
            let _ = sqlx::query(
                "UPDATE hashes SET plain = $1, cracked_at = now() \
                 WHERE hashlist_id = $2 AND hash = $3 AND plain IS NULL",
            )
            .bind(ct)
            .bind(hashlist_id)
            .bind(hash)
            .execute(&self.state.db)
            .await;
            self.state.publish(Event::HashCracked {
                hashlist_id,
                hash: hash.to_string(),
            });
        }
        let _ = sqlx::query(
            "UPDATE hashlists SET cracked = \
             (SELECT count(*) FROM hashes WHERE hashlist_id = $1 AND plain IS NOT NULL) WHERE id = $1",
        )
        .bind(hashlist_id)
        .execute(&self.state.db)
        .await;
        Ok(())
    }

    async fn refresh_metrics(&self) {
        if let Ok(by_state) = flamejob_db::count_jobs_by_state(&self.state.db).await {
            for (state, n) in by_state {
                metrics::gauge!("flamejob_jobs", "state" => state).set(n as f64);
            }
        }
        let running = self.running.lock().await.len() as f64;
        metrics::gauge!("flamejob_tasks_running").set(running);
    }
}

async fn file_path(db: &flamejob_db::Db, id: Uuid) -> anyhow::Result<Option<String>> {
    Ok(sqlx::query_scalar("SELECT path FROM files WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await?)
}

#[cfg(test)]
mod tests {
    use super::plan_chunks;

    #[test]
    fn chunking_splits_keyspace() {
        assert_eq!(plan_chunks(40, 15, 500), vec![(0, 15), (15, 15), (30, 10)]);
        assert_eq!(plan_chunks(0, 15, 500), vec![(0, 0)]); // unknown keyspace -> one chunk
        assert_eq!(plan_chunks(10, 15, 500), vec![(0, 10)]); // smaller than chunk size
                                                             // max_chunks cap widens the chunk size
        let c = plan_chunks(1000, 1, 4);
        assert!(c.len() <= 4);
        assert_eq!(c.iter().map(|(_, l)| l).sum::<i64>(), 1000);
    }
}
