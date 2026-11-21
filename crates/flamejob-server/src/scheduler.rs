//! Scheduler with server-side keyspace chunking and multi-agent parallelism.
//!
//! A job's keyspace (from `hashcat --keyspace`) is divided into chunk tasks,
//! each run with `--skip`/`--limit`. The scheduler keeps up to `Runner::capacity`
//! chunks of the active job in flight at once, so a single job fans out across
//! the whole fleet (or across several local hashcat processes). A job finishes
//! early as soon as every hash is cracked.
//!
//! One job is active at a time; its chunks run in parallel. When a job has no
//! more pending or in-flight chunks it is finalized and the next queued job is
//! claimed.
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

/// A chunk task currently executing.
struct Inflight {
    job_id: Uuid,
    handle: RunHandle,
}

pub struct Scheduler {
    state: AppState,
    runner: Arc<dyn Runner>,
    inflight: Mutex<HashMap<Uuid, Inflight>>, // task_id -> running chunk
    inputs: Mutex<HashMap<Uuid, Arc<JobInputs>>>, // job_id -> shared inputs
    progress: Mutex<HashMap<Uuid, (f64, i64)>>, // task_id -> (progress, speed) for live ETA
    retries: Mutex<HashMap<Uuid, u32>>,       // task_id -> attempts
    max_retries: u32,
    chunk_size: i64,
    max_chunks: i64,
}

pub fn spawn(state: AppState) {
    let runner: Arc<dyn Runner> = if state.cfg.scheduler.runner == "remote" {
        tracing::info!("scheduler using RemoteRunner (agent dispatch)");
        Arc::new(crate::agent::RemoteRunner::new(state.agents.clone()))
    } else {
        Arc::new(LocalRunner::new(
            state.cfg.hashcat.binary.clone(),
            state.cfg.hashcat.workload,
            state.cfg.hashcat.data_dir.clone(),
            state.cfg.scheduler.local_parallelism,
        ))
    };
    let chunk_size = state.cfg.scheduler.chunk_size;
    let max_chunks = state.cfg.scheduler.max_chunks.max(1);
    let sched = Arc::new(Scheduler {
        state,
        runner,
        inflight: Mutex::new(HashMap::new()),
        inputs: Mutex::new(HashMap::new()),
        progress: Mutex::new(HashMap::new()),
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
        // 1) Reconcile cancel/pause against the live chunk processes of each job
        //    that currently has work in flight.
        for job_id in self.inflight_jobs().await {
            let st = self.job_state(job_id).await;
            if st == "cancelled" || st == "paused" {
                for h in self.inflight_handles_for(job_id).await {
                    let _ = self.runner.cancel(&h).await;
                }
            }
        }

        // 2) Backstop: finalize any running job whose chunks are all terminal
        //    (covers a mid-job restart where the consume loops were lost).
        self.finalize_completed_jobs().await;

        // 3) Keep the active job's chunks filled to capacity; only claim a new
        //    job once no running job has remaining work (one job at a time).
        if let Some(job_id) = self.running_job_with_work().await {
            if self.inputs.lock().await.contains_key(&job_id) {
                self.fill_capacity(job_id).await;
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
        // Fan the first wave of chunks across available capacity immediately.
        self.fill_capacity(job_id).await;
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

    /// Start pending chunks of `job_id` until the number in flight for that job
    /// reaches the runner's current capacity (fleet slots, or local parallelism).
    async fn fill_capacity(self: &Arc<Self>, job_id: Uuid) {
        if !self.inputs.lock().await.contains_key(&job_id) {
            return;
        }
        let want = self.runner.capacity().await.max(1);
        loop {
            if self.inflight_count_for(job_id).await >= want {
                break;
            }
            match self.next_pending_chunk(job_id).await {
                Some((task_id, offset, len)) => {
                    if !self.start_chunk(job_id, task_id, offset, len).await {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    async fn next_pending_chunk(&self, job_id: Uuid) -> Option<(Uuid, i64, i64)> {
        sqlx::query_as(
            "SELECT id, keyspace_offset, keyspace_len FROM tasks \
             WHERE job_id = $1 AND state = 'pending' ORDER BY keyspace_offset LIMIT 1",
        )
        .bind(job_id)
        .fetch_optional(&self.state.db)
        .await
        .ok()
        .flatten()
    }

    /// Launch one specific pending chunk. Returns true if it is now in flight.
    async fn start_chunk(
        self: &Arc<Self>,
        job_id: Uuid,
        task_id: Uuid,
        offset: i64,
        len: i64,
    ) -> bool {
        let inputs = match self.inputs.lock().await.get(&job_id).cloned() {
            Some(i) => i,
            None => return false,
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
        // Mark running before dispatch so the next fill iteration won't re-pick it.
        let _ = self.set_task(task_id, "running").await;
        let (tx, rx) = mpsc::channel(64);
        match self.runner.start(&task, tx).await {
            Ok(handle) => {
                self.inflight
                    .lock()
                    .await
                    .insert(task_id, Inflight { job_id, handle });
                self.progress.lock().await.insert(task_id, (0.0, 0));
                let me = self.clone();
                tokio::spawn(me.consume(job_id, task_id, rx));
                tracing::info!(%job_id, %task_id, offset, len, "chunk running");
                true
            }
            Err(e) => {
                tracing::error!(%job_id, %task_id, error = %e, "chunk failed to start");
                self.handle_chunk_failure(job_id, task_id).await;
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
            self.progress
                .lock()
                .await
                .insert(task_id, (u.progress, u.speed));
            let eta = self.compute_job_eta(job_id).await.or(u.eta);
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
        // This chunk is no longer running.
        self.inflight.lock().await.remove(&task_id);
        self.progress.lock().await.remove(&task_id);

        match self.job_state(job_id).await.as_str() {
            "cancelled" => {
                let _ = self.set_task(task_id, "failed").await;
                self.maybe_release_inputs(job_id).await;
                return;
            }
            "paused" => {
                let _ = self.set_task(task_id, "paused").await;
                self.maybe_release_inputs(job_id).await;
                return;
            }
            // Job already finalized by another chunk (early finish, error): just
            // record this chunk's terminal state.
            "completed" | "exhausted" | "error" => {
                let s = if last == TaskState::Done {
                    "done"
                } else {
                    "failed"
                };
                let _ = self.set_task(task_id, s).await;
                self.maybe_release_inputs(job_id).await;
                return;
            }
            _ => {}
        }

        let _ = self.import_cracked(job_id, task_id).await;

        // Finish early if every hash is cracked.
        let (total, cracked) = self.counts(job_id).await;
        if total > 0 && cracked >= total {
            let _ = self.set_task(task_id, "done").await;
            self.cancel_inflight_for(job_id).await;
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
            let others = self.inflight_count_for(job_id).await;
            if pending == 0 && others == 0 {
                // Last chunk of the job done: finalize the whole job.
                let (total, cracked) = self.counts(job_id).await;
                let st = if total > 0 && cracked >= total {
                    "completed"
                } else {
                    "exhausted"
                };
                self.set_job_terminal(job_id, st, None).await;
            }
            // else: the tick loop fills the next pending chunk into the free slot.
        } else {
            self.handle_chunk_failure(job_id, task_id).await;
        }
    }

    /// Retry a failed chunk, or fail the whole job once retries are exhausted.
    async fn handle_chunk_failure(self: &Arc<Self>, job_id: Uuid, task_id: Uuid) {
        let attempts = {
            let mut m = self.retries.lock().await;
            let e = m.entry(task_id).or_insert(0);
            *e += 1;
            *e
        };
        if attempts <= self.max_retries {
            let _ = self.set_task(task_id, "pending").await; // re-run this chunk
            tracing::warn!(%job_id, %task_id, attempts, "chunk failed; retrying");
        } else {
            let _ = self.set_task(task_id, "failed").await;
            self.cancel_inflight_for(job_id).await;
            self.set_job_terminal(job_id, "error", Some("chunk failed after retries"))
                .await;
        }
    }

    /// Per-job ETA: remaining keyspace across all not-done chunks (each in-flight
    /// chunk counted by its remaining fraction) divided by the *combined* speed
    /// of the chunks currently running — so parallel chunks shorten the ETA.
    async fn compute_job_eta(&self, job_id: Uuid) -> Option<DateTime<Utc>> {
        let rows: Vec<(Uuid, String, i64)> =
            sqlx::query_as("SELECT id, state::text, keyspace_len FROM tasks WHERE job_id = $1")
                .bind(job_id)
                .fetch_all(&self.state.db)
                .await
                .ok()?;
        let prog = self.progress.lock().await;
        let mut remaining = 0f64;
        let mut speed = 0i64;
        for (id, state, len) in rows {
            if state == "done" || len <= 0 {
                continue;
            }
            let (p, sp) = prog.get(&id).copied().unwrap_or((0.0, 0));
            remaining += len as f64 * (1.0 - p.clamp(0.0, 1.0));
            if state == "running" {
                speed += sp;
            }
        }
        drop(prog);
        if speed <= 0 || remaining <= 0.0 {
            return None;
        }
        let secs = remaining / speed as f64;
        Some(Utc::now() + chrono::Duration::milliseconds((secs * 1000.0) as i64))
    }

    /// A running job that still has pending or in-flight chunks (the one we fan).
    async fn running_job_with_work(&self) -> Option<Uuid> {
        sqlx::query_scalar(
            "SELECT j.id FROM jobs j WHERE j.state = 'running' \
             AND EXISTS (SELECT 1 FROM tasks t WHERE t.job_id = j.id \
                         AND t.state IN ('pending','running')) \
             ORDER BY j.priority, j.created_at LIMIT 1",
        )
        .fetch_optional(&self.state.db)
        .await
        .ok()
        .flatten()
    }

    /// Finalize any job stuck in `running` with no pending/running chunks left
    /// and nothing in flight (a backstop for finalize_chunk, e.g. after restart).
    async fn finalize_completed_jobs(&self) {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT j.id FROM jobs j WHERE j.state = 'running' \
             AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.job_id = j.id \
                             AND t.state IN ('pending','running'))",
        )
        .fetch_all(&self.state.db)
        .await
        .unwrap_or_default();
        for job_id in ids {
            if self.inflight_count_for(job_id).await > 0 {
                continue;
            }
            let (total, cracked) = self.counts(job_id).await;
            let st = if total > 0 && cracked >= total {
                "completed"
            } else {
                "exhausted"
            };
            self.set_job_terminal(job_id, st, None).await;
        }
    }

    async fn set_job_terminal(&self, job_id: Uuid, state: &str, error: Option<&str>) {
        // Idempotent: only the first transition out of a non-terminal state wins,
        // so concurrent chunk finalizers don't double-finalize or double-publish.
        let changed = sqlx::query(
            "UPDATE jobs SET state = $2::job_state, error = $3, finished_at = now() \
             WHERE id = $1 AND state NOT IN ('completed','exhausted','cancelled','error')",
        )
        .bind(job_id)
        .bind(state)
        .bind(error)
        .execute(&self.state.db)
        .await
        .map(|r| r.rows_affected() > 0)
        .unwrap_or(false);
        if changed {
            if let Ok(js) =
                serde_json::from_value::<JobState>(serde_json::Value::String(state.to_string()))
            {
                self.state.publish(Event::JobUpdated { job_id, state: js });
            }
            tracing::info!(%job_id, state, "job finalized");
        }
        self.cleanup(job_id).await;
    }

    async fn cleanup(&self, job_id: Uuid) {
        self.inflight.lock().await.retain(|_, i| i.job_id != job_id);
        self.inputs.lock().await.remove(&job_id);
    }

    /// Drop a finished job's shared inputs once no chunk of it is still running.
    async fn maybe_release_inputs(&self, job_id: Uuid) {
        if self.inflight_count_for(job_id).await == 0 {
            self.inputs.lock().await.remove(&job_id);
        }
    }

    async fn inflight_jobs(&self) -> Vec<Uuid> {
        let g = self.inflight.lock().await;
        let mut v: Vec<Uuid> = g.values().map(|i| i.job_id).collect();
        v.sort();
        v.dedup();
        v
    }

    async fn inflight_handles_for(&self, job_id: Uuid) -> Vec<RunHandle> {
        self.inflight
            .lock()
            .await
            .values()
            .filter(|i| i.job_id == job_id)
            .map(|i| i.handle.clone())
            .collect()
    }

    async fn inflight_count_for(&self, job_id: Uuid) -> usize {
        self.inflight
            .lock()
            .await
            .values()
            .filter(|i| i.job_id == job_id)
            .count()
    }

    async fn cancel_inflight_for(&self, job_id: Uuid) {
        for h in self.inflight_handles_for(job_id).await {
            let _ = self.runner.cancel(&h).await;
        }
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
        let running = self.inflight.lock().await.len() as f64;
        metrics::gauge!("flamejob_tasks_running").set(running);
        let agents = self.state.agents.connected_count().await as f64;
        metrics::gauge!("flamejob_agents_connected").set(agents);
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
