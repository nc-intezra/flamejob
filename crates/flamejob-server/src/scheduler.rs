//! Scheduler with server-side keyspace chunking and many-job, many-agent
//! parallelism.
//!
//! A job's keyspace (from `hashcat --keyspace`) is divided into chunk tasks,
//! each run with `--skip`/`--limit`. The scheduler admits up to
//! `[scheduler].max_concurrent_jobs` jobs at once and then distributes the
//! fleet's whole chunk capacity (`Runner::capacity` — agent free-slots, or the
//! local parallelism) across every admitted job: each tick it fills free
//! capacity by taking one pending chunk from each running job in priority order,
//! round-robin, so several jobs make progress at once and a single job still
//! fans across every agent. A job finishes early as soon as every hash is
//! cracked, and is finalized independently when its own chunks are all done.
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

/// Per-job ETA estimator state: the last observed overall progress and when it
/// was seen, plus a smoothed completion rate (progress fraction per second).
#[derive(Clone, Copy)]
struct EtaState {
    progress: f64,
    at: DateTime<Utc>,
    rate: f64,
}

/// EMA weight for a fresh rate sample (vs. the retained smoothed rate).
const ETA_EMA_ALPHA: f64 = 0.4;
/// Minimum elapsed time between rate samples; shorter gaps are too noisy to
/// divide by, so we keep accumulating against the previous sample.
const ETA_MIN_DT_SECS: f64 = 0.75;
/// A gap longer than this (seconds) is treated as a discontinuity (pause/resume,
/// scheduler restart): the rate is re-baselined rather than inferred from it.
const ETA_RESET_SECS: i64 = 20;

pub struct Scheduler {
    state: AppState,
    runner: Arc<dyn Runner>,
    inflight: Mutex<HashMap<Uuid, Inflight>>, // task_id -> running chunk
    inputs: Mutex<HashMap<Uuid, Arc<JobInputs>>>, // job_id -> shared inputs
    progress: Mutex<HashMap<Uuid, (f64, i64)>>, // task_id -> (progress, speed) for live ETA
    eta: Mutex<HashMap<Uuid, EtaState>>,      // job_id -> progress-rate ETA state
    retries: Mutex<HashMap<Uuid, u32>>,       // task_id -> attempts
    max_retries: u32,
    chunk_size: i64,
    max_chunks: i64,
    /// How many jobs may be admitted (running) at once. 0 = unlimited.
    max_concurrent_jobs: usize,
}

/// Update a job's smoothed completion rate from a new progress observation and
/// return (new_rate, remaining_secs). `rate` is progress fraction per second.
/// When `dt_secs` is too small to measure, the previous rate is retained.
/// Pure so it can be unit-tested without a scheduler/DB.
fn project_eta(
    prev_progress: f64,
    prev_rate: f64,
    overall: f64,
    dt_secs: f64,
) -> (f64, Option<f64>) {
    let mut rate = prev_rate;
    if dt_secs >= ETA_MIN_DT_SECS {
        let inst = (overall - prev_progress) / dt_secs;
        if inst > 0.0 {
            rate = if prev_rate > 0.0 {
                ETA_EMA_ALPHA * inst + (1.0 - ETA_EMA_ALPHA) * prev_rate
            } else {
                inst
            };
        }
    }
    let remaining = if rate > 0.0 && overall < 1.0 {
        let r = (1.0 - overall) / rate;
        r.is_finite().then_some(r)
    } else {
        None
    };
    (rate, remaining)
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
    let state_cfg_max_concurrent_jobs = state.cfg.scheduler.max_concurrent_jobs;
    let sched = Arc::new(Scheduler {
        state,
        runner,
        inflight: Mutex::new(HashMap::new()),
        inputs: Mutex::new(HashMap::new()),
        progress: Mutex::new(HashMap::new()),
        eta: Mutex::new(HashMap::new()),
        retries: Mutex::new(HashMap::new()),
        max_retries: 2,
        chunk_size,
        max_chunks,
        max_concurrent_jobs: state_cfg_max_concurrent_jobs,
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

        // 3) Re-queue any running job whose in-memory inputs were lost to a
        //    restart (so it is rebuilt), admit queued jobs up to the concurrency
        //    cap, then distribute the fleet's capacity across every running job.
        self.requeue_orphaned_running().await;
        self.promote_queued_jobs().await?;
        self.fill_fleet().await;

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
        tracing::info!(%job_id, chunks = chunks.len(), "job admitted (chunked)");
        // The next fill_fleet pass starts this job's chunks alongside the others.
        Ok(())
    }

    /// Admit queued jobs (lowest priority number first) into the running set
    /// until the concurrency cap is reached or nothing is queued.
    async fn promote_queued_jobs(self: &Arc<Self>) -> anyhow::Result<()> {
        loop {
            if self.max_concurrent_jobs > 0 {
                let active: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM jobs WHERE state IN ('assigned','running')",
                )
                .fetch_one(&self.state.db)
                .await
                .unwrap_or(0);
                if active as usize >= self.max_concurrent_jobs {
                    break;
                }
            }
            if !self.claim_and_start().await? {
                break;
            }
        }
        Ok(())
    }

    /// Re-queue running jobs whose shared inputs are missing from memory (a
    /// restart mid-job); `promote`/`launch` then rebuilds their chunk set.
    async fn requeue_orphaned_running(&self) {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT j.id FROM jobs j WHERE j.state = 'running' \
             AND EXISTS (SELECT 1 FROM tasks t WHERE t.job_id = j.id \
                         AND t.state IN ('pending','running'))",
        )
        .fetch_all(&self.state.db)
        .await
        .unwrap_or_default();
        let missing: Vec<Uuid> = {
            let inputs = self.inputs.lock().await;
            ids.into_iter()
                .filter(|id| !inputs.contains_key(id))
                .collect()
        };
        for job_id in missing {
            let _ = sqlx::query("UPDATE jobs SET state = 'queued' WHERE id = $1")
                .bind(job_id)
                .execute(&self.state.db)
                .await;
        }
    }

    /// Distribute the fleet's chunk capacity across all admitted jobs using
    /// weighted fair-share across the owning directory groups (PR3): each free
    /// slot goes to the fairest group's next job (see `crate::fairness`), which
    /// for a single ungrouped tenant degenerates to the previous per-job
    /// round-robin. Stops at `Runner::capacity`, when nothing is pending, or when
    /// every eligible group is at its ceiling.
    async fn fill_fleet(self: &Arc<Self>) {
        let want = self.runner.capacity().await.max(1);
        let quotas = self.load_quotas().await;
        loop {
            if self.inflight.lock().await.len() >= want {
                break;
            }

            // In-flight chunk counts per job and per owning group, from the live
            // in-memory dispatch map (authoritative for what the scheduler has
            // placed), mapped to groups via the active jobs' owner_group_sid.
            let job_group = self.active_group_map().await;
            let (if_job, if_group) = {
                let inflight = self.inflight.lock().await;
                let mut ij: HashMap<Uuid, i64> = HashMap::new();
                for v in inflight.values() {
                    *ij.entry(v.job_id).or_insert(0) += 1;
                }
                let mut ig: HashMap<String, i64> = HashMap::new();
                for (job, n) in &ij {
                    let g = job_group.get(job).cloned().unwrap_or_default();
                    *ig.entry(g).or_insert(0) += n;
                }
                (ij, ig)
            };

            // Candidates: running jobs with a pending chunk AND ready inputs.
            let rows = self.fillable_candidate_rows().await;
            let cands: Vec<crate::fairness::Candidate> = {
                let ready = self.inputs.lock().await;
                rows.into_iter()
                    .filter(|(id, _, _, _)| ready.contains_key(id))
                    .map(
                        |(id, group, priority, created_at)| crate::fairness::Candidate {
                            job_id: id,
                            group,
                            priority,
                            created_at,
                            in_flight_job: *if_job.get(&id).unwrap_or(&0),
                        },
                    )
                    .collect()
            };
            if cands.is_empty() {
                break;
            }

            let Some(job_id) = crate::fairness::select_job(&cands, &if_group, &quotas) else {
                break; // every eligible group is at its ceiling
            };
            match self.next_pending_chunk(job_id).await {
                Some((task_id, off, len)) => {
                    if !self.start_chunk(job_id, task_id, off, len).await {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    /// owner group SID (``"" `` = ungrouped) for every active job, for in-flight
    /// accounting.
    async fn active_group_map(&self) -> HashMap<Uuid, String> {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, COALESCE(owner_group_sid, '') FROM jobs \
             WHERE state IN ('running','assigned')",
        )
        .fetch_all(&self.state.db)
        .await
        .unwrap_or_default();
        rows.into_iter().collect()
    }

    /// Running jobs that still have a pending chunk, with their group, priority
    /// and creation epoch (for the fair-share selector).
    async fn fillable_candidate_rows(&self) -> Vec<(Uuid, String, i32, i64)> {
        sqlx::query_as(
            "SELECT j.id, COALESCE(j.owner_group_sid, ''), j.priority, \
                    EXTRACT(EPOCH FROM j.created_at)::bigint \
             FROM jobs j WHERE j.state = 'running' \
             AND EXISTS (SELECT 1 FROM tasks t WHERE t.job_id = j.id AND t.state = 'pending')",
        )
        .fetch_all(&self.state.db)
        .await
        .unwrap_or_default()
    }

    /// Per-group fair-share policy from `group_quota` (groups without a row use
    /// the defaults via the selector).
    async fn load_quotas(&self) -> HashMap<String, crate::fairness::Quota> {
        let rows: Vec<(String, i32, i32, Option<i32>)> =
            sqlx::query_as("SELECT group_sid, weight, floor_slots, ceil_slots FROM group_quota")
                .fetch_all(&self.state.db)
                .await
                .unwrap_or_default();
        rows.into_iter()
            .map(|(sid, w, fl, cl)| {
                (
                    sid,
                    crate::fairness::Quota {
                        weight: (w as f64).max(1.0),
                        floor: fl as i64,
                        ceil: cl.map(|c| c as i64),
                    },
                )
            })
            .collect()
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
            pinned_agent_id: None, // keyspace probe: any agent may answer
            allowed_agents: None,  // probe is metadata-only; pool-blind by design
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

    /// The agent-id allow-set for a job, re-derived live from its snapshotted
    /// eligible pools. `None` = unrestricted (empty `eligible_pool_ids`, i.e. a
    /// local/unpooled job). `Some(set)` = members of those pools right now (may
    /// be empty, in which case the chunk waits for an authorized agent).
    async fn eligible_agents_for(&self, job_id: Uuid) -> Option<Vec<Uuid>> {
        let pools: Vec<Uuid> =
            sqlx::query_scalar("SELECT eligible_pool_ids FROM jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&self.state.db)
                .await
                .unwrap_or_default();
        if pools.is_empty() {
            return None;
        }
        let agents: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT agent_id FROM agent_pool_members WHERE pool_id = ANY($1)",
        )
        .bind(&pools)
        .fetch_all(&self.state.db)
        .await
        .unwrap_or_default();
        Some(agents)
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
        // Read the pin fresh at dispatch time so pinning a job mid-run takes
        // effect on its next chunk (the remote runner honors it; local ignores).
        let pinned_agent_id: Option<Uuid> =
            sqlx::query_scalar::<_, Option<Uuid>>("SELECT pinned_agent_id FROM jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&self.state.db)
                .await
                .unwrap_or(None);
        // Re-derive pool eligibility live at dispatch, so revoking a grant or
        // moving an agent out of a pool takes effect on the next chunk. Empty
        // `eligible_pool_ids` (local/unrestricted job) => None (any agent).
        let allowed_agents = self.eligible_agents_for(job_id).await;
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
            pinned_agent_id,
            allowed_agents,
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
            // Observed-rate ETA first; fall back to hashcat's own estimate only
            // when it's actually in the future. Never store a past timestamp —
            // that's what rendered as "soon".
            let now = Utc::now();
            let eta = self
                .compute_job_eta(job_id)
                .await
                .or_else(|| u.eta.filter(|e| *e > now));
            if let Some(eta) = eta.filter(|e| *e > now) {
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

    /// Per-job ETA from *observed progress over wall-clock time*. The job's
    /// overall keyspace-weighted progress is sampled on each update; the rate at
    /// which that percentage climbs (smoothed) is projected to 100%. This
    /// reflects real throughput — unlike remaining-keyspace ÷ reported-speed,
    /// which is wildly optimistic for small/fast jobs (a 23 GH/s rig "finishes"
    /// an 81M keyspace in milliseconds even while the run visibly takes minutes)
    /// and so always rounded to "soon". Returns None until a rate is established.
    async fn compute_job_eta(&self, job_id: Uuid) -> Option<DateTime<Utc>> {
        let rows: Vec<(Uuid, String, i64)> =
            sqlx::query_as("SELECT id, state::text, keyspace_len FROM tasks WHERE job_id = $1")
                .bind(job_id)
                .fetch_all(&self.state.db)
                .await
                .ok()?;
        // Overall progress = done keyspace / total keyspace across all chunks.
        let prog = self.progress.lock().await;
        let mut total = 0f64;
        let mut done = 0f64;
        for (id, state, len) in &rows {
            if *len <= 0 {
                continue;
            }
            let l = *len as f64;
            total += l;
            if state == "done" {
                done += l;
            } else {
                let (p, _) = prog.get(id).copied().unwrap_or((0.0, 0));
                done += l * p.clamp(0.0, 1.0);
            }
        }
        drop(prog);
        if total <= 0.0 {
            return None;
        }
        let overall = (done / total).clamp(0.0, 1.0);
        if overall >= 1.0 {
            return None;
        }

        let now = Utc::now();
        let mut states = self.eta.lock().await;
        let remaining_secs = match states.get(&job_id).copied() {
            // A long gap (e.g. the job was paused and resumed) makes the old
            // sample meaningless — re-baseline instead of inferring a near-zero
            // rate from the elapsed wall time.
            Some(prev) if (now - prev.at).num_seconds() > ETA_RESET_SECS => {
                states.insert(
                    job_id,
                    EtaState {
                        progress: overall,
                        at: now,
                        rate: 0.0,
                    },
                );
                None
            }
            Some(prev) => {
                let dt = (now - prev.at).num_milliseconds() as f64 / 1000.0;
                let (rate, remaining) = project_eta(prev.progress, prev.rate, overall, dt);
                // Only advance the stored sample once enough time has elapsed to
                // measure, so sub-second bursts of updates don't reset the window.
                if dt >= ETA_MIN_DT_SECS {
                    states.insert(
                        job_id,
                        EtaState {
                            progress: overall,
                            at: now,
                            rate,
                        },
                    );
                }
                remaining
            }
            None => {
                states.insert(
                    job_id,
                    EtaState {
                        progress: overall,
                        at: now,
                        rate: 0.0,
                    },
                );
                None // need a second sample before we can estimate a rate
            }
        };
        drop(states);
        let remaining_secs = remaining_secs?;
        if remaining_secs <= 0.0 {
            return None;
        }
        Some(now + chrono::Duration::milliseconds((remaining_secs * 1000.0) as i64))
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
            "UPDATE jobs SET state = $2::job_state, error = $3, finished_at = now(), \
             est_completion = NULL \
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
        self.eta.lock().await.remove(&job_id);
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
    use super::{plan_chunks, project_eta};

    #[test]
    fn eta_projects_from_observed_rate() {
        // No prior rate: first real sample (10% over 10s) -> ~1%/s, ~90s left.
        let (rate, remaining) = project_eta(0.0, 0.0, 0.10, 10.0);
        assert!((rate - 0.01).abs() < 1e-9);
        let r = remaining.expect("rate established -> an estimate");
        assert!((r - 90.0).abs() < 1e-6, "got {r}");

        // A sub-threshold gap keeps the previous rate and still projects.
        let (rate2, remaining2) = project_eta(0.10, 0.01, 0.1001, 0.1);
        assert!((rate2 - 0.01).abs() < 1e-9, "tiny dt retains the rate");
        assert!(remaining2.unwrap() > 0.0);

        // No progress yet (rate stays 0) -> no estimate.
        assert_eq!(project_eta(0.0, 0.0, 0.0, 5.0).1, None);
    }

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
