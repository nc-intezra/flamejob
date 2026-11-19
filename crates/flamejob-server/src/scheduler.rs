//! Phase 1 scheduler: claim queued jobs, run hashcat through the Runner, stream
//! status back into the task/job rows, import cracked hashes (encrypted), and
//! reconcile cancel/pause requested via the API. One job runs at a time on the
//! single box.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use flamejob_api::JobConfig;
use flamejob_core::{RunHandle, Runner, RunnerTask, TaskState};
use flamejob_runner::LocalRunner;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::state::AppState;

pub struct Scheduler {
    state: AppState,
    runner: Arc<dyn Runner>,
    running: Mutex<HashMap<Uuid, RunHandle>>,
    retries: Mutex<HashMap<Uuid, u32>>,
    max_retries: u32,
}

pub fn spawn(state: AppState) {
    let runner: Arc<dyn Runner> = Arc::new(LocalRunner::new(
        state.cfg.hashcat.binary.clone(),
        state.cfg.hashcat.workload,
        state.cfg.hashcat.data_dir.clone(),
    ));
    let sched = Arc::new(Scheduler {
        state,
        runner,
        running: Mutex::new(HashMap::new()),
        retries: Mutex::new(HashMap::new()),
        max_retries: 2,
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
        // Reconcile cancel/pause requested via the API against live processes.
        let ids: Vec<Uuid> = self.running.lock().await.keys().copied().collect();
        for job_id in ids {
            let st: String = sqlx::query_scalar("SELECT state::text FROM jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&self.state.db)
                .await
                .unwrap_or_default();
            if st == "cancelled" || st == "paused" {
                let handle = self.running.lock().await.get(&job_id).cloned();
                if let Some(h) = handle {
                    let _ = self.runner.cancel(&h).await;
                }
            }
        }
        // Capacity: one job at a time on the single box.
        if self.running.lock().await.is_empty() {
            self.claim_and_start().await?;
        }
        // Refresh Prometheus gauges.
        if let Ok(by_state) = flamejob_db::count_jobs_by_state(&self.state.db).await {
            for (state, n) in by_state {
                metrics::gauge!("flamejob_jobs", "state" => state).set(n as f64);
            }
        }
        let running = self.running.lock().await.len() as f64;
        metrics::gauge!("flamejob_tasks_running").set(running);
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
        let task = self
            .prepare_task(job_id, hashlist_id, attack_mode, config)
            .await?;
        sqlx::query(
            "INSERT INTO tasks (id, job_id, runner_id, keyspace_offset, keyspace_len, state) \
             VALUES ($1, $2, 'local', $3, $4, 'running')",
        )
        .bind(task.task_id)
        .bind(job_id)
        .bind(task.keyspace_offset)
        .bind(task.keyspace_len)
        .execute(&self.state.db)
        .await?;
        sqlx::query("UPDATE jobs SET state = 'running', started_at = now() WHERE id = $1")
            .bind(job_id)
            .execute(&self.state.db)
            .await?;

        let (tx, rx) = mpsc::channel(64);
        let handle = self
            .runner
            .start(&task, tx)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        self.running.lock().await.insert(job_id, handle);

        let me = self.clone();
        tokio::spawn(me.consume(job_id, task.task_id, rx));
        tracing::info!(%job_id, task_id = %task.task_id, "job running");
        Ok(())
    }

    async fn prepare_task(
        &self,
        job_id: Uuid,
        hashlist_id: Uuid,
        attack_mode: i16,
        config: serde_json::Value,
    ) -> anyhow::Result<RunnerTask> {
        let cfg: JobConfig = serde_json::from_value(config)?;
        let hash_type: i32 = sqlx::query_scalar("SELECT hash_type FROM hashlists WHERE id = $1")
            .bind(hashlist_id)
            .fetch_one(&self.state.db)
            .await?;

        // Write the hashlist to a file for hashcat.
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

        // Resolve the primary attack input (wordlist path or mask).
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

        Ok(RunnerTask {
            task_id: Uuid::new_v4(),
            hash_type,
            attack_mode,
            hash_file: hash_file.display().to_string(),
            primary,
            rules,
            keyspace_offset: 0,
            keyspace_len: 0,
            extra_args: cfg.extra_args,
        })
    }

    async fn consume(
        self: Arc<Self>,
        job_id: Uuid,
        task_id: Uuid,
        mut rx: mpsc::Receiver<flamejob_core::StatusUpdate>,
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
            if let Some(eta) = u.eta {
                let _ = sqlx::query("UPDATE jobs SET est_completion = $1 WHERE id = $2")
                    .bind(eta)
                    .bind(job_id)
                    .execute(&self.state.db)
                    .await;
            }
            last = u.state;
        }
        self.finalize(job_id, task_id, last).await;
        self.running.lock().await.remove(&job_id);
    }

    async fn finalize(&self, job_id: Uuid, task_id: Uuid, last: TaskState) {
        let cur: String = sqlx::query_scalar("SELECT state::text FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&self.state.db)
            .await
            .unwrap_or_else(|_| "error".into());

        match cur.as_str() {
            "cancelled" => {
                let _ = self.set_task(task_id, "failed").await;
            }
            "paused" => {
                let _ = self.set_task(task_id, "paused").await;
            }
            _ => {
                if last == TaskState::Done {
                    let _ = self.import_cracked(job_id, task_id).await;
                    let counts: (i32, i32) = sqlx::query_as(
                        "SELECT h.total, h.cracked FROM hashlists h \
                         JOIN jobs j ON j.hashlist_id = h.id WHERE j.id = $1",
                    )
                    .bind(job_id)
                    .fetch_one(&self.state.db)
                    .await
                    .unwrap_or((0, 0));
                    let final_state = if counts.0 > 0 && counts.1 >= counts.0 {
                        "completed"
                    } else {
                        "exhausted"
                    };
                    let _ = self.set_task(task_id, "done").await;
                    let _ = sqlx::query(
                        "UPDATE jobs SET state = $2::job_state, finished_at = now() WHERE id = $1",
                    )
                    .bind(job_id)
                    .bind(final_state)
                    .execute(&self.state.db)
                    .await;
                    self.retries.lock().await.remove(&job_id);
                } else {
                    // Process ended without a terminal status => failure; retry.
                    let attempts = {
                        let mut m = self.retries.lock().await;
                        let e = m.entry(job_id).or_insert(0);
                        *e += 1;
                        *e
                    };
                    let _ = self.set_task(task_id, "failed").await;
                    if attempts <= self.max_retries {
                        let _ = sqlx::query("UPDATE jobs SET state = 'queued' WHERE id = $1")
                            .bind(job_id)
                            .execute(&self.state.db)
                            .await;
                        tracing::warn!(%job_id, attempts, "job failed; re-queued");
                    } else {
                        let _ = sqlx::query(
                            "UPDATE jobs SET state = 'error', error = 'runner failed after retries', finished_at = now() WHERE id = $1",
                        )
                        .bind(job_id)
                        .execute(&self.state.db)
                        .await;
                        self.retries.lock().await.remove(&job_id);
                    }
                }
            }
        }
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
}

async fn file_path(db: &flamejob_db::Db, id: Uuid) -> anyhow::Result<Option<String>> {
    Ok(sqlx::query_scalar("SELECT path FROM files WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await?)
}
