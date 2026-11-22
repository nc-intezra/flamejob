//! flamejob-runner: drives the hashcat binary as a subprocess and parses its
//! `--status-json` output into StatusUpdate samples. The LocalRunner keeps a
//! registry of live child processes so a task can be cancelled.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use flamejob_core::{
    DeviceSpeed, Result, RunHandle, Runner, RunnerTask, StatusSink, StatusUpdate, TaskState,
};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Filesystem locations for a single task run.
#[derive(Debug, Clone)]
pub struct RunnerPaths {
    pub potfile: PathBuf,
    pub outfile: PathBuf,
    pub restore: PathBuf,
}

pub struct LocalRunner {
    hashcat_bin: String,
    workload: u8,
    data_dir: PathBuf,
    /// How many hashcat subprocesses this box will run at once. Each chunk owns
    /// its own `--session`, outfile and restore file, so concurrent runs are
    /// independent; this bounds contention on the local GPUs.
    parallelism: usize,
    children: Arc<Mutex<HashMap<Uuid, Child>>>,
}

impl LocalRunner {
    pub fn new(
        hashcat_bin: impl Into<String>,
        workload: u8,
        data_dir: impl Into<PathBuf>,
        parallelism: usize,
    ) -> Self {
        Self {
            hashcat_bin: hashcat_bin.into(),
            workload,
            data_dir: data_dir.into(),
            parallelism: parallelism.max(1),
            children: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Where a task's cracked results are written (read back by the scheduler).
    pub fn outfile_path(data_dir: &Path, task_id: Uuid) -> PathBuf {
        data_dir.join("jobs").join(format!("{task_id}.cracked"))
    }

    fn paths_for(&self, task_id: Uuid) -> RunnerPaths {
        RunnerPaths {
            potfile: self.data_dir.join("flamejob.pot"),
            outfile: Self::outfile_path(&self.data_dir, task_id),
            restore: self
                .data_dir
                .join("restore")
                .join(format!("{task_id}.restore")),
        }
    }
}

/// Build the hashcat argument vector for a task. Pure and unit-testable.
pub fn build_args(task: &RunnerTask, paths: &RunnerPaths, session: &str) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-m".into(),
        task.hash_type.to_string(),
        "-a".into(),
        task.attack_mode.to_string(),
        task.hash_file.clone(),
        task.primary.clone(),
    ];
    for r in &task.rules {
        args.push("-r".into());
        args.push(r.clone());
    }
    args.extend([
        format!("--session={session}"),
        "--status".into(),
        "--status-json".into(),
        "--status-timer=5".into(),
        format!("--potfile-path={}", paths.potfile.display()),
        format!("--outfile={}", paths.outfile.display()),
        "--outfile-format=1,2".into(),
        format!("--restore-file-path={}", paths.restore.display()),
    ]);
    if task.keyspace_len > 0 {
        args.push(format!("--skip={}", task.keyspace_offset));
        args.push(format!("--limit={}", task.keyspace_len));
    }
    args.push("--quiet".into());
    args.extend(task.extra_args.iter().cloned());
    args
}

#[derive(Debug, Deserialize)]
struct HcStatus {
    status: i32,
    progress: Option<[i64; 2]>,
    recovered_hashes: Option<[i64; 2]>,
    devices: Option<Vec<HcDevice>>,
    estimated_stop: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct HcDevice {
    #[serde(default)]
    device_id: i64,
    #[serde(default)]
    speed: i64,
}

/// hashcat status codes: 5 = Exhausted, 6 = Cracked -> Done; others -> Running.
fn status_to_task_state(code: i32) -> TaskState {
    match code {
        5 | 6 => TaskState::Done,
        _ => TaskState::Running,
    }
}

fn parse_status(line: &str, task_id: Uuid) -> Option<StatusUpdate> {
    let s: HcStatus = serde_json::from_str(line).ok()?;
    let progress = s
        .progress
        .filter(|p| p[1] > 0)
        .map(|p| p[0] as f64 / p[1] as f64)
        .unwrap_or(0.0);
    let device_speeds: Vec<DeviceSpeed> = s
        .devices
        .unwrap_or_default()
        .into_iter()
        .map(|d| DeviceSpeed {
            device_id: d.device_id,
            speed: d.speed,
        })
        .collect();
    let speed = device_speeds.iter().map(|d| d.speed).sum();
    let recovered = s.recovered_hashes.map(|r| r[0]).unwrap_or(0);
    let eta = s
        .estimated_stop
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));
    Some(StatusUpdate {
        task_id,
        progress,
        speed,
        recovered,
        eta,
        state: status_to_task_state(s.status),
        device_speeds,
    })
}

#[async_trait]
impl Runner for LocalRunner {
    async fn keyspace(&self, task: &RunnerTask) -> Result<u64> {
        let output = Command::new(&self.hashcat_bin)
            .args([
                "--keyspace",
                "-m",
                &task.hash_type.to_string(),
                "-a",
                &task.attack_mode.to_string(),
                &task.primary,
            ])
            .output()
            .await
            .map_err(|e| flamejob_core::Error::Runner(e.to_string()))?;
        let s = String::from_utf8_lossy(&output.stdout);
        s.trim()
            .parse::<u64>()
            .map_err(|e| flamejob_core::Error::Runner(e.to_string()))
    }

    async fn start(&self, task: &RunnerTask, tx: StatusSink) -> Result<RunHandle> {
        let paths = self.paths_for(task.task_id);
        // ensure output directories exist
        for dir in [paths.outfile.parent(), paths.restore.parent()]
            .into_iter()
            .flatten()
        {
            let _ = tokio::fs::create_dir_all(dir).await;
        }
        let session = task.task_id.to_string();
        let mut args = vec![format!("-w{}", self.workload)];
        args.extend(build_args(task, &paths, &session));

        let mut child = Command::new(&self.hashcat_bin)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| flamejob_core::Error::Runner(e.to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| flamejob_core::Error::Runner("no stdout".into()))?;
        let task_id = task.task_id;
        self.children.lock().await.insert(task_id, child);

        let children = self.children.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(update) = parse_status(&line, task_id) {
                    let _ = tx.send(update).await;
                }
            }
            // stdout closed => process finished; reap it.
            if let Some(mut child) = children.lock().await.remove(&task_id) {
                let _ = child.wait().await;
            }
        });
        Ok(RunHandle { task_id })
    }

    async fn pause(&self, handle: &RunHandle) -> Result<()> {
        // Phase 1: pause == stop the process (a checkpoint restore file is left
        // behind). Resume re-queues the job.
        self.cancel(handle).await
    }

    async fn resume(&self, _handle: &RunHandle) -> Result<()> {
        Ok(())
    }

    async fn cancel(&self, handle: &RunHandle) -> Result<()> {
        if let Some(mut child) = self.children.lock().await.remove(&handle.task_id) {
            let _ = child.kill().await;
        }
        Ok(())
    }

    async fn capacity(&self) -> usize {
        self.parallelism
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_include_core_flags() {
        let task = RunnerTask {
            task_id: uuid::Uuid::nil(),
            hash_type: 1000,
            attack_mode: 0,
            hash_file: "/tmp/hashes".into(),
            primary: "/tmp/rockyou.txt".into(),
            rules: vec!["/tmp/best64.rule".into()],
            keyspace_offset: 0,
            keyspace_len: 0,
            extra_args: vec![],
        };
        let paths = RunnerPaths {
            potfile: "/var/lib/flamejob/flamejob.pot".into(),
            outfile: "/var/lib/flamejob/out".into(),
            restore: "/var/lib/flamejob/restore".into(),
        };
        let args = build_args(&task, &paths, "sess");
        assert!(args.contains(&"--status-json".to_string()));
        assert!(args.contains(&"-m".to_string()));
        assert!(args.iter().any(|a| a == "/tmp/best64.rule"));
    }

    #[test]
    fn parses_running_status() {
        let line = r#"{"status":3,"progress":[50,100],"recovered_hashes":[2,10],"devices":[{"device_id":1,"speed":1000}],"estimated_stop":1700000000}"#;
        let u = parse_status(line, uuid::Uuid::nil()).unwrap();
        assert!((u.progress - 0.5).abs() < 1e-9);
        assert_eq!(u.speed, 1000);
        assert_eq!(u.recovered, 2);
        assert_eq!(u.state, TaskState::Running);
        assert_eq!(u.device_speeds.len(), 1);
        assert_eq!(u.device_speeds[0].device_id, 1);
        assert_eq!(u.device_speeds[0].speed, 1000);
    }

    #[test]
    fn keeps_per_device_speeds_and_sums_total() {
        // Two GPUs: the aggregate speed is the sum, and each device is retained
        // so the agent can attribute a hashrate to each card.
        let line = r#"{"status":3,"progress":[25,100],"devices":[{"device_id":1,"speed":1200},{"device_id":2,"speed":800}]}"#;
        let u = parse_status(line, uuid::Uuid::nil()).unwrap();
        assert_eq!(u.speed, 2000);
        assert_eq!(u.device_speeds.len(), 2);
        assert_eq!(u.device_speeds[1].device_id, 2);
        assert_eq!(u.device_speeds[1].speed, 800);
    }
}
