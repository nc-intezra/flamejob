//! flamejob-runner: drives the hashcat binary as a subprocess and parses its
//! `--status-json` output into StatusUpdate samples.
use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use flamejob_core::{Result, RunHandle, Runner, RunnerTask, StatusSink, StatusUpdate, TaskState};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Filesystem locations the runner needs; derived from the server data_dir.
#[derive(Debug, Clone)]
pub struct RunnerPaths {
    pub potfile: PathBuf,
    pub outfile: PathBuf,
    pub restore: PathBuf,
}

pub struct LocalRunner {
    pub hashcat_bin: String,
    pub workload: u8,
    pub paths: RunnerPaths,
}

impl LocalRunner {
    pub fn new(hashcat_bin: impl Into<String>, workload: u8, paths: RunnerPaths) -> Self {
        Self {
            hashcat_bin: hashcat_bin.into(),
            workload,
            paths,
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
    speed: i64,
}

fn status_to_task_state(code: i32) -> TaskState {
    // hashcat status codes: 3=Running, 5=Exhausted, 6=Cracked, others treated as running
    match code {
        5 => TaskState::Done,
        6 => TaskState::Done,
        _ => TaskState::Running,
    }
}

fn parse_status(line: &str, task_id: uuid::Uuid) -> Option<StatusUpdate> {
    let s: HcStatus = serde_json::from_str(line).ok()?;
    let progress = s
        .progress
        .filter(|p| p[1] > 0)
        .map(|p| p[0] as f64 / p[1] as f64)
        .unwrap_or(0.0);
    let speed = s
        .devices
        .map(|d| d.iter().map(|x| x.speed).sum())
        .unwrap_or(0);
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
        let session = task.task_id.to_string();
        let mut args = vec![format!("-w{}", self.workload)];
        args.extend(build_args(task, &self.paths, &session));
        let mut child = Command::new(&self.hashcat_bin)
            .args(&args)
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| flamejob_core::Error::Runner(e.to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| flamejob_core::Error::Runner("no stdout".into()))?;
        let task_id = task.task_id;
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(update) = parse_status(&line, task_id) {
                    let _ = tx.send(update).await;
                }
            }
            let _ = child.wait().await;
        });
        Ok(RunHandle { task_id })
    }

    async fn pause(&self, _handle: &RunHandle) -> Result<()> {
        // Phase 1: checkpoint via --restore is handled by cancel+relaunch.
        Ok(())
    }

    async fn resume(&self, _handle: &RunHandle) -> Result<()> {
        Ok(())
    }

    async fn cancel(&self, _handle: &RunHandle) -> Result<()> {
        Ok(())
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
}
