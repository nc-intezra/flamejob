//! flamejob-agent (`fj-agent`): a GPU worker node. It enrolls with flamejobd
//! (one-time claim token -> CA-signed client cert), connects to the WebSocket
//! task stream, and runs hashcat chunks via the shared flamejob-runner,
//! streaming progress, cracked hashes and device telemetry back.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use flamejob_api::agent::{AgentMetric, AgentMsg, AgentTask, CrackedItem, ServerMsg};
use flamejob_core::{DeviceSpeed, RunHandle, Runner, RunnerTask, TaskState};
use flamejob_runner::LocalRunner;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

mod gpu;

#[derive(Parser, Debug, Clone)]
#[command(name = "fj-agent", about = "flamejob distributed worker agent")]
struct Args {
    /// flamejobd base URL, e.g. http://host:8099
    #[arg(long, env = "FJ_AGENT_SERVER", default_value = "http://127.0.0.1:8099")]
    server: String,
    /// Human-readable agent name.
    #[arg(long, env = "FJ_AGENT_NAME", default_value = "agent")]
    name: String,
    /// One-time enrollment claim token (required on first run).
    #[arg(long, env = "FJ_AGENT_CLAIM_TOKEN")]
    claim_token: Option<String>,
    /// Directory for the agent's cert/key and scratch files.
    #[arg(
        long,
        env = "FJ_AGENT_DATA_DIR",
        default_value = "/var/lib/flamejob-agent"
    )]
    data_dir: PathBuf,
    /// hashcat binary path.
    #[arg(long, env = "FJ_AGENT_HASHCAT", default_value = "/usr/bin/hashcat")]
    hashcat: String,
    /// hashcat workload profile (1-4).
    #[arg(long, env = "FJ_AGENT_WORKLOAD", default_value_t = 3)]
    workload: u8,
    /// Disable NVIDIA GPU telemetry (nvidia-smi). GPU metrics are on by default
    /// when NVIDIA GPUs are detected.
    #[arg(long, env = "FJ_AGENT_NO_GPU_METRICS")]
    no_gpu_metrics: bool,
    /// Actively manage NVIDIA fan speed under load via nvidia-settings — disables
    /// the driver's auto fan control while a job runs and runs a closed-loop
    /// controller that holds the core at `--fan-target` (needs an X display and
    /// `Coolbits` enabled). Off by default.
    #[arg(long, env = "FJ_AGENT_FAN_CONTROL")]
    fan_control: bool,
    /// Core temperature (°C) the fan controller holds under load.
    #[arg(long, env = "FJ_AGENT_FAN_TARGET", default_value_t = 75)]
    fan_target: i32,
    /// Minimum fan speed (%) the controller will command.
    #[arg(long, env = "FJ_AGENT_FAN_MIN", default_value_t = 30)]
    fan_min: i32,
    /// Maximum fan speed (%) the controller will command.
    #[arg(long, env = "FJ_AGENT_FAN_MAX", default_value_t = 100)]
    fan_max: i32,
    /// Overheat trip (°C): at/above this the task is stopped and the agent is
    /// flagged. Defaults to just below each GPU's rated slowdown temperature.
    #[arg(long, env = "FJ_AGENT_FAN_CRITICAL")]
    fan_critical: Option<i32>,
    /// Dead band (°C) around the target within which the fan is left unchanged.
    #[arg(long, env = "FJ_AGENT_FAN_DEADBAND", default_value_t = gpu::FAN_DEADBAND_DEFAULT)]
    fan_deadband: i32,
    /// Maximum fan-speed decrease (%) per controller tick (ramps down gently).
    #[arg(long, env = "FJ_AGENT_FAN_DOWN_STEP", default_value_t = gpu::FAN_DOWN_STEP_DEFAULT)]
    fan_down_step: i32,
    /// Memory-junction target (°C) for VRAM-aware control. Unset disables it;
    /// currently inert (no GeForce memory-temp sensor is wired in yet).
    #[arg(long, env = "FJ_AGENT_FAN_MEM_TARGET")]
    fan_mem_target: Option<i32>,
    /// Command prefix to run `nvidia-settings` through, e.g. "sudo -n", so an
    /// unprivileged agent can drive fans on a root-owned X server. Empty (default)
    /// runs it directly — which only works when the agent runs as root or as the
    /// X server's own user.
    #[arg(long, env = "FJ_AGENT_FAN_HELPER")]
    fan_helper: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("FJ_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    ensure_data_dir(&args.data_dir)?;

    let pki_dir = args.data_dir.join("pki");
    let cert_path = pki_dir.join("agent.pem");
    let key_path = pki_dir.join("agent.key.pem");

    if !cert_path.exists() {
        enroll(&args, &cert_path, &key_path, &pki_dir).await?;
    }
    let cert_pem = std::fs::read_to_string(&cert_path).context("read agent cert")?;

    run(&args, cert_pem).await
}

/// Create the agent's data dir and the subdirs it writes into (`pki`, `jobs`,
/// `cache`), then prove the dir is writable. Fails early with a clear, actionable
/// message rather than letting a permission error surface later as a confusing
/// "write hash file" / "create cache file" during a job.
fn ensure_data_dir(dir: &Path) -> Result<()> {
    for sub in ["pki", "jobs", "cache"] {
        let p = dir.join(sub);
        std::fs::create_dir_all(&p).with_context(|| {
            format!(
                "cannot create {} — the data dir is not writable by this user. \
                 Set --data-dir (FJ_AGENT_DATA_DIR) to a writable path, or chown it \
                 to the user running fj-agent, e.g. `sudo chown -R $(id -un) {}`",
                p.display(),
                dir.display()
            )
        })?;
    }
    // Writability probe: create_dir_all succeeds when a dir already exists even
    // if it isn't writable, so confirm we can actually write a file.
    let probe = dir.join(".fj-agent-write-probe");
    std::fs::write(&probe, b"ok").with_context(|| {
        format!(
            "{} exists but is not writable by this user. chown it to the user \
             running fj-agent, e.g. `sudo chown -R $(id -un) {}`",
            dir.display(),
            dir.display()
        )
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Generate a keypair + CSR, POST /agent/enroll, and persist the issued cert.
async fn enroll(args: &Args, cert_path: &Path, key_path: &Path, pki_dir: &Path) -> Result<()> {
    use rcgen::{CertificateParams, DnType, KeyPair};

    let claim = args
        .claim_token
        .clone()
        .context("first run needs --claim-token (or FJ_AGENT_CLAIM_TOKEN)")?;

    let key = KeyPair::generate().context("generate key")?;
    let mut params = CertificateParams::new(vec![args.name.clone()]).context("csr params")?;
    params
        .distinguished_name
        .push(DnType::CommonName, args.name.clone());
    let csr = params.serialize_request(&key).context("serialize csr")?;
    let csr_pem = csr.pem().context("csr pem")?;

    let body = flamejob_api::agent::EnrollRequest {
        claim_token: claim,
        name: args.name.clone(),
        csr_pem,
    };
    let url = format!("{}/agent/enroll", args.server.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("enroll request")?
        .error_for_status()
        .context("enroll rejected")?
        .json::<flamejob_api::agent::EnrollResponse>()
        .await
        .context("enroll response")?;

    std::fs::write(cert_path, &resp.cert_pem).context("write cert")?;
    std::fs::write(key_path, key.serialize_pem()).context("write key")?;
    std::fs::write(pki_dir.join("ca.pem"), &resp.ca_pem).ok();
    tracing::info!(agent_id = %resp.agent_id, "enrolled; certificate saved");
    Ok(())
}

/// Connect the WebSocket task stream and service server messages.
async fn run(args: &Args, cert_pem: String) -> Result<()> {
    let ws_url = {
        let base = args.server.trim_end_matches('/');
        let base = base
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        format!("{base}/agent/stream")
    };
    tracing::info!(%ws_url, "connecting to task stream");
    let (ws, _resp) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .context("ws connect")?;
    let (mut sink, mut stream) = ws.split();

    // Outgoing message pump.
    let (out_tx, mut out_rx) = mpsc::channel::<AgentMsg>(128);
    let writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let txt = serde_json::to_string(&msg).unwrap_or_default();
            if sink.send(Message::Text(txt)).await.is_err() {
                break;
            }
        }
    });

    // Handshake: Hello then advertise one slot.
    out_tx
        .send(AgentMsg::Hello {
            name: args.name.clone(),
            cert_pem: cert_pem.clone(),
        })
        .await?;

    // The agent advertises a single slot and runs one chunk at a time, so its
    // local runner parallelism is 1; the control plane achieves per-job
    // parallelism by fanning chunks across many agents.
    let runner = Arc::new(LocalRunner::new(
        args.hashcat.clone(),
        args.workload,
        args.data_dir.clone(),
        1,
    ));
    let current: Arc<Mutex<Option<(Uuid, RunHandle)>>> = Arc::new(Mutex::new(None));

    // Detect NVIDIA GPUs once; samples ride along with task progress below.
    let gpus: Arc<Vec<gpu::Gpu>> = Arc::new(if args.no_gpu_metrics {
        Vec::new()
    } else {
        gpu::detect().await
    });
    if gpus.is_empty() {
        tracing::info!("no NVIDIA GPUs detected (or nvidia-smi unavailable); CPU metrics only");
    } else {
        tracing::info!(
            count = gpus.len(),
            fan_control = args.fan_control,
            "NVIDIA GPU telemetry enabled"
        );
    }

    // Build the fan-control config once (None = controller disabled).
    let fan_cfg: Option<gpu::FanConfig> = args.fan_control.then(|| gpu::FanConfig {
        target_temp: args.fan_target,
        min_fan: args.fan_min,
        max_fan: args.fan_max,
        critical_override: args.fan_critical,
        deadband: args.fan_deadband,
        down_step: args.fan_down_step,
        mem_target: args.fan_mem_target,
        helper: args
            .fan_helper
            .as_deref()
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default(),
    });

    while let Some(msg) = stream.next().await {
        let msg = match msg {
            Ok(Message::Text(t)) => serde_json::from_str::<ServerMsg>(&t).ok(),
            Ok(Message::Close(_)) => break,
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(error = %e, "ws read error");
                break;
            }
        };
        let Some(msg) = msg else { continue };
        match msg {
            ServerMsg::Welcome { agent_id } => {
                tracing::info!(%agent_id, "welcomed by server");
                out_tx.send(AgentMsg::Ready { slots: 1 }).await.ok();
            }
            ServerMsg::Rejected { reason } => {
                tracing::error!(%reason, "server rejected connection");
                break;
            }
            ServerMsg::Heartbeat => {}
            ServerMsg::ComputeKeyspace { req_id, task } => {
                let runner = runner.clone();
                let out_tx = out_tx.clone();
                let data_dir = args.data_dir.clone();
                let server = args.server.clone();
                let cert = cert_pem.clone();
                tokio::spawn(async move {
                    let value = compute_keyspace(&runner, &server, &cert, &task, &data_dir).await;
                    out_tx.send(AgentMsg::Keyspace { req_id, value }).await.ok();
                });
            }
            ServerMsg::Assign { task } => {
                let runner = runner.clone();
                let out_tx = out_tx.clone();
                let data_dir = args.data_dir.clone();
                let current = current.clone();
                let server = args.server.clone();
                let cert = cert_pem.clone();
                let gpus = gpus.clone();
                let fan_cfg = fan_cfg.clone();
                tokio::spawn(async move {
                    run_task(
                        runner, server, cert, task, out_tx, data_dir, current, gpus, fan_cfg,
                    )
                    .await;
                });
            }
            ServerMsg::Cancel { task_id } => {
                let cur = current.lock().await;
                if let Some((id, handle)) = cur.as_ref() {
                    if *id == task_id {
                        let _ = runner.cancel(handle).await;
                        tracing::info!(%task_id, "cancelled task");
                    }
                }
            }
        }
    }

    writer.abort();
    tracing::info!("task stream closed");
    Ok(())
}

async fn compute_keyspace(
    runner: &LocalRunner,
    server: &str,
    cert_pem: &str,
    task: &AgentTask,
    data_dir: &Path,
) -> u64 {
    let (primary, rules) = match resolve_task(server, cert_pem, data_dir, task).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "keyspace file fetch failed");
            return 0;
        }
    };
    let rt = runner_task(task, data_dir, primary, rules);
    runner.keyspace(&rt).await.unwrap_or(0)
}

/// Ensure a wordlist/rule file is present locally, downloading it from the
/// control plane (`GET /agent/files/{id}`) into `{data_dir}/cache/{id}` if not
/// already cached. Returns the local path.
async fn ensure_file(server: &str, cert_pem: &str, data_dir: &Path, id: Uuid) -> Result<PathBuf> {
    use tokio::io::AsyncWriteExt;
    let cache = data_dir.join("cache");
    tokio::fs::create_dir_all(&cache).await.ok();
    let dest = cache.join(id.to_string());
    if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
        return Ok(dest);
    }
    let url = format!("{}/agent/files/{}", server.trim_end_matches('/'), id);
    let resp = reqwest::Client::new()
        .get(&url)
        .header("x-agent-cert", hex::encode(cert_pem.as_bytes()))
        .send()
        .await
        .context("download file")?
        .error_for_status()
        .context("download file status")?;
    let tmp = cache.join(format!("{id}.part"));
    let mut out = tokio::fs::File::create(&tmp)
        .await
        .context("create cache file")?;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read download chunk")?;
        out.write_all(&chunk).await.context("write cache file")?;
    }
    out.flush().await.ok();
    tokio::fs::rename(&tmp, &dest)
        .await
        .context("finalize cache file")?;
    Ok(dest)
}

/// Resolve a task's primary input (mask inline, or a fetched wordlist path) and
/// its rule file paths, downloading any referenced files.
async fn resolve_task(
    server: &str,
    cert_pem: &str,
    data_dir: &Path,
    task: &AgentTask,
) -> Result<(String, Vec<String>)> {
    let primary = if let Some(mask) = &task.mask {
        mask.clone()
    } else if let Some(wid) = task.wordlist {
        ensure_file(server, cert_pem, data_dir, wid)
            .await?
            .display()
            .to_string()
    } else {
        anyhow::bail!("task has neither wordlist nor mask");
    };
    let mut rules = Vec::new();
    for rid in &task.rules {
        rules.push(
            ensure_file(server, cert_pem, data_dir, *rid)
                .await?
                .display()
                .to_string(),
        );
    }
    Ok((primary, rules))
}

#[allow(clippy::too_many_arguments)]
async fn run_task(
    runner: Arc<LocalRunner>,
    server: String,
    cert_pem: String,
    task: AgentTask,
    out_tx: mpsc::Sender<AgentMsg>,
    data_dir: PathBuf,
    current: Arc<Mutex<Option<(Uuid, RunHandle)>>>,
    gpus: Arc<Vec<gpu::Gpu>>,
    fan_cfg: Option<gpu::FanConfig>,
) {
    let task_id = task.task_id;
    // Materialize the hash lines the server shipped inline.
    let hash_file = data_dir.join("jobs").join(format!("{task_id}.hashes"));
    if let Some(parent) = hash_file.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    if let Err(e) = tokio::fs::write(&hash_file, task.hashes.join("\n")).await {
        out_tx
            .send(AgentMsg::Error {
                task_id: Some(task_id),
                message: format!("write hash file: {e}"),
            })
            .await
            .ok();
        return;
    }

    let (primary, rules) = match resolve_task(&server, &cert_pem, &data_dir, &task).await {
        Ok(v) => v,
        Err(e) => {
            out_tx
                .send(AgentMsg::Error {
                    task_id: Some(task_id),
                    message: format!("fetch files: {e}"),
                })
                .await
                .ok();
            return;
        }
    };
    let rt = runner_task(&task, &data_dir, primary, rules);
    let (tx, mut rx) = mpsc::channel(64);
    let handle = match runner.start(&rt, tx).await {
        Ok(h) => h,
        Err(e) => {
            out_tx
                .send(AgentMsg::Error {
                    task_id: Some(task_id),
                    message: format!("start: {e}"),
                })
                .await
                .ok();
            return;
        }
    };
    *current.lock().await = Some((task_id, handle));

    let mut sys = sysinfo::System::new();
    let mut last = TaskState::Running;
    // Per-GPU fan-controller state, persisted across ticks for this task.
    let mut fan_states: std::collections::HashMap<u32, gpu::FanState> =
        std::collections::HashMap::new();
    let mut overheated = false;
    while let Some(u) = rx.recv().await {
        out_tx
            .send(AgentMsg::Progress {
                task_id,
                progress: u.progress,
                speed: u.speed,
                recovered: u.recovered,
                state: state_str(u.state).into(),
            })
            .await
            .ok();
        // Opportunistic host + GPU telemetry alongside progress. hashcat reports
        // a per-device speed breakdown; attribute each to its GPU row so the
        // hashrate shows next to the card doing the work, not on the CPU row.
        let mut gpu_samples = gpu::sample(&gpus).await;
        let cpu_hashrate = assign_gpu_hashrates(&mut gpu_samples, &u.device_speeds, u.speed);
        if let Some(cfg) = &fan_cfg {
            if !gpu_samples.is_empty() {
                if let Some(reason) =
                    gpu::drive_fans(&gpus, &gpu_samples, cfg, &mut fan_states).await
                {
                    // Overheat: stop the run so the card can cool. The server marks
                    // the agent on Error and the scheduler requeues the chunk.
                    tracing::warn!(%reason, "overheat protection tripped; stopping task");
                    out_tx
                        .send(AgentMsg::Error {
                            task_id: Some(task_id),
                            message: format!("overheat protection: {reason}; task stopped"),
                        })
                        .await
                        .ok();
                    if let Some((_, handle)) = current.lock().await.as_ref() {
                        let _ = runner.cancel(handle).await;
                    }
                    last = TaskState::Failed;
                    overheated = true;
                }
            }
        }
        let mut samples = vec![host_metric(&mut sys, cpu_hashrate)];
        samples.extend(gpu_samples);
        out_tx.send(AgentMsg::Metrics { samples }).await.ok();
        if overheated {
            break; // keep last = Failed set above
        }
        last = u.state;
    }
    // Load is off; hand the fans back to the driver's automatic control.
    if let Some(cfg) = &fan_cfg {
        if !gpus.is_empty() {
            gpu::reset_fans(&gpus, cfg).await;
        }
    }

    // Ship any cracked results hashcat wrote to the outfile.
    let outfile = LocalRunner::outfile_path(&data_dir, task_id);
    if let Ok(content) = tokio::fs::read_to_string(&outfile).await {
        let items: Vec<CrackedItem> = content
            .lines()
            .filter_map(|l| l.trim().rsplit_once(':'))
            .map(|(hash, plain)| CrackedItem {
                hash: hash.to_string(),
                plain: plain.to_string(),
            })
            .collect();
        if !items.is_empty() {
            out_tx.send(AgentMsg::Cracked { task_id, items }).await.ok();
        }
    }

    *current.lock().await = None;
    out_tx
        .send(AgentMsg::TaskDone {
            task_id,
            state: state_str(last).into(),
        })
        .await
        .ok();
}

fn runner_task(
    task: &AgentTask,
    data_dir: &Path,
    primary: String,
    rules: Vec<String>,
) -> RunnerTask {
    let hash_file = data_dir
        .join("jobs")
        .join(format!("{}.hashes", task.task_id));
    RunnerTask {
        task_id: task.task_id,
        hash_type: task.hash_type,
        attack_mode: task.attack_mode,
        hash_file: hash_file.display().to_string(),
        primary,
        rules,
        keyspace_offset: task.keyspace_offset,
        keyspace_len: task.keyspace_len,
        extra_args: task.extra_args.clone(),
    }
}

/// Attribute hashcat's per-device speeds to the GPU metric rows (matched by
/// device order), returning the hashrate the host/CPU row should carry.
///
/// hashcat enumerates compute devices as ids 1..N; detected NVIDIA GPUs are
/// ordered by index 0..N-1, so we zip them positionally. Speeds past the GPU
/// count (e.g. a CPU OpenCL device) fall onto the host row, and when no GPUs
/// were detected the whole total stays on the host row (CPU-only agents).
fn assign_gpu_hashrates(
    gpus: &mut [AgentMetric],
    device_speeds: &[DeviceSpeed],
    total: i64,
) -> i64 {
    if gpus.is_empty() {
        return total;
    }
    if device_speeds.is_empty() {
        // No per-device breakdown: a lone GPU must own the total; with several
        // we can't attribute it, so leave it on the host row rather than guess.
        if let [only] = gpus {
            only.hashrate = total;
            return 0;
        }
        return total;
    }
    let mut speeds: Vec<&DeviceSpeed> = device_speeds.iter().collect();
    speeds.sort_by_key(|d| d.device_id);
    for (g, s) in gpus.iter_mut().zip(speeds.iter()) {
        g.hashrate = s.speed;
    }
    speeds.iter().skip(gpus.len()).map(|d| d.speed).sum()
}

fn host_metric(sys: &mut sysinfo::System, hashrate: i64) -> AgentMetric {
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    AgentMetric {
        name: "CPU".into(),
        kind: "cpu".into(),
        temp: 0,
        util: sys.global_cpu_usage() as i32,
        mem_used: (sys.used_memory() / 1_048_576) as i64,
        mem_total: (sys.total_memory() / 1_048_576) as i64,
        pstate: "—".into(),
        power_w: 0,
        fan: 0,
        clock_mhz: 0,
        mem_clock_mhz: 0,
        hashrate,
    }
}

fn state_str(s: TaskState) -> &'static str {
    match s {
        TaskState::Pending => "pending",
        TaskState::Running => "running",
        TaskState::Paused => "paused",
        TaskState::Done => "done",
        TaskState::Failed => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpu_row(name: &str) -> AgentMetric {
        AgentMetric {
            name: name.into(),
            kind: "gpu".into(),
            temp: 0,
            util: 0,
            mem_used: 0,
            mem_total: 0,
            pstate: String::new(),
            power_w: 0,
            fan: 0,
            clock_mhz: 0,
            mem_clock_mhz: 0,
            hashrate: 0,
        }
    }

    #[test]
    fn attributes_each_device_speed_to_its_gpu() {
        let mut gpus = vec![gpu_row("a[0]"), gpu_row("b[1]")];
        // Deliberately out of order to check sort-by-device_id.
        let speeds = vec![
            DeviceSpeed {
                device_id: 2,
                speed: 800,
            },
            DeviceSpeed {
                device_id: 1,
                speed: 1200,
            },
        ];
        let cpu = assign_gpu_hashrates(&mut gpus, &speeds, 2000);
        assert_eq!(gpus[0].hashrate, 1200);
        assert_eq!(gpus[1].hashrate, 800);
        assert_eq!(cpu, 0, "no spare devices -> nothing on the host row");
    }

    #[test]
    fn extra_compute_device_falls_onto_host() {
        let mut gpus = vec![gpu_row("a[0]")];
        let speeds = vec![
            DeviceSpeed {
                device_id: 1,
                speed: 1000,
            },
            DeviceSpeed {
                device_id: 2,
                speed: 50,
            }, // e.g. a CPU OpenCL device
        ];
        let cpu = assign_gpu_hashrates(&mut gpus, &speeds, 1050);
        assert_eq!(gpus[0].hashrate, 1000);
        assert_eq!(cpu, 50);
    }

    #[test]
    fn cpu_only_agent_keeps_total_on_host() {
        let mut none: Vec<AgentMetric> = Vec::new();
        assert_eq!(assign_gpu_hashrates(&mut none, &[], 500), 500);
    }

    #[test]
    fn single_gpu_without_breakdown_owns_total() {
        let mut gpus = vec![gpu_row("a[0]")];
        let cpu = assign_gpu_hashrates(&mut gpus, &[], 1234);
        assert_eq!(gpus[0].hashrate, 1234);
        assert_eq!(cpu, 0);
    }
}
