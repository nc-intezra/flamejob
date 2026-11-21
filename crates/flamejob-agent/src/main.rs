//! flamejob-agent (`fj-agent`): a GPU worker node. It enrolls with flamejobd
//! (one-time claim token -> CA-signed client cert), connects to the WebSocket
//! task stream, and runs hashcat chunks via the shared flamejob-runner,
//! streaming progress, cracked hashes and device telemetry back.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use flamejob_api::agent::{AgentMetric, AgentMsg, AgentTask, CrackedItem, ServerMsg};
use flamejob_core::{RunHandle, Runner, RunnerTask, TaskState};
use flamejob_runner::LocalRunner;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

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
    std::fs::create_dir_all(&args.data_dir).ok();

    let pki_dir = args.data_dir.join("pki");
    std::fs::create_dir_all(&pki_dir).ok();
    let cert_path = pki_dir.join("agent.pem");
    let key_path = pki_dir.join("agent.key.pem");

    if !cert_path.exists() {
        enroll(&args, &cert_path, &key_path, &pki_dir).await?;
    }
    let cert_pem = std::fs::read_to_string(&cert_path).context("read agent cert")?;

    run(&args, cert_pem).await
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

    let runner = Arc::new(LocalRunner::new(
        args.hashcat.clone(),
        args.workload,
        args.data_dir.clone(),
    ));
    let current: Arc<Mutex<Option<(Uuid, RunHandle)>>> = Arc::new(Mutex::new(None));

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
                tokio::spawn(async move {
                    run_task(runner, server, cert, task, out_tx, data_dir, current).await;
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

async fn run_task(
    runner: Arc<LocalRunner>,
    server: String,
    cert_pem: String,
    task: AgentTask,
    out_tx: mpsc::Sender<AgentMsg>,
    data_dir: PathBuf,
    current: Arc<Mutex<Option<(Uuid, RunHandle)>>>,
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
        // Opportunistic host telemetry alongside progress.
        out_tx
            .send(AgentMsg::Metrics {
                samples: vec![host_metric(&mut sys, u.speed)],
            })
            .await
            .ok();
        last = u.state;
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
