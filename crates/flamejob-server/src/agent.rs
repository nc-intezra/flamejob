//! Phase 3 distributed-agent plane: enrollment (CA-signed client certs), the
//! WebSocket task protocol (`WS /agent/stream`), the in-memory agent hub that
//! tracks connected workers and dispatches chunk tasks, and a `RemoteRunner`
//! that implements the flamejob-core `Runner` trait so the existing scheduler
//! can ship chunks to agents instead of running them locally.
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use tokio_util::io::ReaderStream;
use flamejob_api::agent::{
    AgentClaim, AgentClaimCreate, AgentInfo, AgentMetric, AgentMsg, AgentTask, EnrollRequest,
    EnrollResponse, ServerMsg,
};
use flamejob_api::DeviceView;
use flamejob_core::{
    Capability, Result as CoreResult, RunHandle, Runner, RunnerTask, StatusSink, StatusUpdate,
    TaskState,
};
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use tokio::sync::{mpsc, oneshot, Mutex};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::pki;
use crate::state::AppState;

// ======================= agent hub =======================

/// Tracks connected agents and routes chunk tasks + status back to the
/// scheduler's per-chunk status channel.
#[derive(Default)]
pub struct AgentHub {
    inner: Mutex<HubInner>,
}

#[derive(Default)]
struct HubInner {
    conns: HashMap<Uuid, Conn>,
    /// task_id -> status channel the scheduler is consuming for that chunk.
    sinks: HashMap<Uuid, StatusSink>,
    /// task_id -> agent currently running it.
    assigned: HashMap<Uuid, Uuid>,
    /// Chunk tasks waiting for a free agent slot.
    queue: VecDeque<AgentTask>,
    /// Outstanding keyspace probes.
    ks_waiters: HashMap<Uuid, oneshot::Sender<u64>>,
}

struct Conn {
    #[allow(dead_code)]
    name: String,
    tx: mpsc::Sender<ServerMsg>,
    slots: u32,
}

impl AgentHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    async fn register(&self, agent_id: Uuid, name: String, tx: mpsc::Sender<ServerMsg>) {
        self.inner
            .lock()
            .await
            .conns
            .insert(agent_id, Conn { name, tx, slots: 0 });
    }

    /// Mark an agent gone; fail its in-flight tasks so the scheduler retries.
    async fn disconnect(&self, agent_id: Uuid) {
        let mut g = self.inner.lock().await;
        g.conns.remove(&agent_id);
        let orphaned: Vec<Uuid> = g
            .assigned
            .iter()
            .filter(|(_, a)| **a == agent_id)
            .map(|(t, _)| *t)
            .collect();
        for task_id in orphaned {
            g.assigned.remove(&task_id);
            if let Some(sink) = g.sinks.remove(&task_id) {
                let _ = sink.try_send(StatusUpdate {
                    task_id,
                    progress: 0.0,
                    speed: 0,
                    recovered: 0,
                    eta: None,
                    state: TaskState::Failed,
                });
            }
        }
    }

    /// Update an agent's free slots and dispatch any queued work.
    async fn set_ready(&self, agent_id: Uuid, slots: u32) {
        let mut g = self.inner.lock().await;
        if let Some(c) = g.conns.get_mut(&agent_id) {
            c.slots = slots;
        }
        Self::drain(&mut g);
    }

    /// Queue (and if possible immediately assign) a chunk task.
    async fn dispatch(&self, task: AgentTask, sink: StatusSink) {
        let mut g = self.inner.lock().await;
        g.sinks.insert(task.task_id, sink);
        g.queue.push_back(task);
        Self::drain(&mut g);
    }

    /// Assign as many queued tasks as there are free agent slots.
    fn drain(g: &mut HubInner) {
        while let Some(task) = g.queue.front().cloned() {
            let Some((&agent_id, _)) = g.conns.iter().find(|(_, c)| c.slots > 0) else {
                break;
            };
            g.queue.pop_front();
            if let Some(c) = g.conns.get_mut(&agent_id) {
                c.slots = c.slots.saturating_sub(1);
                if c.tx
                    .try_send(ServerMsg::Assign { task: task.clone() })
                    .is_ok()
                {
                    g.assigned.insert(task.task_id, agent_id);
                } else {
                    // send failed: put it back and stop.
                    g.queue.push_front(task);
                    break;
                }
            }
        }
    }

    /// Clone the status sink for a task so the caller can forward an update
    /// without holding the hub lock across the await.
    async fn sink_for(&self, task_id: Uuid) -> Option<StatusSink> {
        self.inner.lock().await.sinks.get(&task_id).cloned()
    }

    /// Finish a task: drop its sink (ends the scheduler's consume loop) and
    /// free the agent slot, then dispatch anything queued.
    async fn finish_task(&self, task_id: Uuid) {
        let mut g = self.inner.lock().await;
        g.sinks.remove(&task_id);
        if let Some(agent_id) = g.assigned.remove(&task_id) {
            if let Some(c) = g.conns.get_mut(&agent_id) {
                c.slots += 1;
            }
        }
        Self::drain(&mut g);
    }

    async fn cancel_task(&self, task_id: Uuid) {
        let g = self.inner.lock().await;
        if let Some(agent_id) = g.assigned.get(&task_id) {
            if let Some(c) = g.conns.get(agent_id) {
                let _ = c.tx.try_send(ServerMsg::Cancel { task_id });
            }
        }
    }

    /// Ask any ready agent to compute a keyspace. None if no agent is free.
    async fn keyspace_probe(&self, task: AgentTask) -> Option<oneshot::Receiver<u64>> {
        let mut g = self.inner.lock().await;
        let (&agent_id, _) = g.conns.iter().find(|(_, c)| c.slots > 0)?;
        let tx = g.conns.get(&agent_id)?.tx.clone();
        let req_id = Uuid::new_v4();
        let (otx, orx) = oneshot::channel();
        if tx
            .try_send(ServerMsg::ComputeKeyspace { req_id, task })
            .is_err()
        {
            return None;
        }
        g.ks_waiters.insert(req_id, otx);
        Some(orx)
    }

    async fn fulfill_keyspace(&self, req_id: Uuid, value: u64) {
        if let Some(tx) = self.inner.lock().await.ks_waiters.remove(&req_id) {
            let _ = tx.send(value);
        }
    }

    pub async fn connected_count(&self) -> usize {
        self.inner.lock().await.conns.len()
    }
}

// ======================= remote runner =======================

pub struct RemoteRunner {
    hub: Arc<AgentHub>,
    keyspace_timeout: Duration,
}

impl RemoteRunner {
    pub fn new(hub: Arc<AgentHub>) -> Self {
        Self {
            hub,
            keyspace_timeout: Duration::from_secs(20),
        }
    }

    /// Build the wire task from a scheduler RunnerTask, inlining the hash lines
    /// (the server can read its own data_dir; the agent cannot).
    async fn to_agent_task(&self, task: &RunnerTask) -> AgentTask {
        let hashes = match tokio::fs::read_to_string(&task.hash_file).await {
            Ok(body) => body
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect(),
            Err(_) => Vec::new(),
        };
        // `primary` is either a mask string or a path to an uploaded wordlist
        // under the server's data_dir (basename = file id). Masks travel inline;
        // wordlists are referenced by id for the agent to fetch.
        let (mask, wordlist) = match file_id_of_path(&task.primary).await {
            Some(id) => (None, Some(id)),
            None => (Some(task.primary.clone()), None),
        };
        let mut rules = Vec::new();
        for r in &task.rules {
            if let Some(id) = file_id_of_path(r).await {
                rules.push(id);
            }
        }
        AgentTask {
            task_id: task.task_id,
            hash_type: task.hash_type,
            attack_mode: task.attack_mode,
            hashes,
            mask,
            wordlist,
            rules,
            keyspace_offset: task.keyspace_offset,
            keyspace_len: task.keyspace_len,
            extra_args: task.extra_args.clone(),
        }
    }
}

#[async_trait]
impl Runner for RemoteRunner {
    async fn keyspace(&self, task: &RunnerTask) -> CoreResult<u64> {
        let at = self.to_agent_task(task).await;
        match self.hub.keyspace_probe(at).await {
            Some(rx) => match tokio::time::timeout(self.keyspace_timeout, rx).await {
                Ok(Ok(v)) => Ok(v),
                // Timed out or the agent dropped: treat as unknown keyspace.
                _ => Ok(0),
            },
            None => Ok(0),
        }
    }

    async fn start(&self, task: &RunnerTask, tx: StatusSink) -> CoreResult<RunHandle> {
        let at = self.to_agent_task(task).await;
        let task_id = task.task_id;
        self.hub.dispatch(at, tx).await;
        tracing::info!(%task_id, "chunk dispatched to agent pool");
        Ok(RunHandle { task_id })
    }

    async fn pause(&self, handle: &RunHandle) -> CoreResult<()> {
        self.cancel(handle).await
    }

    async fn resume(&self, _handle: &RunHandle) -> CoreResult<()> {
        Ok(())
    }

    async fn cancel(&self, handle: &RunHandle) -> CoreResult<()> {
        self.hub.cancel_task(handle.task_id).await;
        Ok(())
    }
}

// ======================= HTTP: enrollment & admin =======================

/// POST /agent/enroll — unauthenticated; gated by a one-time claim token.
pub async fn enroll(
    State(state): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, AppError> {
    // Consume the claim token (must exist and be unused).
    let claim: Option<(String,)> =
        sqlx::query_as("SELECT name FROM agent_claims WHERE token = $1 AND used_at IS NULL")
            .bind(&req.claim_token)
            .fetch_optional(&state.db)
            .await?;
    if claim.is_none() {
        return Err(AppError::Unauthorized("invalid or used claim token".into()));
    }

    let (cert_pem, fingerprint) = state
        .pki
        .sign_csr(&req.csr_pem)
        .map_err(|e| AppError::BadRequest(format!("csr: {e}")))?;

    let agent_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (name, fingerprint, status) VALUES ($1, $2, 'enrolled') RETURNING id",
    )
    .bind(&req.name)
    .bind(&fingerprint)
    .fetch_one(&state.db)
    .await?;
    sqlx::query("UPDATE agent_claims SET used_at = now() WHERE token = $1")
        .bind(&req.claim_token)
        .execute(&state.db)
        .await?;
    tracing::info!(%agent_id, name = %req.name, "agent enrolled");
    Ok(Json(EnrollResponse {
        agent_id,
        cert_pem,
        ca_pem: state.pki.ca_pem().to_string(),
    }))
}

/// POST /admin/agent-claims — mint a one-time enrollment token.
pub async fn create_claim(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<AgentClaimCreate>,
) -> Result<(StatusCode, Json<AgentClaim>), AppError> {
    auth.require(Capability::ManageAgents)?;
    let token: String = {
        let mut rng = rand::thread_rng();
        (0..32)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect()
    };
    sqlx::query("INSERT INTO agent_claims (token, name, created_by) VALUES ($1, $2, $3)")
        .bind(&token)
        .bind(&body.name)
        .bind(auth.id)
        .execute(&state.db)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(AgentClaim {
            claim_token: token,
            name: body.name,
        }),
    ))
}

/// GET /agents — list enrolled agents.
#[allow(clippy::type_complexity)]
pub async fn list_agents(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<AgentInfo>>, AppError> {
    auth.require(Capability::ViewStats)?;
    let rows: Vec<(
        Uuid,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT id, name, status, enrolled_at, last_seen FROM agents ORDER BY enrolled_at",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, name, status, enrolled_at, last_seen)| AgentInfo {
                id,
                name,
                status,
                enrolled_at,
                last_seen,
            })
            .collect(),
    ))
}

/// GET /agent/files/:id — stream an uploaded wordlist/rule file to an agent.
/// Authenticated the same way as the WS: the agent presents its issued client
/// certificate in `x-agent-cert`, matched by fingerprint to an enrolled agent.
pub async fn download_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<Uuid>,
) -> Result<Response, AppError> {
    let cert = headers
        .get("x-agent-cert")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing agent certificate".into()))?;
    let fingerprint = pki::fingerprint_of_pem(cert)
        .map_err(|_| AppError::Unauthorized("bad certificate".into()))?;
    let enrolled: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM agents WHERE fingerprint = $1 AND status <> 'revoked'")
            .bind(&fingerprint)
            .fetch_optional(&state.db)
            .await?;
    if enrolled.is_none() {
        return Err(AppError::Unauthorized("certificate not enrolled".into()));
    }
    let path: Option<String> = sqlx::query_scalar("SELECT path FROM files WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    let Some(path) = path else {
        return Err(AppError::NotFound("file not found".into()));
    };
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|e| AppError::NotFound(format!("file unavailable: {e}")))?;
    Ok(Response::new(Body::from_stream(ReaderStream::new(file))))
}

/// Resolve an uploaded-file path (`{data_dir}/files/{id}`) to its file id, if
/// the basename is a UUID and the file exists on disk. Returns None for a mask
/// string or any non-file path.
async fn file_id_of_path(p: &str) -> Option<Uuid> {
    let id = std::path::Path::new(p)
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| Uuid::parse_str(s).ok())?;
    match tokio::fs::metadata(p).await {
        Ok(m) if m.is_file() => Some(id),
        _ => None,
    }
}

// ======================= WebSocket task stream =======================

/// WS /agent/stream — agents connect, authenticate with their issued cert, and
/// exchange the task protocol.
pub async fn agent_stream(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| handle_agent(socket, state))
}

async fn handle_agent(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();

    // First frame must be Hello with the issued client cert.
    let hello = match stream.next().await {
        Some(Ok(Message::Text(t))) => serde_json::from_str::<AgentMsg>(&t).ok(),
        _ => None,
    };
    let Some(AgentMsg::Hello { name, cert_pem }) = hello else {
        let _ = sink
            .send(Message::Text(reject("expected hello frame")))
            .await;
        return;
    };

    let Ok(fingerprint) = pki::fingerprint_of_pem(&cert_pem) else {
        let _ = sink.send(Message::Text(reject("bad certificate"))).await;
        return;
    };
    let agent_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM agents WHERE fingerprint = $1 AND status <> 'revoked'")
            .bind(&fingerprint)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let Some(agent_id) = agent_id else {
        let _ = sink
            .send(Message::Text(reject("certificate not enrolled")))
            .await;
        return;
    };

    // Writer task: hub -> socket.
    let (tx, mut rx) = mpsc::channel::<ServerMsg>(64);
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let txt = serde_json::to_string(&msg).unwrap_or_default();
            if sink.send(Message::Text(txt)).await.is_err() {
                break;
            }
        }
    });

    let _ = tx.send(ServerMsg::Welcome { agent_id }).await;
    state
        .agents
        .register(agent_id, name.clone(), tx.clone())
        .await;
    let _ = sqlx::query("UPDATE agents SET status = 'online', last_seen = now() WHERE id = $1")
        .bind(agent_id)
        .execute(&state.db)
        .await;
    tracing::info!(%agent_id, %name, "agent connected");

    while let Some(Ok(msg)) = stream.next().await {
        match msg {
            Message::Text(t) => {
                if let Ok(m) = serde_json::from_str::<AgentMsg>(&t) {
                    handle_agent_msg(&state, agent_id, &name, m).await;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    state.agents.disconnect(agent_id).await;
    let _ = sqlx::query("UPDATE agents SET status = 'offline' WHERE id = $1")
        .bind(agent_id)
        .execute(&state.db)
        .await;
    writer.abort();
    tracing::info!(%agent_id, "agent disconnected");
}

async fn handle_agent_msg(state: &AppState, agent_id: Uuid, agent_name: &str, msg: AgentMsg) {
    match msg {
        AgentMsg::Ready { slots } => state.agents.set_ready(agent_id, slots).await,
        AgentMsg::Keyspace { req_id, value } => state.agents.fulfill_keyspace(req_id, value).await,
        AgentMsg::Progress {
            task_id,
            progress,
            speed,
            recovered,
            state: st,
        } => {
            if let Some(sink) = state.agents.sink_for(task_id).await {
                let _ = sink
                    .send(StatusUpdate {
                        task_id,
                        progress,
                        speed,
                        recovered,
                        eta: None,
                        state: parse_task_state(&st),
                    })
                    .await;
            }
        }
        AgentMsg::Cracked { task_id, items } => {
            import_cracked(state, task_id, &items).await;
        }
        AgentMsg::Metrics { samples } => {
            let devices = samples
                .into_iter()
                .map(|m| to_device_view(agent_name, m))
                .collect::<Vec<_>>();
            crate::telemetry::record(state, &devices).await;
        }
        AgentMsg::TaskDone { task_id, state: st } => {
            let ts = parse_task_state(&st);
            if let Some(sink) = state.agents.sink_for(task_id).await {
                let _ = sink
                    .send(StatusUpdate {
                        task_id,
                        progress: if ts == TaskState::Done { 1.0 } else { 0.0 },
                        speed: 0,
                        recovered: 0,
                        eta: None,
                        state: ts,
                    })
                    .await;
            }
            state.agents.finish_task(task_id).await;
        }
        AgentMsg::Error { task_id, message } => {
            tracing::warn!(%agent_id, ?task_id, %message, "agent reported error");
            if let Some(task_id) = task_id {
                if let Some(sink) = state.agents.sink_for(task_id).await {
                    let _ = sink
                        .send(StatusUpdate {
                            task_id,
                            progress: 0.0,
                            speed: 0,
                            recovered: 0,
                            eta: None,
                            state: TaskState::Failed,
                        })
                        .await;
                }
                state.agents.finish_task(task_id).await;
            }
        }
        AgentMsg::Hello { .. } => {}
    }
}

async fn import_cracked(
    state: &AppState,
    task_id: Uuid,
    items: &[flamejob_api::agent::CrackedItem],
) {
    let hashlist_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT j.hashlist_id FROM jobs j JOIN tasks t ON t.job_id = j.id WHERE t.id = $1",
    )
    .bind(task_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some(hashlist_id) = hashlist_id else {
        return;
    };
    for item in items {
        let ct = state.cipher.encrypt(item.plain.as_bytes());
        let _ = sqlx::query(
            "UPDATE hashes SET plain = $1, cracked_at = now() \
             WHERE hashlist_id = $2 AND hash = $3 AND plain IS NULL",
        )
        .bind(ct)
        .bind(hashlist_id)
        .bind(&item.hash)
        .execute(&state.db)
        .await;
    }
    let _ = sqlx::query(
        "UPDATE hashlists SET cracked = \
         (SELECT count(*) FROM hashes WHERE hashlist_id = $1 AND plain IS NOT NULL) WHERE id = $1",
    )
    .bind(hashlist_id)
    .execute(&state.db)
    .await;
}

fn to_device_view(agent_name: &str, m: AgentMetric) -> DeviceView {
    DeviceView {
        name: format!("{agent_name}/{}", m.name),
        kind: m.kind,
        temp: m.temp,
        util: m.util,
        mem_used: m.mem_used,
        mem_total: m.mem_total,
        pstate: m.pstate,
        power_w: m.power_w,
        fan: m.fan,
        clock_mhz: m.clock_mhz,
        mem_clock_mhz: m.mem_clock_mhz,
        hashrate: m.hashrate,
    }
}

fn parse_task_state(s: &str) -> TaskState {
    match s {
        "done" => TaskState::Done,
        "failed" => TaskState::Failed,
        "paused" => TaskState::Paused,
        "pending" => TaskState::Pending,
        _ => TaskState::Running,
    }
}

fn reject(reason: &str) -> String {
    serde_json::to_string(&ServerMsg::Rejected {
        reason: reason.to_string(),
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_state_parsing() {
        assert_eq!(parse_task_state("done"), TaskState::Done);
        assert_eq!(parse_task_state("failed"), TaskState::Failed);
        assert_eq!(parse_task_state("running"), TaskState::Running);
        assert_eq!(parse_task_state("anything"), TaskState::Running);
    }

    #[tokio::test]
    async fn hub_queues_without_agents() {
        let hub = AgentHub::new();
        assert_eq!(hub.connected_count().await, 0);
        // No agents: a keyspace probe returns None rather than blocking.
        let task = AgentTask {
            task_id: Uuid::new_v4(),
            hash_type: 0,
            attack_mode: 3,
            hashes: vec![],
            mask: Some("?d?d".into()),
            wordlist: None,
            rules: vec![],
            keyspace_offset: 0,
            keyspace_len: 0,
            extra_args: vec![],
        };
        assert!(hub.keyspace_probe(task).await.is_none());
    }
}
