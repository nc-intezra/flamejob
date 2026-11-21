use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

#[derive(Clone)]
pub struct JobRow {
    pub id: Uuid,
    pub name: String,
    pub state: String,
    pub priority: i32,
    pub progress: f64,
    pub speed: i64,
    pub eta: Option<DateTime<Utc>>,
    pub cracked: i32,
    pub total: i32,
}

#[derive(Clone)]
pub struct ChunkRow {
    pub offset: i64,
    pub len: i64,
    pub progress: f64,
    pub speed: i64,
    pub state: String,
}

#[derive(Clone)]
pub struct Agent {
    pub name: String,
    /// online | away | error | busy (see flamejob_api::agent::AgentInfo).
    pub status: String,
}

#[derive(Clone)]
pub struct Device {
    pub name: String,
    pub temp: i32,
    pub util: i32,
    pub mem_used: i32,
    pub mem_total: i32,
    pub pstate: String,
    pub fan: i32,
    pub clock_mhz: i32,
    pub hashrate: i64,
}

pub struct Dashboard {
    pub server: String,
    pub now: DateTime<Utc>,
    pub jobs: Vec<JobRow>,
    pub selected: usize,
    pub chunks: Vec<ChunkRow>,
    pub devices: Vec<Device>,
    pub agents: Vec<Agent>,
    pub telemetry_live: bool,
    /// Finished jobs are hidden from the jobs list (local view filter).
    pub hide_finished: bool,
    /// The logged-in user may submit/clear jobs (SubmitJobs capability).
    pub can_submit: bool,
    /// Total jobs reported by the server before any local filtering.
    pub total_jobs: usize,
}

impl Dashboard {
    pub fn selected_job(&self) -> Option<&JobRow> {
        self.jobs.get(self.selected)
    }

    /// Representative data used for design screenshots (no server required).
    pub fn sample() -> Self {
        let now = Utc::now();
        let jobs = vec![
            JobRow {
                id: Uuid::new_v4(),
                name: "corp NTLM dump".into(),
                state: "running".into(),
                priority: 50,
                progress: 0.62,
                speed: 1_240_000_000,
                eta: Some(now + Duration::seconds(8 * 60 + 12)),
                cracked: 142,
                total: 512,
            },
            JobRow {
                id: Uuid::new_v4(),
                name: "md5 leak set".into(),
                state: "running".into(),
                priority: 40,
                progress: 0.23,
                speed: 880_000_000,
                eta: Some(now + Duration::seconds(41 * 60 + 5)),
                cracked: 1203,
                total: 5000,
            },
            JobRow {
                id: Uuid::new_v4(),
                name: "wifi handshakes".into(),
                state: "queued".into(),
                priority: 100,
                progress: 0.0,
                speed: 0,
                eta: None,
                cracked: 0,
                total: 1,
            },
            JobRow {
                id: Uuid::new_v4(),
                name: "vpn hashes q3".into(),
                state: "completed".into(),
                priority: 60,
                progress: 1.0,
                speed: 0,
                eta: None,
                cracked: 88,
                total: 88,
            },
            JobRow {
                id: Uuid::new_v4(),
                name: "legacy sha1".into(),
                state: "exhausted".into(),
                priority: 70,
                progress: 1.0,
                speed: 0,
                eta: None,
                cracked: 3,
                total: 900,
            },
            JobRow {
                id: Uuid::new_v4(),
                name: "oracle set".into(),
                state: "error".into(),
                priority: 55,
                progress: 0.44,
                speed: 0,
                eta: None,
                cracked: 0,
                total: 240,
            },
        ];
        let chunks = vec![
            ChunkRow {
                offset: 0,
                len: 25_000_000,
                progress: 1.0,
                speed: 0,
                state: "done".into(),
            },
            ChunkRow {
                offset: 25_000_000,
                len: 25_000_000,
                progress: 0.48,
                speed: 1_240_000_000,
                state: "running".into(),
            },
            ChunkRow {
                offset: 50_000_000,
                len: 25_000_000,
                progress: 0.0,
                speed: 0,
                state: "pending".into(),
            },
            ChunkRow {
                offset: 75_000_000,
                len: 25_000_000,
                progress: 0.0,
                speed: 0,
                state: "pending".into(),
            },
        ];
        let devices = vec![
            Device {
                name: "GPU0 RTX 4090".into(),
                temp: 72,
                util: 98,
                mem_used: 22100,
                mem_total: 24564,
                pstate: "P2".into(),
                fan: 62,
                clock_mhz: 2520,
                hashrate: 640_000_000,
            },
            Device {
                name: "GPU1 RTX 4090".into(),
                temp: 69,
                util: 97,
                mem_used: 21040,
                mem_total: 24564,
                pstate: "P2".into(),
                fan: 58,
                clock_mhz: 2490,
                hashrate: 600_000_000,
            },
        ];
        let agents = vec![
            Agent {
                name: "gpu-rig-01".into(),
                status: "online".into(),
            },
            Agent {
                name: "gpu-rig-02".into(),
                status: "busy".into(),
            },
            Agent {
                name: "gpu-rig-03".into(),
                status: "away".into(),
            },
            Agent {
                name: "gpu-rig-04".into(),
                status: "error".into(),
            },
        ];
        let total_jobs = jobs.len();
        Dashboard {
            server: "https://crack01.lab:8443".into(),
            now,
            jobs,
            selected: 0,
            chunks,
            devices,
            agents,
            telemetry_live: false,
            hide_finished: false,
            can_submit: true,
            total_jobs,
        }
    }
}

/// Persistent, cross-frame UI state for the scrollable tables. Lives in the run
/// loop (ratatui's stateful tables keep their scroll offset here between draws).
#[derive(Default)]
pub struct UiState {
    pub jobs: ratatui::widgets::TableState,
    pub chunks: ratatui::widgets::TableState,
}
