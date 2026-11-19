//! Builds the Dashboard model from the live API via flamejob-client.
use anyhow::Result;
use flamejob_client::Client;

use crate::model::{ChunkRow, Dashboard, Device, JobRow};

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(String::from))
        .unwrap_or_default()
}

pub async fn fetch_dashboard(client: &Client, server: &str, selected: usize) -> Result<Dashboard> {
    let jobs_api = client.list_jobs().await?;
    let jobs: Vec<JobRow> = jobs_api
        .iter()
        .map(|j| JobRow {
            id: j.id,
            name: j.name.clone(),
            state: enum_str(&j.state),
            priority: j.priority,
            progress: j.progress,
            speed: j.speed,
            eta: j.est_completion,
            cracked: j.cracked,
            total: j.total,
        })
        .collect();
    let selected = selected.min(jobs.len().saturating_sub(1));
    let chunks = match jobs_api.get(selected) {
        Some(j) => client
            .list_job_tasks(j.id)
            .await
            .unwrap_or_default()
            .iter()
            .map(|t| ChunkRow {
                offset: t.keyspace_offset,
                len: t.keyspace_len,
                progress: t.progress,
                speed: t.speed,
                state: enum_str(&t.state),
            })
            .collect(),
        None => Vec::new(),
    };
    let devices: Vec<Device> = client
        .list_devices()
        .await
        .unwrap_or_default()
        .iter()
        .map(|d| Device {
            name: d.name.clone(),
            temp: d.temp,
            util: d.util,
            mem_used: d.mem_used as i32,
            mem_total: d.mem_total as i32,
            pstate: d.pstate.clone(),
            clock_mhz: d.clock_mhz,
            hashrate: d.hashrate,
        })
        .collect();
    let telemetry_live = !devices.is_empty();
    Ok(Dashboard {
        server: server.to_string(),
        now: chrono::Utc::now(),
        jobs,
        selected,
        chunks,
        devices,
        telemetry_live,
    })
}
