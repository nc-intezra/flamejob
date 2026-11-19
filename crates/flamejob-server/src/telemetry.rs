//! Local device telemetry collection (Phase 2, single-box). Samples GPU metrics
//! via NVML (NVIDIA) and host CPU/RAM via sysinfo on a configurable interval,
//! updates the AppState snapshot read by GET /devices, records history in
//! `metric_samples`, upserts the `current_devices` snapshot, and exports gauges.
//!
//! Degrades gracefully: with no NVIDIA GPU / no NVML the collector still reports
//! host CPU and RAM, and each per-device metric falls back to 0 when a specific
//! NVML query is unsupported on the installed driver.
use std::time::Duration;

use flamejob_api::DeviceView;
use nvml_wrapper::enum_wrappers::device::{Clock, TemperatureSensor};
use nvml_wrapper::Nvml;
use sysinfo::System;

use crate::state::AppState;

pub fn spawn(state: AppState) {
    if !state.cfg.telemetry.enabled {
        tracing::info!("telemetry collector disabled by config");
        return;
    }
    let interval = Duration::from_secs(state.cfg.telemetry.sample_interval_secs.max(1));
    tokio::spawn(async move {
        let nvml = Nvml::init().ok();
        if nvml.is_none() {
            tracing::info!("NVML unavailable; collecting host metrics only");
        }
        let mut sys = System::new();
        loop {
            let devices = collect(nvml.as_ref(), &mut sys);
            record(&state, &devices).await;
            *state.devices.write().await = devices;
            tokio::time::sleep(interval).await;
        }
    });
}

/// Export Prometheus gauges and append a sample row for each device. Shared by
/// the local collector and the remote-agent telemetry ingest path.
pub(crate) async fn record(state: &AppState, devices: &[DeviceView]) {
    export_gauges(devices);
    persist(state, devices).await;
}

/// Build the current device list: every NVML GPU plus the host CPU/RAM.
fn collect(nvml: Option<&Nvml>, sys: &mut System) -> Vec<DeviceView> {
    let mut devices = Vec::new();

    if let Some(nvml) = nvml {
        if let Ok(count) = nvml.device_count() {
            for i in 0..count {
                if let Ok(d) = nvml.device_by_index(i) {
                    devices.push(gpu_view(&d, i));
                }
            }
        }
    }

    sys.refresh_cpu_usage();
    sys.refresh_memory();
    devices.push(DeviceView {
        name: "CPU (host)".into(),
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
        hashrate: 0,
    });
    devices
}

fn export_gauges(devices: &[DeviceView]) {
    for d in devices {
        let label = d.name.clone();
        metrics::gauge!("flamejob_device_temp_celsius", "device" => label.clone())
            .set(d.temp as f64);
        metrics::gauge!("flamejob_device_util_percent", "device" => label.clone())
            .set(d.util as f64);
        metrics::gauge!("flamejob_device_mem_used_mib", "device" => label.clone())
            .set(d.mem_used as f64);
        metrics::gauge!("flamejob_device_mem_total_mib", "device" => label.clone())
            .set(d.mem_total as f64);
        metrics::gauge!("flamejob_device_power_watts", "device" => label.clone())
            .set(d.power_w as f64);
        metrics::gauge!("flamejob_device_fan_percent", "device" => label.clone()).set(d.fan as f64);
        metrics::gauge!("flamejob_device_clock_mhz", "device" => label.clone())
            .set(d.clock_mhz as f64);
        metrics::gauge!("flamejob_device_mem_clock_mhz", "device" => label.clone())
            .set(d.mem_clock_mhz as f64);
        metrics::gauge!("flamejob_device_hashrate", "device" => label).set(d.hashrate as f64);
    }
}

/// Append each sample to `metric_samples` and upsert the `current_devices`
/// snapshot. Failures are logged at debug and never stall collection.
async fn persist(state: &AppState, devices: &[DeviceView]) {
    for d in devices {
        if let Err(e) = sqlx::query(
            "INSERT INTO metric_samples \
             (name, kind, temp, util, mem_used, mem_total, pstate, power_w, fan, clock_mhz, mem_clock_mhz, hashrate) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(&d.name)
        .bind(&d.kind)
        .bind(d.temp)
        .bind(d.util)
        .bind(d.mem_used)
        .bind(d.mem_total)
        .bind(&d.pstate)
        .bind(d.power_w)
        .bind(d.fan)
        .bind(d.clock_mhz)
        .bind(d.mem_clock_mhz)
        .bind(d.hashrate)
        .execute(&state.db)
        .await
        {
            tracing::debug!(error = %e, device = %d.name, "metric_samples insert failed");
            continue;
        }
        let _ = sqlx::query(
            "INSERT INTO current_devices \
             (name, kind, temp, util, mem_used, mem_total, pstate, power_w, fan, clock_mhz, mem_clock_mhz, hashrate, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now()) \
             ON CONFLICT (name) DO UPDATE SET \
               kind=EXCLUDED.kind, temp=EXCLUDED.temp, util=EXCLUDED.util, \
               mem_used=EXCLUDED.mem_used, mem_total=EXCLUDED.mem_total, pstate=EXCLUDED.pstate, \
               power_w=EXCLUDED.power_w, fan=EXCLUDED.fan, clock_mhz=EXCLUDED.clock_mhz, \
               mem_clock_mhz=EXCLUDED.mem_clock_mhz, hashrate=EXCLUDED.hashrate, updated_at=now()",
        )
        .bind(&d.name)
        .bind(&d.kind)
        .bind(d.temp)
        .bind(d.util)
        .bind(d.mem_used)
        .bind(d.mem_total)
        .bind(&d.pstate)
        .bind(d.power_w)
        .bind(d.fan)
        .bind(d.clock_mhz)
        .bind(d.mem_clock_mhz)
        .bind(d.hashrate)
        .execute(&state.db)
        .await;
    }
}

fn gpu_view(d: &nvml_wrapper::Device, idx: u32) -> DeviceView {
    let name = d.name().unwrap_or_else(|_| format!("GPU{idx}"));
    let temp = d.temperature(TemperatureSensor::Gpu).unwrap_or(0) as i32;
    let util = d.utilization_rates().map(|u| u.gpu as i32).unwrap_or(0);
    let (mem_used, mem_total) = d
        .memory_info()
        .map(|m| ((m.used / 1_048_576) as i64, (m.total / 1_048_576) as i64))
        .unwrap_or((0, 0));
    let pstate = d
        .performance_state()
        .map(|p| format!("{p:?}"))
        .unwrap_or_else(|_| "—".into());
    let power_w = d.power_usage().map(|mw| (mw / 1000) as i32).unwrap_or(0);
    let fan = d.fan_speed(0).map(|f| f as i32).unwrap_or(0);
    let clock_mhz = d.clock_info(Clock::Graphics).unwrap_or(0) as i32;
    let mem_clock_mhz = d.clock_info(Clock::Memory).unwrap_or(0) as i32;
    DeviceView {
        name: format!("GPU{idx} {name}"),
        kind: "gpu".into(),
        temp,
        util,
        mem_used,
        mem_total,
        pstate,
        power_w,
        fan,
        clock_mhz,
        mem_clock_mhz,
        hashrate: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_degrades_to_host_only() {
        // With no NVML handle the collector must still report the host CPU/RAM.
        let mut sys = System::new();
        let devices = collect(None, &mut sys);
        let cpu = devices
            .iter()
            .find(|d| d.kind == "cpu")
            .expect("host CPU device present");
        assert_eq!(cpu.name, "CPU (host)");
        assert!(cpu.mem_total >= 0);
        assert!(!devices.iter().any(|d| d.kind == "gpu"));
    }
}
