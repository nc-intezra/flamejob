//! Local device telemetry collection (Phase 2, single-box). Samples GPU metrics
//! via NVML (NVIDIA) and host CPU/RAM via sysinfo, updates the AppState snapshot
//! read by GET /devices, records history in device_samples, and exports gauges.
use std::time::Duration;

use flamejob_api::DeviceView;
use nvml_wrapper::enum_wrappers::device::TemperatureSensor;
use nvml_wrapper::Nvml;
use sysinfo::System;

use crate::state::AppState;

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let nvml = Nvml::init().ok();
        if nvml.is_none() {
            tracing::info!("NVML unavailable; collecting host metrics only");
        }
        let mut sys = System::new();
        loop {
            let mut devices = Vec::new();

            if let Some(nvml) = &nvml {
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
                hashrate: 0,
            });

            for d in &devices {
                metrics::gauge!("flamejob_device_temp_celsius", "device" => d.name.clone())
                    .set(d.temp as f64);
                metrics::gauge!("flamejob_device_util_percent", "device" => d.name.clone())
                    .set(d.util as f64);
                let _ = sqlx::query(
                    "INSERT INTO device_samples (name, kind, temp, util, mem_used, mem_total, pstate, power_w, fan, hashrate) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
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
                .bind(d.hashrate)
                .execute(&state.db)
                .await;
            }

            *state.devices.write().await = devices;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
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
        hashrate: 0,
    }
}
