//! NVIDIA GPU telemetry and fan control for the agent.
//!
//! Telemetry is read with `nvidia-smi` and fan control is driven with
//! `nvidia-settings`, both as subprocesses. Everything here is best-effort: with
//! no NVIDIA driver or binaries present (or on a box with no GPUs) the functions
//! log nothing noisy and simply return empty / no-op, so the agent runs fine on
//! CPU-only hosts.
use flamejob_api::agent::AgentMetric;
use tokio::process::Command;

#[derive(Clone, Debug)]
pub struct Gpu {
    pub index: u32,
    /// Slowdown (thermal-throttle) temperature in °C, treated as the "max rated"
    /// temperature for fan control. 0 when unknown.
    pub max_temp: i32,
}

async fn nvidia_smi(args: &[&str]) -> Option<String> {
    let out = Command::new("nvidia-smi").args(args).output().await.ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

async fn nvidia_settings(args: &[String]) {
    // Fire-and-forget; requires an X display and a permissive driver. Errors are
    // expected on headless/unsupported hosts and are intentionally ignored.
    let _ = Command::new("nvidia-settings").args(args).output().await;
}

/// Detect NVIDIA GPUs once at startup (index, name, and max/slowdown temp).
pub async fn detect() -> Vec<Gpu> {
    let listing =
        match nvidia_smi(&["--query-gpu=index,name", "--format=csv,noheader,nounits"]).await {
            Some(s) => s,
            None => return Vec::new(),
        };
    let mut gpus = Vec::new();
    for line in listing.lines() {
        let mut parts = line.splitn(2, ',');
        let index = match parts.next().and_then(|s| s.trim().parse::<u32>().ok()) {
            Some(i) => i,
            None => continue,
        };
        let max_temp = slowdown_temp(index).await;
        gpus.push(Gpu { index, max_temp });
    }
    gpus
}

/// Parse the slowdown (or shutdown) temperature from `nvidia-smi -q -d TEMPERATURE`.
async fn slowdown_temp(index: u32) -> i32 {
    let q = match nvidia_smi(&["-i", &index.to_string(), "-q", "-d", "TEMPERATURE"]).await {
        Some(s) => s,
        None => return 0,
    };
    let field = |label: &str| -> Option<i32> {
        q.lines()
            .find(|l| l.contains(label))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse::<i32>().ok())
    };
    field("GPU Slowdown Temp")
        .or_else(|| field("GPU Shutdown Temp").map(|t| t - 5))
        .or_else(|| field("GPU Max Operating Temp"))
        .unwrap_or(0)
}

/// Sample every detected GPU into an `AgentMetric` (kind `gpu`).
pub async fn sample(gpus: &[Gpu]) -> Vec<AgentMetric> {
    if gpus.is_empty() {
        return Vec::new();
    }
    let out = match nvidia_smi(&[
        "--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,\
         pstate,power.draw,fan.speed,clocks.sm,clocks.mem",
        "--format=csv,noheader,nounits",
    ])
    .await
    {
        Some(s) => s,
        None => return Vec::new(),
    };
    out.lines().filter_map(parse_sample_line).collect()
}

/// Parse one `nvidia-smi --format=csv,noheader,nounits` row (the 11 fields queried
/// by [`sample`]) into an `AgentMetric`. Returns `None` for short/garbage rows.
/// nvidia-smi prints `[N/A]` for unsupported fields; those parse as 0.
fn parse_sample_line(line: &str) -> Option<AgentMetric> {
    let f: Vec<String> = line.split(',').map(|s| s.trim().to_string()).collect();
    if f.len() < 11 {
        return None;
    }
    let n = |i: usize| -> i32 {
        f.get(i)
            .and_then(|s| s.parse::<f64>().ok())
            .map(|x| x as i32)
            .unwrap_or(0)
    };
    let index = f[0].parse::<u32>().unwrap_or(0);
    Some(AgentMetric {
        name: format!("{}[{}]", f[1], index),
        kind: "gpu".into(),
        temp: n(2),
        util: n(3),
        mem_used: n(4) as i64,
        mem_total: n(5) as i64,
        pstate: f[6].clone(),
        power_w: n(7),
        fan: n(8),
        clock_mhz: n(9),
        mem_clock_mhz: n(10),
        hashrate: 0,
    })
}

/// Fan curve target for a GPU: hold the temperature inside 85–95% of its max
/// rated temperature. Below the band → base speed; above → full; linear between.
/// Returns `None` when the max temp is unknown (don't touch fans blindly).
pub fn fan_target(max_temp: i32, temp: i32) -> Option<i32> {
    if max_temp <= 0 {
        return None;
    }
    let low = (max_temp as f32 * 0.85) as i32;
    let high = (max_temp as f32 * 0.95) as i32;
    let pct = if temp <= low {
        30
    } else if temp >= high {
        100
    } else {
        30 + ((temp - low) as f32 / (high - low).max(1) as f32 * 70.0) as i32
    };
    Some(pct.clamp(0, 100))
}

/// While under load, disable auto fan control and drive each GPU's fan toward the
/// 85–95% temperature band. Best-effort via `nvidia-settings`.
pub async fn apply_fan_curve(gpus: &[Gpu], samples: &[AgentMetric]) {
    for g in gpus {
        let suffix = format!("[{}]", g.index);
        let temp = match samples.iter().find(|s| s.name.ends_with(&suffix)) {
            Some(s) => s.temp,
            None => continue,
        };
        if let Some(pct) = fan_target(g.max_temp, temp) {
            nvidia_settings(&[
                "-a".into(),
                format!("[gpu:{}]/GPUFanControlState=1", g.index),
                "-a".into(),
                format!("[fan:{}]/GPUTargetFanSpeed={pct}", g.index),
            ])
            .await;
        }
    }
}

/// Hand the fans back to the driver's automatic control (task finished).
pub async fn reset_fans(gpus: &[Gpu]) {
    for g in gpus {
        nvidia_settings(&[
            "-a".into(),
            format!("[gpu:{}]/GPUFanControlState=0", g.index),
        ])
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::{fan_target, parse_sample_line};

    #[test]
    fn parses_a_real_nvidia_smi_row() {
        // index,name,temp,util,mem_used,mem_total,pstate,power,fan,sm_clock,mem_clock
        let m = parse_sample_line(
            "0, NVIDIA GeForce RTX 4090, 71, 99, 2048, 24564, P2, 342, 68, 2520, 10501",
        )
        .expect("row should parse");
        assert_eq!(m.name, "NVIDIA GeForce RTX 4090[0]");
        assert_eq!(m.kind, "gpu");
        assert_eq!(m.temp, 71);
        assert_eq!(m.util, 99);
        assert_eq!(m.mem_used, 2048);
        assert_eq!(m.mem_total, 24564);
        assert_eq!(m.pstate, "P2");
        assert_eq!(m.power_w, 342);
        assert_eq!(m.fan, 68);
        assert_eq!(m.clock_mhz, 2520);
        assert_eq!(m.mem_clock_mhz, 10501);
    }

    #[test]
    fn na_fields_become_zero_and_short_rows_drop() {
        // A passively-cooled card reports [N/A] for fan/power; those must not break parsing.
        let m =
            parse_sample_line("1, NVIDIA A100, 55, 0, 100, 40960, P0, [N/A], [N/A], 1410, 1215")
                .expect("row should parse");
        assert_eq!(m.fan, 0);
        assert_eq!(m.power_w, 0);
        assert_eq!(m.temp, 55);
        assert_eq!(m.pstate, "P0");
        assert!(parse_sample_line("0, only, three, fields").is_none());
    }

    #[test]
    fn fan_curve_holds_the_band() {
        // max 90°C -> band 76.5..85.5 (low 76, high 85).
        assert_eq!(fan_target(90, 50), Some(30)); // cool -> base
        assert_eq!(fan_target(90, 76), Some(30)); // at/below low -> base
        assert_eq!(fan_target(90, 90), Some(100)); // above high -> full
        let mid = fan_target(90, 80).unwrap(); // inside band -> ramped
        assert!(mid > 30 && mid < 100, "mid-band ramp was {mid}");
        assert_eq!(fan_target(0, 80), None); // unknown max -> don't touch
    }
}
