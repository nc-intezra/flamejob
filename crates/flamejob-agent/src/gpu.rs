//! NVIDIA GPU telemetry and fan control for the agent.
//!
//! Telemetry is read with `nvidia-smi` and fan control is driven with
//! `nvidia-settings`, both as subprocesses. Everything here is best-effort: with
//! no NVIDIA driver or binaries present (or on a box with no GPUs) the functions
//! log nothing noisy and simply return empty / no-op, so the agent runs fine on
//! CPU-only hosts.
//!
//! Platform note: `nvidia-smi` telemetry works identically on Linux and Windows
//! (the driver ships `nvidia-smi.exe` on `PATH`). Active fan control, however,
//! is driven through `nvidia-settings`, which is an Xorg/Coolbits mechanism with
//! no Windows counterpart, so the actuation here is compiled in only on Unix;
//! on Windows it is a no-op and the fans stay on the driver's automatic control.
//! The controller decision logic ([`decide_fan`]) is pure and platform-neutral.
use flamejob_api::agent::AgentMetric;
use std::collections::HashMap;
use tokio::process::Command;

#[derive(Clone, Debug)]
pub struct Gpu {
    pub index: u32,
    /// Slowdown (thermal-throttle) temperature in °C, treated as the "max rated"
    /// temperature for fan control. 0 when unknown.
    pub max_temp: i32,
    /// Global `nvidia-settings` fan handles driven by this GPU (e.g. `[0]`, or
    /// `[0, 1]` on a multi-fan card). Defaults to `[index]` when the fan list
    /// can't be determined.
    pub fans: Vec<u32>,
}

async fn nvidia_smi(args: &[&str]) -> Option<String> {
    let out = Command::new("nvidia-smi").args(args).output().await.ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Warn only once if the driver refuses fan control, so a per-tick failure
/// doesn't flood the log but also isn't swallowed silently.
#[cfg(unix)]
static FAN_REFUSED_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Run `nvidia-settings` (optionally via a `helper` prefix such as `["sudo",
/// "-n"]`) with the given attribute assignments. Needs an X display and a
/// permissive driver. A refusal is logged once — see [`FanConfig::helper`] —
/// rather than silently ignored; other failures (no X, unsupported host) stay
/// quiet so CPU-only/headless hosts aren't noisy.
/// Build the `(program, args)` to invoke, applying an optional `helper` prefix
/// (e.g. `["sudo","-n"]` → run `sudo -n nvidia-settings <args>`).
#[cfg(unix)]
fn fan_cmd_parts(helper: &[String], args: &[String]) -> (String, Vec<String>) {
    if helper.is_empty() {
        ("nvidia-settings".to_string(), args.to_vec())
    } else {
        let mut full = helper[1..].to_vec();
        full.push("nvidia-settings".to_string());
        full.extend_from_slice(args);
        (helper[0].clone(), full)
    }
}

/// Apply `nvidia-settings` attribute assignments (Unix only).
///
/// `nvidia-settings` is an Xorg mechanism; on non-Unix targets (Windows) there
/// is no equivalent, so this is a no-op and the fans stay on the driver's
/// automatic control. Callers never reach it on Windows anyway — the agent
/// disables fan control there — but keeping a stub keeps the fan paths
/// cross-platform without scattering `cfg` at every call site.
#[cfg(not(unix))]
async fn nvidia_settings(_helper: &[String], _args: &[String]) {}

#[cfg(unix)]
async fn nvidia_settings(helper: &[String], args: &[String]) {
    let (program, full) = fan_cmd_parts(helper, args);
    let mut cmd = Command::new(program);
    cmd.args(full);
    if let Ok(out) = cmd.output().await {
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let refused = err.contains("permission") || err.contains("not permitted");
            if refused && !FAN_REFUSED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(
                    "GPU fan control was refused by the driver (\"Operation not permitted\"). \
                     nvidia-settings must run as root or as the X server's user; run the agent \
                     as root, or set FJ_AGENT_FAN_HELPER (e.g. \"sudo -n\"). Logged once; fans \
                     are left on the driver's automatic control."
                );
            }
        }
    }
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
        let fans = detect_fans(index).await;
        gpus.push(Gpu {
            index,
            max_temp,
            fans,
        });
    }
    gpus
}

/// Best-effort list of the `nvidia-settings` fan handles bound to a GPU, so a
/// multi-fan card has every fan driven. Falls back to `[index]`.
///
/// Fan handles are only meaningful for `nvidia-settings` actuation, which is
/// Unix-only, so on Windows this just returns `[index]` without spawning
/// anything.
#[cfg(not(unix))]
async fn detect_fans(index: u32) -> Vec<u32> {
    vec![index]
}

#[cfg(unix)]
async fn detect_fans(index: u32) -> Vec<u32> {
    let out = Command::new("nvidia-settings")
        .args(["-q", &format!("[gpu:{index}]/Fans"), "-t"])
        .output()
        .await
        .ok();
    let fans = out
        .filter(|o| o.status.success())
        .map(|o| parse_fan_handles(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default();
    if fans.is_empty() {
        vec![index]
    } else {
        fans
    }
}

/// Parse fan handles out of an `nvidia-settings` fan listing. Prefers `fan:N`
/// tokens; falls back to bare integers.
#[cfg(unix)]
fn parse_fan_handles(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in s.split("fan:").skip(1) {
        let num: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = num.parse::<u32>() {
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    if out.is_empty() {
        for tok in s.split(|c: char| !c.is_ascii_digit()) {
            if let Ok(n) = tok.parse::<u32>() {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
    }
    out
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

// ---- Closed-loop fan controller --------------------------------------------
//
// A target-temperature controller (adapted from the HiveOS autofan approach):
// hold the core at `target_temp` with a dead band, trend damping, an asymmetric
// slew limit (ramp up fast, coast down slowly), and an overheat fail-safe. It
// replaces the earlier stateless 85–95%-of-rated band.

pub const FAN_DEADBAND_DEFAULT: i32 = 2;
pub const FAN_DOWN_STEP_DEFAULT: i32 = 5;
const RECOVER_MARGIN: i32 = 10; // clear overheat once temp <= critical - this
const FAST_RISE: i32 = 3; // °C/tick that earns an extra fan boost
const MIN_DIFF: i32 = 10; // critical is forced to be at least target + this

/// Operator-supplied fan-control configuration (one set per agent).
#[derive(Clone, Debug)]
pub struct FanConfig {
    pub target_temp: i32,
    pub min_fan: i32,
    pub max_fan: i32,
    /// Overheat trip; `None` derives it per-GPU from the rated slowdown temp.
    pub critical_override: Option<i32>,
    pub deadband: i32,
    pub down_step: i32,
    /// Memory-junction target; `None` disables VRAM-aware control. Inert until a
    /// memory-temperature sensor is wired in (unsupported on most GeForce cards).
    pub mem_target: Option<i32>,
    /// Optional command prefix for `nvidia-settings`, e.g. `["sudo", "-n"]`, so
    /// an unprivileged agent can drive fans on a root-owned X server. Empty runs
    /// `nvidia-settings` directly (works when the agent runs as root or as the X
    /// server's user).
    pub helper: Vec<String>,
}

/// Resolved per-GPU policy (critical temperature filled in).
#[derive(Clone, Copy, Debug)]
pub struct FanPolicy {
    pub target_temp: i32,
    pub min_fan: i32,
    pub max_fan: i32,
    pub critical_temp: i32,
    pub deadband: i32,
    pub down_step: i32,
    pub mem_target: Option<i32>,
}

/// Per-GPU state carried across controller ticks.
#[derive(Clone, Copy, Debug)]
pub struct FanState {
    pub last_temp: Option<i32>,
    pub last_fan: i32,
    pub overheated: bool,
}

impl FanState {
    pub fn new(initial_fan: i32) -> Self {
        Self {
            last_temp: None,
            last_fan: initial_fan,
            overheated: false,
        }
    }
}

/// The controller's decision for one GPU this tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FanAction {
    /// Command this fan %.
    Set(i32),
    /// Within the dead band / sub-1% change — issue no `nvidia-settings` call.
    Hold,
    /// At/above critical: command this % (max) AND the caller must stop the task.
    Critical(i32),
}

/// Derive a GPU's critical temperature from its rated slowdown temp and target,
/// unless the operator pinned one. Kept in `[target + MIN_DIFF, max_temp]`.
pub fn critical_for(max_temp: i32, target: i32, override_c: Option<i32>) -> i32 {
    if let Some(c) = override_c {
        return c;
    }
    let ceiling = if max_temp > 0 { max_temp } else { target + 20 };
    (ceiling - 3).clamp(target + MIN_DIFF, ceiling.max(target + MIN_DIFF))
}

fn policy_for(cfg: &FanConfig, max_temp: i32) -> FanPolicy {
    FanPolicy {
        target_temp: cfg.target_temp,
        min_fan: cfg.min_fan,
        max_fan: cfg.max_fan,
        critical_temp: critical_for(max_temp, cfg.target_temp, cfg.critical_override),
        deadband: cfg.deadband,
        down_step: cfg.down_step,
        mem_target: cfg.mem_target,
    }
}

/// Pure decision: given the policy, prior state and this tick's reading, return
/// the fan command and the next state. `mem_temp` is the memory-junction temp
/// when available, else `None`. No I/O.
pub fn decide_fan(
    policy: &FanPolicy,
    state: FanState,
    core_temp: i32,
    mem_temp: Option<i32>,
) -> (FanAction, FanState) {
    let mut next = state;

    // Reject obviously-bad driver readings; leave state untouched.
    if core_temp <= 0 || core_temp > 120 {
        return (FanAction::Hold, state);
    }

    // Governing margin: whichever of core/memory is further over its own target.
    let core_over = core_temp - policy.target_temp;
    let (over, mem_governs) = match (policy.mem_target, mem_temp) {
        (Some(mt), Some(m)) if m - mt > core_over => (m - mt, true),
        _ => (core_over, false),
    };
    let deadband = if mem_governs {
        policy.deadband + 1
    } else {
        policy.deadband
    };

    // Overheat is a *core*-temperature safety (memory can legitimately run much
    // hotter, e.g. GDDR6X ~100°C+). Memory only drives the proportional fan via
    // `over`/`mem_governs` above; it never stops the task. Latch at/above
    // critical, release only after cooling by the recovery margin.
    let hot = core_temp >= policy.critical_temp;
    if hot || (state.overheated && core_temp > policy.critical_temp - RECOVER_MARGIN) {
        next.overheated = true;
        next.last_temp = Some(core_temp);
        next.last_fan = policy.max_fan;
        return (FanAction::Critical(policy.max_fan), next);
    }
    next.overheated = false;

    let first = state.last_temp.is_none();

    // Within the dead band (and not the first observation): hold.
    if !first && over.abs() <= deadband {
        next.last_temp = Some(core_temp);
        return (FanAction::Hold, next);
    }

    // Proportional setpoint: target → min_fan, critical → max_fan.
    let span = (policy.critical_temp - policy.target_temp).max(1);
    let gain = (policy.max_fan - policy.min_fan) as f32 / span as f32;
    let mut prop = policy.min_fan + (over as f32 * gain).round() as i32;

    // Trend damping: don't slow while heating (boost on a fast rise); don't
    // speed up while cooling.
    if let Some(prev) = state.last_temp {
        let rise = core_temp - prev;
        if rise > 0 && over > 0 {
            prop = prop.max(state.last_fan);
            if rise >= FAST_RISE {
                prop = (prop + 5).min(policy.max_fan);
            }
        } else if rise < 0 && over < 0 {
            prop = prop.min(state.last_fan);
        }
    }
    prop = prop.clamp(policy.min_fan, policy.max_fan);

    // Asymmetric slew: up is immediate, down is capped per tick.
    let new_fan = if prop < state.last_fan {
        prop.max(state.last_fan - policy.down_step)
    } else {
        prop
    }
    .clamp(policy.min_fan, policy.max_fan);

    next.last_temp = Some(core_temp);
    // Suppress redundant commands, but always emit on the first tick so manual
    // control actually gets established.
    if !first && (new_fan - state.last_fan).abs() <= 1 {
        return (FanAction::Hold, next);
    }
    next.last_fan = new_fan;
    (FanAction::Set(new_fan), next)
}

/// Drive every detected GPU's fans one controller tick. Updates `states` in
/// place and returns an overheat description if any GPU tripped critical (the
/// caller should then stop the task). Best-effort via `nvidia-settings`.
pub async fn drive_fans(
    gpus: &[Gpu],
    samples: &[AgentMetric],
    cfg: &FanConfig,
    states: &mut HashMap<u32, FanState>,
) -> Option<String> {
    let mut overheat = None;
    for g in gpus {
        let suffix = format!("[{}]", g.index);
        let s = match samples.iter().find(|s| s.name.ends_with(&suffix)) {
            Some(s) => s,
            None => continue,
        };
        let policy = policy_for(cfg, g.max_temp);
        let st = states
            .entry(g.index)
            .or_insert_with(|| FanState::new(if s.fan > 0 { s.fan } else { cfg.min_fan }));
        let (action, next) = decide_fan(&policy, *st, s.temp, None);
        *st = next;
        let pct = match action {
            FanAction::Hold => continue,
            FanAction::Set(p) => p,
            FanAction::Critical(p) => {
                overheat.get_or_insert_with(|| {
                    format!(
                        "GPU {} at {}°C >= critical {}°C",
                        g.index, s.temp, policy.critical_temp
                    )
                });
                p
            }
        };
        let mut args = vec![
            "-a".to_string(),
            format!("[gpu:{}]/GPUFanControlState=1", g.index),
        ];
        for fan in &g.fans {
            args.push("-a".to_string());
            args.push(format!("[fan:{fan}]/GPUTargetFanSpeed={pct}"));
        }
        nvidia_settings(&cfg.helper, &args).await;
    }
    overheat
}

/// Hand the fans back to the driver's automatic control (task finished).
pub async fn reset_fans(gpus: &[Gpu], cfg: &FanConfig) {
    for g in gpus {
        nvidia_settings(
            &cfg.helper,
            &[
                "-a".into(),
                format!("[gpu:{}]/GPUFanControlState=0", g.index),
            ],
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::{critical_for, decide_fan, parse_sample_line, FanAction, FanPolicy, FanState};
    #[cfg(unix)]
    use super::{fan_cmd_parts, parse_fan_handles};

    #[cfg(unix)]
    #[test]
    fn fan_cmd_applies_helper_prefix() {
        let a = vec!["-a".to_string(), "x".to_string()];
        assert_eq!(
            fan_cmd_parts(&[], &a),
            ("nvidia-settings".to_string(), vec!["-a".into(), "x".into()])
        );
        let helper = vec!["sudo".to_string(), "-n".to_string()];
        assert_eq!(
            fan_cmd_parts(&helper, &a),
            (
                "sudo".to_string(),
                vec![
                    "-n".into(),
                    "nvidia-settings".into(),
                    "-a".into(),
                    "x".into()
                ]
            )
        );
    }

    fn policy() -> FanPolicy {
        // target 75, critical 87 -> span 12; fan 30..100.
        FanPolicy {
            target_temp: 75,
            min_fan: 30,
            max_fan: 100,
            critical_temp: 87,
            deadband: 2,
            down_step: 5,
            mem_target: None,
        }
    }

    // Reach steady state at a temperature, so later ticks are not "first tick".
    fn primed(temp: i32, fan: i32) -> FanState {
        FanState {
            last_temp: Some(temp),
            last_fan: fan,
            overheated: false,
        }
    }

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
    fn holds_within_deadband() {
        // At target, primed: no change.
        let (a, _) = decide_fan(&policy(), primed(75, 40), 75, None);
        assert_eq!(a, FanAction::Hold);
    }

    #[test]
    fn first_tick_always_sets_to_establish_control() {
        // last_temp None -> must emit a Set even if within the dead band.
        let (a, st) = decide_fan(&policy(), FanState::new(30), 75, None);
        assert!(matches!(a, FanAction::Set(_)));
        assert_eq!(st.last_temp, Some(75));
    }

    #[test]
    fn ramps_up_above_target() {
        // Halfway to critical (81°C) should land mid-range, above min.
        let (a, _) = decide_fan(&policy(), primed(75, 30), 81, None);
        match a {
            FanAction::Set(p) => assert!(p > 40 && p < 100, "mid ramp was {p}"),
            other => panic!("expected Set, got {other:?}"),
        }
    }

    #[test]
    fn saturates_near_critical() {
        // One below critical (87): proportional + fast-rise boost pins it high.
        let (a, _) = decide_fan(&policy(), primed(80, 70), 86, None);
        match a {
            FanAction::Set(p) => assert!(p >= 95, "near-critical fan was {p}"),
            other => panic!("expected Set, got {other:?}"),
        }
    }

    #[test]
    fn down_step_limits_decrease() {
        // Over the dead band so it recomputes, but a big drop may only fall by
        // down_step (5) this tick: 90 -> 85, not straight to the proportional ~48.
        let (a, _) = decide_fan(&policy(), primed(85, 90), 78, None);
        assert_eq!(a, FanAction::Set(85));
    }

    #[test]
    fn up_is_immediate() {
        // Jump from cool to hot: fan goes straight up, not step-limited.
        let (a, _) = decide_fan(&policy(), primed(74, 30), 84, None);
        match a {
            FanAction::Set(p) => assert!(p >= 80, "expected a big jump, got {p}"),
            other => panic!("expected Set, got {other:?}"),
        }
    }

    #[test]
    fn rising_temp_prevents_slowdown() {
        // Over target but proportional would suggest ~min; rising trend clamps to last_fan.
        let (a, _) = decide_fan(&policy(), primed(76, 60), 78, None);
        match a {
            FanAction::Set(p) => assert!(p >= 60, "rising clamp failed: {p}"),
            FanAction::Hold => {} // holding at >=60 is also acceptable
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn critical_latches_and_recovers() {
        let p = policy();
        let (a, st) = decide_fan(&p, primed(85, 90), 88, None);
        assert_eq!(a, FanAction::Critical(100));
        assert!(st.overheated);
        // Still latched at 80 (critical 87 - recover 10 = 77; 80 > 77).
        let (a2, st2) = decide_fan(&p, st, 80, None);
        assert_eq!(a2, FanAction::Critical(100));
        assert!(st2.overheated);
        // Cooled to 76 (<= 77): releases.
        let (a3, st3) = decide_fan(&p, st2, 76, None);
        assert!(!st3.overheated);
        assert!(matches!(a3, FanAction::Set(_) | FanAction::Hold));
    }

    #[test]
    fn invalid_reading_holds_without_state_change() {
        let before = primed(70, 45);
        let (a, after) = decide_fan(&policy(), before, 130, None);
        assert_eq!(a, FanAction::Hold);
        assert_eq!(after.last_fan, before.last_fan);
        assert_eq!(after.last_temp, before.last_temp);
    }

    #[test]
    fn memory_governs_when_hotter() {
        let mut p = policy();
        p.mem_target = Some(95);
        // Core cool (60, under target) but memory at 104 -> should ramp up hard.
        let (a, _) = decide_fan(&p, primed(60, 30), 60, Some(104));
        match a {
            FanAction::Set(pct) => assert!(pct > 50, "mem governance weak: {pct}"),
            other => panic!("expected Set, got {other:?}"),
        }
    }

    #[test]
    fn critical_derivation() {
        assert_eq!(critical_for(90, 75, None), 87); // 90 - 3
        assert_eq!(critical_for(90, 75, Some(80)), 80); // override wins
        assert_eq!(critical_for(0, 75, None), 92); // unknown max -> (target + 20) - 3
    }

    #[cfg(unix)]
    #[test]
    fn parses_fan_handles() {
        assert_eq!(parse_fan_handles("[fan:0], [fan:1]"), vec![0, 1]);
        assert_eq!(parse_fan_handles("fan:2"), vec![2]);
        assert_eq!(parse_fan_handles("0, 1"), vec![0, 1]); // bare-integer fallback
        assert!(parse_fan_handles("none here").is_empty());
    }
}
