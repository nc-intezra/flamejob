# Design draft: closed-loop GPU fan controller (v1.2.5)

**Status:** implemented in **v1.3.0** (this document is the design record; a few
names were refined during implementation — e.g. `Gpu.fans: Vec<u32>` rather than
a bare `fan_cnt`). Replaced v1.1.0's stateless `fan_target()` band with a
target-temperature closed loop, adapting the proven HiveOS `autofan` approach
(clean-room; no code copied) to flamejob's agent. Pairs with the findings in the
earlier GPU-fan-curve research.

## Why

Today `gpu::fan_target(max_temp, temp)` maps temperature into the **85–95 % of
rated-temp** band each sample, statelessly. The research flagged three gaps:
it targets a fraction of the *ceiling* (≈71–79 °C, hotter than the ~65–75 °C
longevity sweet spot), it has **no hysteresis** (oscillation risk), and it's
**VRAM-blind**. This design fixes the first two outright and leaves a clean hook
for the third.

It also fixes a latent bug: `apply_fan_curve` writes `[fan:{gpu.index}]`, i.e. it
assumes fan index == GPU index and only ever sets one fan. Multi-fan cards (3090
FE etc.) need every fan `0..fan_cnt` of that GPU driven.

## Scope

- Replace the stateless curve with a **stateful per-GPU closed loop** in the
  agent, still gated behind the existing opt-in `--fan-control`.
- Absolute temperature target + hysteresis + trend damping + slew-limited
  decreases + an overheat fail-safe mapped to flamejob semantics.
- Per-fan addressing (`fan_cnt`).
- VRAM-aware control as an **optional** path (best-effort; see caveat).
- Pure, unit-tested decision function; all I/O stays in the async wrappers.

Out of scope for 1.2.5: reboot/shutdown-on-overheat, undervolt/power-limit
control, a per-GPU config file (flags + sane defaults only).

## Configuration

Extend the agent `Args` (clap + env), keeping the surface small. All temps °C,
fans %. These apply only when `--fan-control` is set.

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--fan-control` | `FJ_AGENT_FAN_CONTROL` | off | Master switch (unchanged). |
| `--fan-target` | `FJ_AGENT_FAN_TARGET` | `75` | Core temp to hold. |
| `--fan-min` | `FJ_AGENT_FAN_MIN` | `30` | Fan floor (driver often enforces ~30 anyway). |
| `--fan-max` | `FJ_AGENT_FAN_MAX` | `100` | Fan ceiling. |
| `--fan-critical` | `FJ_AGENT_FAN_CRITICAL` | per-GPU (below) | Overheat trip. |
| `--fan-mem-target` | `FJ_AGENT_FAN_MEM_TARGET` | unset (disabled) | VRAM target if memory temp is readable. |

Internal constants (not flags unless a reason emerges): `DEADBAND = 2`,
`DOWN_STEP = 5` (max % decrease per tick), `RECOVER_MARGIN = 10`, `FAST_RISE = 3`
(°C/tick that earns a boost), `MIN_DIFF = 10`.

`--fan-critical` default is derived per GPU from its rated slowdown temp
(`Gpu.max_temp`): `critical = clamp(max_temp - 3, target + MIN_DIFF, max_temp)`.
So on a card rated 90 °C with target 75, critical ≈ 87.

## Types and signature (pure core)

```rust
/// Tunables for the fan loop. One set per agent; copied into the decision fn.
#[derive(Clone, Copy, Debug)]
pub struct FanPolicy {
    pub target_temp: i32,      // 75
    pub min_fan: i32,          // 30
    pub max_fan: i32,          // 100
    pub critical_temp: i32,    // derived per GPU
    pub deadband: i32,         // 2
    pub down_step: i32,        // 5
    pub recover_margin: i32,   // 10
    pub mem_target: Option<i32>, // None = ignore VRAM temp
}

/// Per-GPU memory carried across ticks (one entry per GPU index).
#[derive(Clone, Copy, Debug)]
pub struct FanState {
    pub last_temp: Option<i32>, // previous governing temp, for trend
    pub last_fan: i32,          // last commanded %
    pub overheated: bool,       // latched until recovery
}

/// The controller's decision for one GPU this tick.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FanAction {
    Set(i32),       // command this %
    Hold,           // within deadband / < ~1% change — issue no nvidia-settings call
    Critical(i32),  // >= critical: command this % (max) AND caller pauses task + marks agent
}

/// Pure, no I/O: given policy, prior state and this tick's reading, decide the
/// new fan command and the next state. `mem_temp` is the NVIDIA memory-junction
/// temperature when available, else None.
pub fn decide_fan(
    policy: &FanPolicy,
    state: FanState,
    core_temp: i32,
    mem_temp: Option<i32>,
) -> (FanAction, FanState);
```

## Algorithm (inside `decide_fan`)

1. **Reject bad readings.** `core_temp <= 0 || core_temp > 120` → `(Hold, state
   unchanged)` (driver glitch; HiveOS treats >120 as invalid).
2. **Governing temp & target.** If `mem_target` set and `mem_temp` present, pick
   whichever is more "over" its own target:
   `over = max(core_temp - target_temp, mem_temp - mem_target)`, and remember
   which governed (affects deadband: mem uses ±(deadband+1), per autofan).
   Otherwise `over = core_temp - target_temp`.
3. **Overheat.** If `core_temp >= critical_temp` (or `mem_temp >= critical` when
   mem governs): return `Critical(max_fan)`, set `overheated = true`. If already
   `overheated`, stay overheated until `core_temp <= critical_temp -
   recover_margin`, then clear and resume normal control this tick.
4. **Deadband.** If `over.abs() <= deadband` → `Hold` (keep `last_fan`).
5. **Proportional setpoint** (linear map target→min_fan, critical→max_fan):
   `gain = (max_fan - min_fan) / (critical_temp - target_temp)`;
   `prop = clamp(min_fan + over * gain, min_fan, max_fan)`.
6. **Trend damping** (needs `last_temp`): let `rise = core_temp - last_temp`.
   - Rising & over>0: `prop = max(prop, last_fan)` (never slow down while
     heating); if `rise >= FAST_RISE`, `prop = min(prop + 5, max_fan)`.
   - Falling & over<0: `prop = min(prop, last_fan)` (never speed up while
     cooling).
7. **Slew limit (asymmetric).** Up is immediate; down is capped:
   `new = if prop < last_fan { max(prop, last_fan - down_step) } else { prop }`,
   then clamp to `[min_fan, max_fan]`.
8. **Emit.** If `|new - last_fan| <= 1` → `Hold` (avoid redundant calls); else
   `Set(new)`. Update state: `last_temp = Some(core_temp)`, `last_fan = new`
   (or unchanged on Hold), `overheated = false`.

This is "thermostat with hysteresis + rate-limited cool-down," which is what
makes autofan stable under constant load; it holds `target_temp` precisely
without hunting.

## State handling & integration

- `FanState` lives in a `HashMap<u32, FanState>` (keyed by `Gpu.index`), created
  once in `run_task` **outside** the `while rx.recv()` loop, so it persists
  across the per-status-update ticks that already drive sampling. Initial state:
  `last_temp: None, last_fan: current fan reading or min_fan, overheated: false`.
- The loop already samples GPUs each tick (`gpu::sample`). Replace the
  `apply_fan_curve` call with a stateful `drive_fans(&gpus, &samples, &policy,
  &mut states).await` that, per GPU: finds its sample, calls `decide_fan`,
  applies the action, and stores the new state.
- **Cadence.** Ticks fire per hashcat status update (`rx.recv()`), typically a
  few seconds apart. The slew limit is per-tick, so if updates are very frequent
  the cool-down just happens in smaller steps — acceptable. If we see thrash,
  add a `min_interval` guard (skip driving if <N s since last drive). Flagged as
  a tuning knob, not built initially.
- **Per-fan addressing (bug fix).** `drive_fans` sets
  `[gpu:{i}]/GPUFanControlState=1` once, then
  `[fan:{f}]/GPUTargetFanSpeed={pct}` for every fan `f` belonging to that GPU.
  Needs each GPU's `fan_cnt`; `detect()` gains a `fan_cnt` field (from
  `nvidia-settings -q [gpu:i]/Fans` or the fans query), defaulting to 1.
- **Reset.** `reset_fans` (restore `GPUFanControlState=0`) stays as-is, called
  when the task ends; state map is dropped with the task.

## Overheat semantics (flamejob, not HiveOS)

On `Critical`: command `max_fan`, log a warning, and — instead of HiveOS's
`miner stop`/reboot — **pause the running task and emit `AgentMsg::Error`** so
the control plane marks the agent (the error/“errored” path from v1.0.6 already
exists). Resume the task when `decide_fan` clears `overheated`. Rebooting or
shutting down the host is deliberately *not* a default. hashcat's own
`--hwmon-temp-abort` remains a backstop underneath all of this.

## VRAM-aware caveat

`mem_target` only helps if the agent can read memory-junction temperature.
`nvidia-smi --query-gpu=temperature.memory` exists but is **unsupported on most
GeForce cards** (returns `[N/A]`), which is exactly the 3080/3090 case the
research cares about. So this path is wired in the signature and control math but
will be inert on the very cards that need it until we get the sensor another way.
Recommendation: ship the hook, default it **off**, and treat a real GDDR6X fix as
its own investigation rather than claiming it here.

## Tests (pure `decide_fan`, no hardware)

1. `holds_within_deadband` — `core == target` → `Hold`, state temp updated.
2. `ramps_proportionally` — `core == target + span/2` → `Set(~mid)`.
3. `saturates_at_critical_span` — `core` near critical → `Set(max_fan)`.
4. `down_step_limited` — big temp drop → fan falls by at most `down_step`/tick.
5. `up_is_immediate` — big temp spike → fan jumps straight up (no step cap).
6. `rising_temp_prevents_slowdown` — rising trend clamps `prop` to `last_fan`.
7. `falling_temp_prevents_speedup` — falling trend clamps `prop` to `last_fan`.
8. `fast_rise_boost` — `rise >= FAST_RISE` adds the boost, capped at `max_fan`.
9. `critical_latches_and_recovers` — `>= critical` → `Critical`; stays until
   `<= critical - recover_margin`, then clears.
10. `invalid_reading_holds` — `core > 120` or `<= 0` → `Hold`, state unchanged.
11. `mem_governs_when_hotter` — cool core, hot mem (with `mem_target`) → ramps on
    the memory margin; `None` mem leaves core in control.
12. `clamps_to_min_max` — results never leave `[min_fan, max_fan]`.
13. `no_op_emits_hold` — sub-1% change → `Hold` (no redundant nvidia-settings).

Plus one small integration-ish test that `drive_fans` issues per-fan writes for a
`fan_cnt > 1` GPU (can assert on the arg vector via a seam, without real
hardware).

## Migration

- `gpu.rs`: delete `fan_target`; add `FanPolicy`/`FanState`/`FanAction`/
  `decide_fan` + `drive_fans`; add `fan_cnt` to `Gpu` and `detect`.
- `main.rs`: new flags → build one `FanPolicy` (critical derived per GPU);
  create the state map before the metrics loop; swap `apply_fan_curve` for
  `drive_fans`; handle `Critical` by pausing + `AgentMsg::Error`.
- Docs: admin guide fan section gains the new flags + the overheat behavior;
  CHANGELOG `[1.2.5]`.

## Open questions for review

1. **Default target 75 °C** — comfortable longevity pick; want it lower (70) or
   card-relative instead of absolute?
2. **Overheat = pause task.** Agreed that pause + agent-error is the right action
   (vs. just maxing fans and letting hashcat's abort handle it)?
3. **VRAM hook** — ship it inert now, or leave it out entirely until we have a
   sensor that works on GeForce?
4. **Config surface** — expose `deadband`/`down_step` as flags, or keep internal?
5. **Version** — strictly this is a feature (→ 1.3.0 by semver); keep your 1.2.5
   numbering or bump minor?
