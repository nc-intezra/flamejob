# Changelog

All notable changes to flamejob are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.3] - 2026-11-22

Job-ETA fixes and direct agent pinning.

### Fixed
- **Job ETA now shows a real countdown instead of "soon".** Three separate
  causes are addressed:
  - The agent dropped hashcat's estimate at the agent→server boundary
    (`AgentMsg::Progress` had no `eta` field). Progress now carries hashcat's
    `estimated_stop`, so the server can show an ETA even for an unknown-keyspace
    chunk it can't estimate from keyspace/speed itself.
  - `estimated_stop: 0` (hashcat's "no estimate yet") was mapped to the Unix
    epoch (1970) and rendered as a bogus past time. Non-positive values are now
    treated as "no estimate".
  - A finished/paused/cancelled job kept its last ETA, which was now in the past.
    `est_completion` is cleared whenever a job leaves the running state.
- ETA is now formatted as **HH:MM:SS** in both the Jobs list and the job detail.

### Added
- **Pin a job to a specific agent.** Superadmin/Admin can left-click a job name
  in the Jobs list to open a menu and pin the job to an agent (or set it back to
  "Auto / any agent"); the scheduler then runs that job's chunks only on the
  pinned agent (a pinned chunk waits for its agent rather than running elsewhere).
  - New column `jobs.pinned_agent_id` (migration `0005`, `ON DELETE SET NULL`).
  - `POST /jobs/{id}/pin` (body `{agent_id}`) and `DELETE /jobs/{id}/pin`, gated
    to the **ManageAgents** capability.
  - New config `scheduler.local_agent_name` (defaults to the machine hostname)
    names local-runner work in the agent display.
- **"Agent" column** in the Jobs list and an agent line in the job detail, for
  Superadmin/Admin/Operator — shows the pinned agent, or the agent(s)/local host
  currently running the job (single-agent and local-host fallbacks included).

### Changed
- **Admin** role now also holds the **ViewJobs** capability, so admins can see
  the job queue they pin to agents (an admin still cannot submit jobs). `/agents`
  now accepts ViewStats **or** ManageAgents so admins can list agents to pin to.



A dashboard reliability and layout release. It also rolls up two changes that
merged after v1.3.1 without a version bump of their own: the inline Ember "fj"
favicon (#32) and the Active Directory / LDAP integration design doc (#33).

### Fixed
- **Agent device metrics now stay live between jobs.** Agent-reported GPU
  telemetry (temperature, fan, P-state, clocks, hashrate) only streamed while a
  task was running, so after a job completed, paused, or was cancelled the
  dashboard left the agent's cards frozen on their last in-job sample. The agent
  now emits an idle telemetry heartbeat on a fixed interval whenever no task is
  running, mirroring the server's local collector, so agent-connected hardware
  tracks live the same way local hardware already did. Hashrate reads 0 while
  idle; under load, telemetry still streams alongside task progress (carrying
  per-card hashrate and driving fan control) and the heartbeat yields to it.
- **Submit panel no longer shows its own scrollbars at 100% in a windowed
  1080p browser.** The "Submit a job" and "Devices" regions were a touch too
  short in a normal (non-fullscreen) viewport; a fixed slice of height (about
  one select-field tall) now shifts from the "Jobs"/"Job detail" regions into
  them so the form fits without scrolling.

### Changed
- **Submit panel layout.** The hash-file drop zone now spans the full width at
  the top of the form, and the "Submit to agents" button sits beside the field
  grid with its top aligned to the "Job name" field, rather than running the
  full height of the panel alongside the drop zone.

### Added
- **`--metrics-interval-secs` / `FJ_AGENT_METRICS_INTERVAL_SECS`** (default 5) —
  how often the agent reports device telemetry while idle.
- Inline **Ember "fj" favicon** for the dashboard (#32): a scalable SVG with
  font-independent vector glyphs over the ember-gradient tile, plus 16×16 and
  32×32 PNG fallbacks, all inlined as data URIs (no external requests).

### Docs
- **Active Directory / LDAP integration design** (#33) — `docs/design/ad-ldap-integration.md`:
  LDAPS/StartTLS search-then-bind, objectSID-keyed group→role mapping,
  server-enforced per-agent pools/grants, and per-group fairness, framed as the
  Phase 5 rollout onto the current auth/scheduler code.

## [1.3.1] - 2026-11-22

Makes the v1.3.0 fan controller usable from an unprivileged agent, and stops it
failing silently.

### Added
- **`--fan-helper` / `FJ_AGENT_FAN_HELPER`** — a command prefix (e.g. `sudo -n`)
  that the agent runs `nvidia-settings` through, so an unprivileged agent can
  drive fans on a root-owned X server without running the whole agent as root.

### Changed
- When the driver refuses a fan command (*"Operation not permitted"* — which
  happens when the agent is neither root nor the X server's user), the agent now
  **logs a one-time warning** explaining the fix, instead of swallowing the error
  and leaving the fans on auto with no indication why.

### Docs
- Administrator guide §7: why fan control needs root or the X-server user, the
  two ways to grant it (run as root, or `sudo` + `FJ_AGENT_FAN_HELPER`), and a
  headless dedicated-Xorg recipe (Coolbits + per-GPU **virtual display**, needed
  because GeForce cards refuse fan control without an active display head).
- The packaged `agent.env` documents the privilege requirement and the helper.

## [1.3.0] - 2026-11-21

Replaces the agent's fan curve with a target-temperature closed-loop controller
and an overheat fail-safe.

### Changed
- **Closed-loop fan control.** With `--fan-control`, the agent now holds each
  GPU's core at a configurable target (default 75 °C) instead of chasing the old
  85–95 %-of-rated band. The controller adds a dead band, trend damping (ramp up
  fast, coast down slowly, boost on a fast rise), and an asymmetric slew limit —
  adapted clean-room from the HiveOS autofan approach. New agent flags:
  `--fan-target`, `--fan-min`, `--fan-max`, `--fan-critical`, `--fan-deadband`,
  `--fan-down-step`, and `--fan-mem-target` (with matching `FJ_AGENT_FAN_*`
  env vars).
- Multi-fan cards now have **every** fan driven, not just `[fan:<gpu-index>]`.

### Added
- **Overheat protection.** If a GPU reaches its critical temperature (default
  just below the rated slowdown temp), the agent maxes the fans, stops the task,
  and reports an error so the scheduler requeues the chunk elsewhere; it recovers
  once the card cools.
- A VRAM-aware control hook (`--fan-mem-target`) is wired into the controller but
  **inert** for now — `nvidia-smi` doesn't expose memory-junction temperature on
  most GeForce cards, which is exactly where it would matter.

## [1.2.0] - 2026-11-21

Adds revocable API keys for programmatic access, fixes per-GPU hashrate
attribution, ties the API's reported version to the release, and refines the
submit panel.

### Added
- **API keys.** Signed-in users can mint long-lived, revocable API keys from the
  web dashboard (click your username). Keys authenticate any request as
  `Authorization: Bearer fj_…` with the user's current roles, default to a
  1-year lifetime (selectable, including no-expiry), and are stored only as a
  SHA-256 hash — the secret is shown once at creation. New endpoints:
  `POST /auth/api-keys`, `GET /auth/api-keys`, `DELETE /auth/api-keys/{id}`
  (each scoped to the calling user). Revocation and expiry take effect
  immediately, and keys survive a JWT-secret rotation.

### Changed
- **Per-card hashrate.** hashcat's per-device speeds are now attributed to each
  GPU's device row instead of being summed onto the agent's CPU row. GPU rows
  show their own hashrate; the CPU row shows a hashrate only on CPU-only agents.
- **Submit panel.** "Submit to agents" is now a tall square button on the right
  of the panel, with the fields reflowed into the freed space to cut scrolling.
- **API version.** The OpenAPI document served at `/openapi.json` now reports the
  live crate version (so it tracks the release automatically) instead of a
  hand-maintained `1.0.0` literal that had drifted.

### Fixed
- Per-GPU hashrate previously showed `—` on every GPU row while the combined rate
  appeared on the remote agent's CPU row.

## [1.1.0] - 2026-11-21

Brings NVIDIA GPU telemetry and optional fan control to the agents, and reworks
the browser dashboard: hash-mode autodetection, clearer errors, a denser layout,
and an OLED-black theme with a themed flame wordmark.

### Added
- **NVIDIA GPU telemetry.** When `nvidia-smi` is on an agent's `PATH`, the agent
  now auto-detects its GPUs at startup and reports per-card temperature, fan
  speed, utilization, P-state, SM/memory clocks and power draw alongside its
  hashrate. Each GPU appears as its own device row named `{gpu-name}[{index}]`
  beside the host CPU, in both the TUI and web Devices panels. Opt out with
  `--no-gpu-metrics` (env `FJ_AGENT_NO_GPU_METRICS`).
- **GPU fan control (opt-in).** `--fan-control` (env `FJ_AGENT_FAN_CONTROL`,
  off by default) uses `nvidia-settings` to disable the driver's automatic fan
  control while a task runs and ramp each fan to hold the GPU inside 85–95 % of
  its rated (slowdown) temperature, handing control back to the driver when the
  task finishes. Best-effort: needs an X display and a Coolbits-permissive
  driver, and is a silent no-op where unsupported.
- **Fan column** in the TUI and web Devices tables.
- **Hash-mode autodetection.** Dropping a hash file into the web "Submit a job"
  panel now guesses the hashcat `-m` mode from the file's first line (bcrypt,
  sha-crypt variants, phpass, Kerberos, NetNTLMv2, NTLM pwdump, and bare hex by
  length) and preselects it, instead of leaving a wrong default to fail later.
- **OLED-black theme.** A third dashboard theme (true-black background, orange-
  fade text) joins dark and light; the theme button cycles all three and the
  choice persists. A theme-aware flame graphic sits behind the "flamejob"
  wordmark — orange-red on the dark/OLED themes, blue-to-purple on light.

### Changed
- **Denser submit + layout rework.** The "Submit a job" panel is now a compact
  two-column grid at half width; the Devices panel moves up beside it; and the
  job-detail ("Job — …") region is given roughly twice its former height.
- Clearer web submit/import errors: the dashboard now surfaces the server's
  problem detail (mapped to a short human message, full text on hover) and names
  the step that failed, rather than showing a generic error.

### Fixed
- GPU metrics other than CPU temperature/load and hashrate were never collected
  on the agent side; NVIDIA temperature, fan, and P-state (and the rest) now
  populate as intended.

## [1.0.6] - 2026-11-21

Runs many jobs across the agent fleet at once, adds browser job submission, live
agent status, and a cracked-password view, and raises the hash-import limit to
8 GiB.

### Added
- **Many jobs × many agents.** The scheduler now admits up to
  `[scheduler].max_concurrent_jobs` jobs (default 8) at once and distributes the
  whole fleet's chunk capacity across them — each tick it takes one pending
  chunk from every running job in priority order, round-robin, so several jobs
  run at once while a single job still fans across every agent. Each job is
  finalized independently.
- `[scheduler].max_concurrent_jobs` config key (and
  `FJ_SCHEDULER__MAX_CONCURRENT_JOBS`).
- **Web job submission.** Superadmin/Operator dashboards gain a "Submit a job"
  panel: drop a hash file, choose a hash-mode (`-m`) and a mask or wordlist
  attack, and it is queued to the agent pool (hashlist + import + job in one
  step).
- **Agent status taxonomy.** `GET /agents` now reports a live `status` —
  `online` (connected/usable), `away` (enrolled, not connected), `error`
  (reported an error, or revoked), or `busy` (a multi-slot agent that is fully
  loaded / near overloaded). The web dashboards and the TUI render it as a
  coloured dot with styled name: green bold, gray italic, red bold-underline,
  orange bold.
- **Cracked-password view.** The web job-detail panel gains a "Cracked" tab (for
  roles with `ViewPlaintext`) showing a scrollable hash → plaintext list.
- **TUI agents panel** showing connected agents with the status dots above.
- `JobView.hashlist_id` so clients can fetch a job's cracked results.

### Changed
- **Hash import limit raised to 8 GiB** (was axum's ~2 MB body default).
  `POST /hashlists/{id}/hashes` now streams the request body line-by-line and
  inserts in batched transactions, so large hashlists import without buffering
  the whole upload in memory — mirroring the wordlist upload change in 1.0.3.

## [1.0.5] - 2026-11-21

Adds a browser dashboard and a browseable OpenAPI reference, parallelises a
single job's chunks across the agent fleet, and adds a "clear finished jobs"
action with scrollable TUI tables.

### Added
- **Multi-agent job parallelism.** The scheduler now fans a single job's chunks
  across the whole fleet instead of running one chunk at a time. It keeps as many
  chunks in flight as there is capacity — the sum of agents' advertised free
  slots for the remote runner, or `[scheduler].local_parallelism` (default 1)
  hashcat processes for the local runner — via a new `Runner::capacity` method.
  Per-job progress and ETA aggregate across the running chunks, so adding agents
  speeds up a single job. One job still runs at a time.
- `[scheduler].local_parallelism` config key (and `FJ_SCHEDULER__LOCAL_PARALLELISM`).
- **Web dashboard.** A browser UI on its own listener (`[web]`, default `:9443`,
  plain HTTP or rustls TLS) mirroring the TUI: jobs, chunk breakdown, devices and
  agents, with the signed-in username, a log-out button and a light/dark theme
  toggle. Panels are capability-gated so each role sees the same metrics it can
  access. The API port now sends CORS headers so the browser can call it.
- **Browseable API reference** at `GET /docs` (RapiDoc) bound to `GET /openapi.json`;
  the OpenAPI document now describes every operation (paths + bearer security),
  not just the DTO schemas.
- **Clear finished jobs**: `POST /jobs/clear` (requires `SubmitJobs`) removes
  completed/exhausted/cancelled/error jobs and their tasks (cracked hashes kept).
  Exposed in the TUI (`C`) and the web dashboard; `ClearedJobs` DTO and
  `client.clear_finished_jobs()`.
- **TUI scrolling**: the jobs and chunk tables now scroll with a scrollbar when
  they overflow the pane, keeping the selection (and active chunks) in view. New
  keys: `f` hide/show finished jobs, `C` clear finished (operators/superadmin).

### Changed
- Job finalization is now idempotent (a guarded state transition), so concurrent
  chunk completions can't double-finalize or double-publish a job event.
- The TUI gates job controls by the signed-in user's capabilities (via `/auth/me`).

## [1.0.4] - 2026-11-21

Makes a plain `flamejob-agent` install produce a working worker (mirroring the
server packaging fix from 1.0.2), and exposes rule files on the CLI.

### Added
- **`fj job submit --rule <id|path>`** applies a rule file to a dictionary
  attack. Repeat the flag to apply several rule files in order; each value is an
  already-uploaded file id (UUID) or a path to a local rule file, which is
  uploaded for you (as kind `rule`). Rules are distributed to remote agents the
  same way wordlists are (see 1.0.3). Brute-force attacks are the mask attack
  (`-a 3`), already exposed as `--mask` since 1.0.3.

### Fixed
- **Agent `.deb` now sets up the worker, not just the binary.** It creates a
  `flamejob-agent` system user, creates `/var/lib/flamejob-agent` (with the
  `pki`, `jobs` and `cache` subdirs) owned by that user, writes a default
  `/etc/flamejob-agent/agent.env`, and installs and enables a systemd unit that
  runs the agent as the `flamejob-agent` user. Previously the data dir's
  ownership was left to chance, so an agent enrolled as root but run as another
  user hit `Permission denied` writing its hash/cache files (surfacing as
  `write hash file: Permission denied` and `keyspace file fetch failed`).
- **The agent fails fast with a clear message** when its data dir isn't writable,
  creating `pki`/`jobs`/`cache` up front and probing writability at startup
  instead of swallowing the error and failing later mid-job.

## [1.0.3] - 2026-11-21

Makes wordlist jobs work end to end, including in distributed mode.

### Added
- **Wordlist/rule distribution to agents.** In remote (distributed) mode the
  agent now fetches the wordlist and rule files a task needs from the control
  plane (`GET /agent/files/{id}`, authenticated by the agent's client
  certificate) and caches them under its data dir, then runs hashcat against the
  local copies. Wordlist attacks no longer require pre-staging files on each
  agent.
- `fj job submit --mask <mask>` submits a mask attack (`-a 3`). Masks travel
  inline to agents, so they need no file distribution.

### Fixed
- Uploading a real wordlist no longer fails with a broken pipe: the `/files`
  endpoint's request-body limit is lifted to 8 GiB and the upload is streamed to
  disk, so large wordlists (e.g. rockyou.txt) upload without being buffered in
  memory.

### Changed
- `fj job submit --wordlist` now accepts either an existing file id (UUID) or a
  path to a local wordlist file (which it uploads for you), instead of only a
  UUID; a value that is neither is rejected with a clear message.

### Documentation
- Synced the Administrator, Operator and Viewer guides to 1.0.3: removed the
  obsolete "wordlists must already be present on the agent" caveat and documented
  on-demand file distribution and the `GET /agent/files/{id}` endpoint; documented
  `fj job submit --mask` and the `--wordlist` id-or-path behaviour; and added a
  complete command/subcommand reference for every binary (`flamejobd`, `fj`,
  `flamejob-tui`, `fj-agent`) to the Administrator and Operator guides.

## [1.0.2] - 2026-11-20

Packaging fix so a plain install produces a working server.

### Fixed
- The `flamejob-server` `.deb` now installs a complete server, not just the
  binary: it ships the systemd unit and runs maintainer scripts that create the
  `flamejob` system user, generate the JWT and plaintext keys, write a default
  local config (only if absent, so upgrades and edits are preserved), and enable
  the service. `apt purge` removes the generated config and keys.
- `deploy/install.sh` now installs the binaries (building them if `cargo` is
  present, or exiting with guidance if not), creates the `flamejob` user, and
  installs and enables the systemd unit — previously it wrote config for a
  binary it never installed.
- The systemd unit's `ExecStart` now points at `/usr/bin/flamejobd`, matching
  where both the package and the installer place the binary (was
  `/usr/local/bin/flamejobd`).

### Changed
- The `flamejob-server` package now depends on `openssl` (used by the postinst
  to generate keys).

## [1.0.1] - 2026-11-20

Documentation and packaging release. No changes to the server, agent, CLI or TUI
runtime behavior.

### Added
- Role-based guides under `docs/guides/`: Administrator, Operator, and Viewer,
  including an end-to-end "Distributed quick start" (control plane → agent → TUI).

### Changed
- Release `.deb` packages are now built on Ubuntu 22.04 (glibc 2.35), so they
  install and run on Ubuntu 22.04 as well as newer releases (glibc is
  forward-compatible); `cargo-deb` stamps `libc6 (>= 2.35)`.
- `deploy/install.sh` now checks for PostgreSQL 16 after the database choice: it
  verifies an external DSN's server version or a local PG 16 install, and stops
  with guidance if 16 is not detected (override: `FLAMEJOB_SKIP_PG_CHECK=1`).

## [1.0.0] - 2026-11-19

First stable release: a single-control-plane hashcat job queue with server-side
chunking, a dashboard, GPU/host telemetry, and an optional distributed worker
fleet, all over one OpenAPI-described API.

### Added

#### Phase 1 — single-box core
- Cargo workspace: `flamejob-core` (domain model, job/task state machines, the
  `Runner` trait, Role/Capability), `flamejob-api` (OpenAPI DTOs), `flamejob-db`
  (Postgres pool + migrations), `flamejob-runner` (hashcat subprocess driver and
  `--status-json` parser), `flamejob-server` (`flamejobd`), `flamejob-client`,
  and `flamejob-cli` (`fj`).
- Postgres schema and migrations; JWT + Argon2 auth with capability-based RBAC
  (superadmin / admin / operator / viewer).
- Scheduler with runner process control and encryption of cracked plaintext.
- Server-side keyspace chunking: a job's `hashcat --keyspace` is split into
  `--skip`/`--limit` chunk tasks, with early finish once every hash is cracked.
- Ingest: SSE `GET /events`, multipart file upload, and hashlist hash-import.

#### Phase 2 — dashboard & telemetry
- `flamejob-tui`: a ratatui dashboard (jobs queue, per-job chunk breakdown,
  keyspace/ETA aggregate, devices panel) driven by the live API.
- Per-job ETA computed from remaining keyspace and current speed.
- Local device telemetry: GPU metrics via NVML (temperature, utilization,
  memory, P-state, power, fan, core and memory clocks; degrades gracefully with
  no NVIDIA/NVML present) and host CPU/RAM via `sysinfo`, on a configurable
  interval. Samples persist to `metric_samples`, the latest per device to
  `current_devices`; exposed at `GET /devices`, `GET /devices/{name}/history`,
  and as Prometheus gauges on `/metrics`.

#### Phase 3 — distributed agents
- `flamejob-agent` (`fj-agent`): a GPU worker node.
- mTLS-oriented enrollment: a persisted CA signs an agent CSR on
  `POST /agent/enroll` (gated by a one-time claim token minted via
  `POST /admin/agent-claims`; new `ManageAgents` capability).
- WebSocket task protocol (`WS /agent/stream`): agents authenticate with their
  issued certificate, pull chunk tasks, and push progress, cracked hashes and
  device telemetry.
- `RemoteRunner` implementing the core `Runner` trait, selected by
  `scheduler.runner = "remote"`, so the scheduler dispatches chunks to the agent
  fleet; `GET /agents` lists enrolled workers.

### Notes / known limitations
- Transport TLS for the agent socket is expected to be terminated by the
  deployment (rustls acceptor or reverse proxy); in-process the agent connection
  authenticates at the application layer by certificate fingerprint.
- The scheduler runs one job and one chunk at a time; multi-agent parallelism is
  not yet exploited.
- Wordlist/rule distribution to agents is not implemented — mask attacks are
  self-contained over the wire, while wordlist attacks assume the file is
  present on the agent.

[1.3.1]: https://github.com/nc-intezra/flamejob/releases/tag/v1.3.1
[1.3.0]: https://github.com/nc-intezra/flamejob/releases/tag/v1.3.0
[1.2.0]: https://github.com/nc-intezra/flamejob/releases/tag/v1.2.0
[1.1.0]: https://github.com/nc-intezra/flamejob/releases/tag/v1.1.0
[1.0.6]: https://github.com/nc-intezra/flamejob/releases/tag/v1.0.6
[1.0.5]: https://github.com/nc-intezra/flamejob/releases/tag/v1.0.5
[1.0.4]: https://github.com/nc-intezra/flamejob/releases/tag/v1.0.4
[1.0.3]: https://github.com/nc-intezra/flamejob/releases/tag/v1.0.3
[1.0.2]: https://github.com/nc-intezra/flamejob/releases/tag/v1.0.2
[1.0.1]: https://github.com/nc-intezra/flamejob/releases/tag/v1.0.1
[1.0.0]: https://github.com/nc-intezra/flamejob/releases/tag/v1.0.0
