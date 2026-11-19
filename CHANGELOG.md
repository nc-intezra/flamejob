# Changelog

All notable changes to flamejob are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/nc-intezra/flamejob/releases/tag/v1.0.0
