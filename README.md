# flamejob

Distributed hashcat job queue with a web UI, a TUI, and a CLI over one
OpenAPI-described API, GPU/CPU telemetry, LDAP/AD-aware RBAC, and metrics
export for Prometheus/Zabbix/Grafana.

Design docs (architecture decision record and the build spec) live in the
project workspace.

## Status

**1.5.0** — current release. The Phase 1 single-box core (scheduler, keyspace
chunking, ingest/SSE, RBAC), Phase 2 TUI/web dashboards + GPU/host telemetry,
and Phase 3 distributed agents (enrollment, WebSocket task protocol, remote
runner) are all in place, plus the work layered on since 1.0.0:

- **API-key authentication** (`fj_…` bearer tokens, same roles as the user) for
  CLI and scripting, managed from the web UI.
- **GPU fan control** on Linux agents and per-device hashrate in telemetry.
- **Observed-rate job ETAs** (progress-rate EMA rather than raw keyspace/speed).
- **Direct job→agent pinning** — run a job's chunks on a chosen worker.
- **Windows GPU worker agent** (NVIDIA; MSI + native Windows service), same
  binary and version as the Linux agent.
- **Web dashboard**: live queue, a completed-jobs history tab that keeps cracked
  results reachable after a job is cleared, device grouping by host, job submit,
  agent enrollment, and user/key administration.

See [CHANGELOG.md](CHANGELOG.md) for the full history.

## Workspace

| Crate | Purpose |
| --- | --- |
| `flamejob-core` | domain model, job/task state machines, `Runner` trait, Role/Capability |
| `flamejob-api` | OpenAPI DTOs (utoipa), the single wire contract |
| `flamejob-db` | Postgres pool, migrations, row models (sqlx) |
| `flamejob-runner` | hashcat subprocess driver + `--status-json` parser |
| `flamejob-server` | `flamejobd` — axum server, auth, scheduler, routes |
| `flamejob-client` | typed async HTTP client |
| `flamejob-cli` | `fj` — the command-line client |
| `flamejob-tui` | ratatui dashboard |
| `flamejob-agent` | `fj-agent` — distributed GPU worker node (Phase 3) |

## Quick start (dev)

```bash
# bring up Postgres + the server
docker compose -f deploy/docker-compose.yml up --build

# or run locally against a Postgres you provide
export FJ_DATABASE__DSN=postgres://flamejob@localhost/flamejob
cargo run --bin flamejobd

# use the CLI
cargo run --bin fj -- --server http://localhost:8443 job ls
```

The OpenAPI document is served at `/openapi.json`, health at `/healthz`,
Prometheus metrics at `/metrics`.

## Telemetry (Phase 2)

`flamejobd` samples local GPU metrics via NVML (temp, utilization, memory,
P-state, power, fan, core/memory clock; it degrades to host CPU/RAM only when
no NVIDIA/NVML is present) and host CPU/RAM via `sysinfo` on a configurable
interval. Samples are appended to `metric_samples`, the latest per device is
kept in `current_devices`, and gauges are exported on `/metrics`. Read the
current snapshot at `GET /devices` and per-device history at
`GET /devices/{name}/history`. Configure under `[telemetry]`:
`enabled`, `sample_interval_secs`, `history_limit`.

## Distributed agents (Phase 3)

Set `scheduler.runner = "remote"` to dispatch chunk tasks to enrolled worker
nodes instead of running hashcat on the control-plane box.

```bash
# 1. mint a one-time enrollment token (needs ManageAgents)
fj ... # or: curl -XPOST /admin/agent-claims -d '{"name":"gpu-box-1"}'

# 2. start a worker; it enrolls (CSR -> CA-signed client cert) then connects
fj-agent --server http://control-plane:8099 --name gpu-box-1 \
         --claim-token <token> --hashcat /usr/bin/hashcat
```

Agents run on **Linux** (`.deb`, systemd) and **Windows** (NVIDIA; MSI + a native
Windows service) from the same binary and version. For a Windows worker see
[docs/guides/windows-agent.md](docs/guides/windows-agent.md). Active GPU fan
control is Linux-only; Windows reports GPU telemetry but leaves fans to the
driver.

Enrollment (`POST /agent/enroll`) signs the agent's CSR with the server CA
(persisted under `{data_dir}/pki`) and returns the issued client certificate.
Agents then open `WS /agent/stream`, authenticate by presenting that
certificate (matched by fingerprint against the `agents` table), pull chunk
tasks, and push progress, cracked hashes and device telemetry. The scheduler
dispatches through a `RemoteRunner` that implements the same `Runner` trait as
the local hashcat runner, so chunking and ETA logic are unchanged.

> Transport note: the issued certificates are intended for mutual TLS. In this
> build the agent socket authenticates at the application layer (certificate
> fingerprint) and transport TLS is expected to be terminated by the deployment
> (a rustls acceptor or reverse proxy). `GET /agents` lists enrolled workers.

## Roles (RBAC)

- **superadmin** (local break-glass): everything, incl. modify any job
- **admin**: manage users, roles and agents; view jobs; cannot run jobs
- **operator**: run/view jobs, ingest, view decrypted plaintext and stats
- **viewer**: view jobs in progress and metrics

Capabilities (`ManageUsers`, `SubmitJobs`, `Ingest`, `ViewPlaintext`,
`ViewStats`, `ViewJobs`, `ManageDirectory`, `ManageAgents`) are resolved live
from a user's roles on every request; handlers gate on the capability, not the
role name.

## Build

```bash
cargo check --workspace
cargo test --workspace
```
