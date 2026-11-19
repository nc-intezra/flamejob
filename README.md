# flamejob

Distributed hashcat job queue with a web UI, a TUI, and a CLI over one
OpenAPI-described API, GPU/CPU telemetry, LDAP/AD-aware RBAC, and metrics
export for Prometheus/Zabbix/Grafana.

This repository currently holds the **Phase 1** scaffold: a single-box core.
Design docs (architecture decision record and the Phase 1 build spec) live in
the project workspace.

## Status

Phase 1 — single-box core. Compiling scaffold of the workspace, schema,
runner, API server, and `fj` CLI. Full behaviour is in progress per the build
checklist in the Phase 1 spec.

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

## Roles (Phase 1 RBAC)

- **superadmin** (local break-glass): everything, incl. modify any job
- **admin**: manage users and roles; cannot run jobs
- **operator**: run/view jobs, ingest, view decrypted plaintext and stats
- **viewer**: view jobs in progress and metrics

## Build

```bash
cargo check --workspace
cargo test --workspace
```

License: MIT
