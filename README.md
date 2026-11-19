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
