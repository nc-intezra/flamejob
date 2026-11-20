# flamejob Administrator Guide

> **Skeleton** — section structure from the documentation architecture plan.
> Prose to be written next. Each section below notes its intended content.
> Audience: the `superadmin` and `admin` roles, plus whoever deploys and runs
> the control plane and worker fleet.

## 1. Introduction & audience

_Who it's for (superadmin, admin, deployers); a one-paragraph description of flamejob; how this guide relates to the Operator and Viewer guides; product version (1.0.0)._

## 2. Concepts primer

_Component/trust-model view: the binaries and crates, control plane + Postgres + optional agents, local vs remote runner, and the trust model (CA, agent certs, JWT, Argon2) — enough to orient an administrator._

## 3. Architecture overview

_Components and binaries (`flamejobd`, `fj`, `fj-agent`, TUI) and the crate map; control-plane + Postgres + optional agent fleet (diagram); data flow (submit → keyspace chunking → run local or remote → ingest results/SSE → metrics)._

## 4. Deployment & installation

_Prerequisites (Linux, hashcat, optional NVIDIA/NVML, Postgres 16). Three install paths: Docker Compose (eval/dev), native via `install.sh` + the systemd unit, and the container image (Dockerfile). Database choice: `local` vs `external` DSN. First boot: migrations auto-run; `/healthz`. Break-glass superadmin seeding via `FJ_BOOTSTRAP_PASSWORD` (or the random password logged on first run)._

## 5. Configuration reference

_File location (`/etc/flamejob/flamejob.toml`, override with `FLAMEJOB_CONFIG`) and precedence (defaults → TOML → `FJ_`-prefixed env with `__` nesting). Full key reference by section: `[server]`, `[database]`, `[auth]`, `[hashcat]`, `[crypto]`, `[scheduler]` (incl. `runner`, `chunk_size`, `max_chunks`), `[telemetry]`. Call out keys present in the defaults but absent from the shipped example file (e.g. `[scheduler].runner`, `[telemetry]`)._

## 6. Identity, roles & access control

_The role → capability matrix (superadmin / admin / operator / viewer × the eight capabilities). Auth model: JWT (HS256) + Argon2, token TTL. Creating users (`POST /admin/users`, assigning roles) — requires `ManageUsers`. Break-glass superadmin: purpose, when to use, how to rotate. Least-privilege notes (admins cannot submit jobs). Directory / LDAP-AD RBAC flagged as roadmap._

## 7. Managing the agent fleet (distributed mode)

_When to switch to `runner = "remote"`. Enrollment end to end: mint a one-time claim token (`POST /admin/agent-claims`, requires `ManageAgents`) → `fj-agent` generates key + CSR → server CA signs → agent opens `WS /agent/stream` and authenticates by certificate fingerprint. Deploying `fj-agent`: flags/env (`--server`, `--name`, `--claim-token`, `--data-dir`, `--hashcat`, `--workload`) and its `pki/` material. Listing/monitoring agents (`GET /agents`; statuses enrolled/online/offline/revoked). Transport-TLS note (terminate with rustls or a reverse proxy). Failure handling (orphaned tasks re-queued on disconnect). Known limits: one job / one chunk at a time; wordlist/rule files are not distributed to agents._

## 8. Telemetry, metrics & monitoring

_Local collector (NVML GPU; degrades to host CPU/RAM via `sysinfo`) and `[telemetry]` tuning (`enabled`, `sample_interval_secs`, `history_limit`). Snapshot/history endpoints (`GET /devices`, `GET /devices/{name}/history`). Prometheus `/metrics` and wiring into Prometheus/Zabbix/Grafana. How agent-reported telemetry merges into the same snapshot._

## 9. Data security & cryptography

_Cracked-plaintext encryption at rest (`plaintext_key_file`) and how `ViewPlaintext` gates decryption. JWT secret handling (`jwt.key`). PKI material under `{data_dir}/pki`. What to back up and protect._

## 10. Operations & maintenance

_Service management (systemd), logs and levels (`FJ_LOG` / tracing). Migrations (0001–0003) and upgrades. Backup/restore (Postgres, key files, `data_dir/files`). Health/readiness. Scaling and current single-scheduler limits._

## 11. Troubleshooting

_Server won't boot / DB connection / unix socket path length. Agent won't enroll or connect (claim token used, cert not enrolled, TLS). No devices appear (NVML absent). Auth failures / token TTL._

## 12. Reference & appendices

_Full REST API reference (all endpoints, auth, request/response DTOs) + pointer to `/openapi.json`. Capability reference. Config env-var map. Glossary. Links to in-workspace design docs (ADR + build spec) and the roadmap._
