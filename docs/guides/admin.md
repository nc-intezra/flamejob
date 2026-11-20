# flamejob Administrator Guide

## 1. Introduction & audience

flamejob is a distributed hashcat job queue. A single control-plane service, `flamejobd`, holds the queue, splits each job across its keyspace, runs or dispatches the work, and exposes everything through one OpenAPI-described HTTP API. People reach it through the `fj` command-line client and a terminal dashboard (`flamejob-tui`); optional `fj-agent` worker nodes let the control plane farm cracking out to a fleet of GPU machines.

This guide is for the people who stand that system up and keep it running: the **superadmin** (the local break-glass account) and **admin** roles, plus anyone responsible for deployment, configuration, user and agent management, and monitoring. Running and watching jobs day to day is covered separately in the **Operator Guide** and the **Viewer Guide**.

It documents flamejob **1.0.0**. A web UI and directory-mapped (LDAP/AD) RBAC are on the roadmap but are not part of this release; where they come up, they are flagged as planned.

## 2. Concepts primer

flamejob is one Cargo workspace. At runtime it is a few binaries:

- **`flamejobd`** — the control plane: an axum HTTP server that owns the queue, the scheduler, authentication, and the API.
- **`fj`** — the command-line client used to log in, submit and control jobs, and manage hashlists and files.
- **`flamejob-tui`** — a read-only terminal dashboard that polls the API.
- **`fj-agent`** — an optional GPU worker node that runs the hashcat chunks the control plane dispatches to it.

Behind them are library crates you will see named in logs and configuration: `flamejob-core` (domain model, state machines, the `Runner` trait, roles and capabilities), `flamejob-api` (the OpenAPI DTOs — the single wire contract), `flamejob-db` (the Postgres pool and migrations), `flamejob-runner` (the hashcat subprocess driver), and `flamejob-client` (the typed HTTP client shared by the CLI and TUI).

All state lives in one PostgreSQL database. Cracking is performed by hashcat, invoked either locally by `flamejobd` or remotely by an `fj-agent` — a single configuration switch decides which (see §7).

**The runner.** A job's work runs through a `Runner`. The *local* runner spawns hashcat as a subprocess on the control-plane box; the *remote* runner dispatches the same chunks to enrolled agents over a WebSocket. Both satisfy the same interface, so keyspace chunking and ETA behave identically either way.

**Trust.** Three mechanisms matter. User requests carry a JWT (HS256) issued at login and signed with the server's `jwt_secret`; passwords are stored as Argon2 hashes. Agents authenticate with a client certificate: the control plane runs a small internal certificate authority that signs each agent's certificate at enrollment, and recognises the agent thereafter by that certificate's fingerprint. Cracked plaintext is encrypted at rest with a separate key. All three are detailed later (§6, §7, §9).

## 3. Architecture overview

**Components.** A deployment is the `flamejobd` control plane, its PostgreSQL database, and — in distributed mode — one or more `fj-agent` workers. Clients (`fj`, the TUI, anything speaking the API) talk only to `flamejobd`.

**The life of a job.**

1. A client creates a hashlist, imports hashes into it, and uploads any wordlist / rule / mask files.
2. A client submits a job against that hashlist (attack mode, optional wordlist, priority). The job enters the queue as `queued`.
3. The scheduler asks hashcat for the job's keyspace (`hashcat --keyspace`) and splits it into chunk tasks of `chunk_size` keyspace units each, capped at `max_chunks`. An unknown or zero keyspace becomes a single full-keyspace task.
4. Each chunk runs as a hashcat invocation with `--skip` / `--limit`, locally or on an agent. Progress, speed, recovered counts, cracked hashes and device telemetry stream back as it runs.
5. Recovered plaintext is encrypted and stored. The job finishes `completed` — or early, as soon as every hash is cracked — and can also end `exhausted`, `cancelled` or `error`.

**How you observe it.** Live job and task events are published on `GET /events` (SSE). Device and host metrics are readable at `GET /devices` and exported for Prometheus at `GET /metrics`. The full endpoint list is in §12.

*A component-and-flow diagram will be added in the design pass.*

## 4. Deployment & installation

**Prerequisites.** A Linux host (the installer targets Ubuntu/Debian), `hashcat` on `PATH`, and PostgreSQL 16. For GPU telemetry you also need the NVIDIA driver — the installer warns if `nvidia-smi` is missing; without it, flamejob still runs and reports host CPU/RAM only.

There are three ways to run the control plane.

**Docker Compose (quickest, for evaluation).** `deploy/docker-compose.yml` brings up PostgreSQL 16 and builds and runs `flamejobd`:

```
docker compose -f deploy/docker-compose.yml up --build
```

It wires the database and server together through `FJ_`-prefixed environment variables and publishes the API on `:8443`. The compose file sets `FJ_AUTH__JWT_SECRET` to a placeholder — change it before any real use.

**Native install + systemd (for a persistent deployment).** Run the interactive installer:

```
sudo deploy/install.sh
```

It checks for `hashcat` and `nvidia-smi`, asks whether PostgreSQL is `local` or `external` (taking a DSN for external), records the directory type (reserved for the LDAP/AD roadmap — local auth is used until then), generates `jwt.key` and `plain.key` under `/etc/flamejob`, and writes `/etc/flamejob/flamejob.toml`. Then install the service unit and start it:

```
sudo cp deploy/flamejob-server.service /etc/systemd/system/
sudo systemctl enable --now flamejob-server
```

The unit runs `flamejobd` as the `flamejob` user with `FLAMEJOB_CONFIG=/etc/flamejob/flamejob.toml`, and restarts on failure.

**Container image.** The `Dockerfile` builds a release `flamejobd` and runs it on `:8443` — use it if you deploy your own orchestration against an external database.

**First boot.** `flamejobd` runs its database migrations on startup, then serves. Confirm it is up with `GET /healthz` (returns `ok`).

**Seeding the superadmin.** On the very first boot, when the `users` table is empty, flamejob seeds a break-glass local account named `superadmin`. Set its password by exporting `FJ_BOOTSTRAP_PASSWORD` before that first start; if you don't, a random password is generated and written to the server log (at warn level) exactly once. Capture it, log in, and create real accounts (§6).

## 5. Configuration reference

flamejob reads configuration from three layers, in increasing precedence: built-in defaults, a TOML file, then environment variables. The TOML path is `/etc/flamejob/flamejob.toml` by default, overridable with the `FLAMEJOB_CONFIG` environment variable. Environment overrides use the `FJ_` prefix with `__` (double underscore) separating nested keys — so `[database].dsn` becomes `FJ_DATABASE__DSN` and `[auth].jwt_secret` becomes `FJ_AUTH__JWT_SECRET`.

| Section | Key | Default | Purpose |
| --- | --- | --- | --- |
| `[server]` | `bind` | `0.0.0.0:8443` | Listen address. |
| `[database]` | `mode` | `local` | `local` = installer manages Postgres here; `external` = use `dsn`. |
| `[database]` | `dsn` | `postgres://flamejob@localhost/flamejob` | Postgres connection string. |
| `[database]` | `max_connections` | `10` | Connection-pool size. |
| `[auth]` | `jwt_secret` | `dev-insecure-change-me` | HS256 signing secret. **Must be changed.** |
| `[auth]` | `token_ttl_hours` | `1` | Login-token lifetime (minimum 1). |
| `[hashcat]` | `binary` | `/usr/bin/hashcat` | hashcat executable. |
| `[hashcat]` | `data_dir` | `/var/lib/flamejob` | Working data: uploaded files, PKI, job scratch. |
| `[hashcat]` | `workload` | `3` | hashcat workload profile (1–4). |
| `[crypto]` | `plaintext_key_file` | *(none)* | Key file for encrypting cracked plaintext. |
| `[scheduler]` | `chunk_size` | `50000000` | Keyspace units per chunk; `0` / unknown = one task. |
| `[scheduler]` | `max_chunks` | `500` | Upper bound on chunks per job. |
| `[scheduler]` | `runner` | `local` | `local` = hashcat here; `remote` = dispatch to agents. |
| `[telemetry]` | `enabled` | `true` | Run the local GPU/host collector. |
| `[telemetry]` | `sample_interval_secs` | `5` | Seconds between samples. |
| `[telemetry]` | `history_limit` | `500` | Max rows returned by the device-history endpoint. |

**Watch for these.** The shipped `deploy/flamejob.toml.example` and `install.sh` don't write every section — notably `[scheduler].runner` and the entire `[telemetry]` block are absent. That is harmless, because the defaults above fill them in, but it means distributed mode and telemetry tuning are enabled by adding those keys yourself (or via `FJ_` env vars). Always replace the default `jwt_secret`, and point `[crypto].plaintext_key_file` at a real key so cracked plaintext is encrypted at rest (§9).

## 6. Identity, roles & access control

flamejob authorizes by **capability**, not by role directly: each API route requires a specific capability, and roles are bundles of capabilities. That indirection lets the role-to-capability mapping change without touching route handlers.

| Capability | Superadmin | Admin | Operator | Viewer |
| --- | :---: | :---: | :---: | :---: |
| `ManageUsers` | ✓ | ✓ | | |
| `ManageAgents` | ✓ | ✓ | | |
| `ManageDirectory` | ✓ | | | |
| `SubmitJobs` | ✓ | | ✓ | |
| `Ingest` | ✓ | | ✓ | |
| `ViewPlaintext` | ✓ | | ✓ | |
| `ViewStats` | ✓ | | ✓ | ✓ |
| `ViewJobs` | ✓ | | ✓ | ✓ |

In practice: **admins manage people and agents but cannot run jobs or read cracked plaintext**; **operators run and inspect jobs but cannot manage users or the fleet**; **viewers are read-only**; the **superadmin** holds everything.

**How auth works.** A client logs in at `POST /auth/login` with a username and password, verified against an Argon2 hash. On success the server issues a JWT (HS256) signed with `[auth].jwt_secret`, carrying the user's id, username and roles and valid for `[auth].token_ttl_hours`. Clients send it as a `Bearer` token; `GET /auth/me` echoes the current identity and roles.

**Creating users.** `POST /admin/users` (requires `ManageUsers`) takes a username, a password and a list of roles and creates a local account. The `fj` CLI handles login and identity (`fj login`, `fj whoami`) but does not wrap user creation — call the endpoint directly (for example with `curl` and an admin token) or from your own tooling.

**The break-glass superadmin.** The `superadmin` seeded on first boot (§4) is a local account for bootstrapping and emergencies. Once it exists, log in as it and create named admin and operator accounts rather than sharing it. Version 1.0.0 ships account *creation* but not a password-change or disable endpoint, so rotating the superadmin password — or disabling any account — is a database operation today (the `users` table carries a `disabled` flag that login honours). Treat that as the current rotation path until later releases add self-service.

**Directory integration (roadmap).** The `ManageDirectory` capability and the installer's directory prompt are placeholders for planned LDAP/AD-mapped RBAC (Phase 5). Until then, all roles come from the local `user_roles` table.

## 7. Managing the agent fleet (distributed mode)

By default the scheduler runs hashcat locally (`[scheduler].runner = "local"`). Set `runner = "remote"` to dispatch chunk tasks to a fleet of enrolled `fj-agent` workers instead. The control plane schedules exactly as before — chunking, ETA and early-finish are unchanged — but each chunk executes on an agent.

**Enrolling an agent** is a one-time, token-gated certificate exchange:

1. On the control plane, mint a one-time claim token (requires `ManageAgents`): `POST /admin/agent-claims` with `{"name": "gpu-box-1"}`. The response contains a `claim_token`.
2. On the worker, start `fj-agent` with that token. On first run it generates a keypair and CSR, calls `POST /agent/enroll` with the claim token and CSR, and the server's CA signs and returns a client certificate. The agent stores the certificate and key under `{data_dir}/pki` (`agent.pem`, `agent.key.pem`, `ca.pem`):

```
fj-agent --server http://control-plane:8443 --name gpu-box-1 \
         --claim-token <token> --hashcat /usr/bin/hashcat
```

The claim token is single-use — it is consumed on enrollment and a second attempt is rejected.

3. Thereafter the agent opens `WS /agent/stream`, presents its certificate, and is matched by fingerprint against the `agents` table. Once welcomed it advertises its free slots and begins pulling chunk tasks.

**`fj-agent` options.** Each flag has an environment-variable equivalent:

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--server` | `FJ_AGENT_SERVER` | `http://127.0.0.1:8099` | Control-plane base URL — point at your `flamejobd`. |
| `--name` | `FJ_AGENT_NAME` | `agent` | Human-readable agent name. |
| `--claim-token` | `FJ_AGENT_CLAIM_TOKEN` | — | One-time enrollment token (first run only). |
| `--data-dir` | `FJ_AGENT_DATA_DIR` | `/var/lib/flamejob-agent` | Certificate/key and scratch storage. |
| `--hashcat` | `FJ_AGENT_HASHCAT` | `/usr/bin/hashcat` | hashcat binary on the worker. |
| `--workload` | `FJ_AGENT_WORKLOAD` | `3` | hashcat workload profile (1–4). |

Log verbosity is set with `FJ_LOG`. Note the agent's default `--server` port (`8099`) differs from the control plane's default bind (`8443`) — always set `--server` to the address and port your `flamejobd` actually listens on.

**Monitoring the fleet.** `GET /agents` (requires `ViewStats`) lists enrolled workers with status and timestamps. Status moves through `enrolled` (certificate issued, never connected), `online` (connected now), `offline` (disconnected), and `revoked` (certificate refused at connect).

**Transport security.** The issued certificates are intended for mutual TLS, but in 1.0.0 the agent WebSocket authenticates at the *application* layer — by certificate fingerprint — and does not itself terminate transport TLS. For anything beyond a trusted network, terminate TLS in front of `flamejobd` with a rustls acceptor or a reverse proxy.

**Resilience and limits.** If an agent disconnects mid-task, the control plane fails its in-flight chunks so the scheduler can retry them. Two limits to plan around in this release: the scheduler runs **one job and one chunk at a time** (it does not yet fan a single job across many agents in parallel), and **wordlist/rule files are not shipped to agents** — mask attacks are self-contained over the wire, but a wordlist attack assumes the wordlist already exists on the agent.

## 8. Telemetry, metrics & monitoring

`flamejobd` runs a local telemetry collector that samples device and host metrics on an interval, persists them, and exports them for scraping. It reads NVIDIA GPUs via NVML — temperature, utilisation, memory, P-state, power, fan, and core and memory clocks — and host CPU/RAM via `sysinfo`. With no NVIDIA/NVML present it degrades gracefully to host CPU/RAM only.

Tune it under `[telemetry]`: `enabled` turns the collector on or off, `sample_interval_secs` sets the cadence (default 5s), and `history_limit` caps how many rows the history endpoint returns.

Samples are appended to `metric_samples`; the latest per device is kept in `current_devices`. Read them through the API:

- `GET /devices` (requires `ViewStats`) — the current snapshot, one row per device.
- `GET /devices/{name}/history` (requires `ViewStats`) — recent samples for one device, newest first, bounded by `history_limit`.

For dashboards and alerting, `GET /metrics` exposes the same figures as Prometheus gauges — scrape it from Prometheus, Zabbix or Grafana.

When agents are connected (§7) they push their own device telemetry up the WebSocket, and it lands in the same `current_devices` snapshot. So `GET /devices` and `/metrics` show the whole fleet — local and remote GPUs — in one place.

## 9. Data security & cryptography

**Cracked plaintext.** Recovered plaintext is encrypted before it is written to the database and decrypted only when read back through `GET /hashlists/{id}/cracked`, which requires `ViewPlaintext`. The key comes from `[crypto].plaintext_key_file`; the installer generates one (`/etc/flamejob/plain.key`, 32 random bytes). If that key is unset, plaintext cannot be protected at rest — always configure it in production.

**Login tokens.** JWTs are signed with `[auth].jwt_secret` (the installer writes `/etc/flamejob/jwt.key`). Keep it secret and stable: changing it invalidates every outstanding token, and the built-in default (`dev-insecure-change-me`) must never reach production.

**Agent PKI.** The control plane's certificate authority — the key and certificate it uses to sign agent certificates — is persisted under `{data_dir}/pki` (that is, under `[hashcat].data_dir`, `/var/lib/flamejob` by default). Each agent holds its own issued certificate and key under its own `{data_dir}/pki`.

**What to protect and back up.** Treat three things as secrets with tight file permissions: `jwt.key`, `plain.key`, and the CA material under the server's `pki/`. Losing the plaintext key makes existing cracked results unreadable; losing the CA means re-enrolling every agent. Back all three up alongside the database (§10).

## 10. Operations & maintenance

**Service control.** Under the systemd unit, manage `flamejobd` with `systemctl status|restart|stop flamejob-server`. It runs as the `flamejob` user and reads its configuration from `FLAMEJOB_CONFIG`.

**Logs.** The server logs through `tracing`; set the level with the `FJ_LOG` environment variable (e.g. `FJ_LOG=debug`). Remember that the one-time break-glass password is emitted here, at warn level, on first boot.

**Migrations and upgrades.** The schema is managed by the bundled migrations — `0001_init`, `0002_telemetry`, `0003_agents` — which run automatically when `flamejobd` starts. To upgrade, deploy the new binary and restart; any new migrations apply on boot. There is no separate migrate step to run.

**Backup and restore.** Back up the PostgreSQL database (e.g. `pg_dump`) together with the key material in `/etc/flamejob` (`jwt.key`, `plain.key`) and the server's `data_dir` — which holds the `pki/` CA and uploaded `files/`. Restoring the database without those keys leaves tokens and cracked plaintext unusable.

**Health and readiness.** `GET /healthz` returns `ok` when the process is serving. `GET /metrics`, `GET /agents` and `GET /devices` are useful deeper liveness probes once the system is in use.

**Scaling and current limits.** Version 1.0.0 is a single control plane with a single scheduler that processes one job and one chunk at a time; it does not yet parallelise one job across many agents. Uploaded wordlists, rules and masks live on the control plane's `data_dir` and are not distributed to agents (§7). Plan capacity with those constraints in mind.

## 11. Troubleshooting

**Server won't start.** Check the database first: the DSN, that PostgreSQL 16 is running and reachable, and that `max_connections` isn't exhausted. Because the server also runs migrations on first boot, a schema or permission error shows up here. One specific gotcha: a `local` Postgres whose unix socket path exceeds the 107-byte limit fails to connect — use a short data/socket path (this bites when running from a deep scratch directory).

**An agent won't enroll.** `POST /agent/enroll` returns *invalid or used claim token* when the token was already consumed or never existed — claim tokens are single-use, so mint a fresh one with `POST /admin/agent-claims`. A CSR error points to a mismatched or broken `fj-agent` build.

**An agent enrolls but won't connect.** On `WS /agent/stream` the server rejects a Hello whose certificate fingerprint isn't in the `agents` table, or whose agent is `revoked` (*certificate not enrolled*). Also check the URL scheme: the agent derives `ws://` from an `http://` server URL and `wss://` from `https://`, so with a TLS-terminating proxy in front the agent should point at the `https://` address.

**No devices appear.** If `GET /devices` is empty: confirm `[telemetry].enabled` is true; expect host-only rows (no GPU fields) when NVML/NVIDIA isn't present; and note that right after a fresh start — before the first sample is persisted — the snapshot falls back to an in-memory view.

**Auth failures.** A `401` with *invalid credentials* means a bad username/password or a disabled account. An otherwise-valid token that stops working has usually expired (`token_ttl_hours`) — log in again. If *every* token suddenly fails after a restart, `jwt_secret` changed between runs.

## 12. Reference & appendices

**REST API.** Every route and the capability it requires. The authoritative, always-current contract is the OpenAPI document at `GET /openapi.json`.

| Method & path | Capability |
| --- | --- |
| `GET /healthz` | none |
| `GET /metrics` | none |
| `GET /openapi.json` | none |
| `POST /auth/login` | none |
| `GET /auth/me` | any authenticated |
| `GET /jobs` | `ViewJobs` |
| `POST /jobs` | `SubmitJobs` |
| `GET /jobs/{id}` | `ViewJobs` |
| `PATCH /jobs/{id}` | `SubmitJobs` |
| `GET /jobs/{id}/tasks` | `ViewJobs` |
| `POST /jobs/{id}/pause` | `SubmitJobs` |
| `POST /jobs/{id}/resume` | `SubmitJobs` |
| `POST /jobs/{id}/cancel` | `SubmitJobs` |
| `GET /hashlists` | `ViewJobs` |
| `POST /hashlists` | `Ingest` |
| `GET /hashlists/{id}/cracked` | `ViewPlaintext` |
| `POST /hashlists/{id}/hashes` | `Ingest` |
| `GET /files` | `ViewJobs` |
| `POST /files` | `Ingest` |
| `DELETE /files/{id}` | `Ingest` |
| `GET /events` | `ViewJobs` |
| `GET /devices` | `ViewStats` |
| `GET /devices/{name}/history` | `ViewStats` |
| `GET /agents` | `ViewStats` |
| `POST /admin/agent-claims` | `ManageAgents` |
| `POST /agent/enroll` | none (claim-token gated) |
| `GET /agent/stream` | agent certificate (WebSocket) |
| `POST /admin/users` | `ManageUsers` |

**Capabilities.** `ManageUsers`, `ManageAgents`, `ManageDirectory` (roadmap), `SubmitJobs`, `Ingest`, `ViewPlaintext`, `ViewStats`, `ViewJobs` — see the role matrix in §6.

**Job states.** `queued` → `assigned` → `running`, with `paused` (resumable), and terminal states `completed`, `exhausted`, `cancelled`, `error`. Task states: `pending`, `running`, `paused`, `done`, `failed`.

**Config environment map.** Any key maps to `FJ_<SECTION>__<KEY>` (uppercase, `__` between levels): e.g. `FJ_SERVER__BIND`, `FJ_DATABASE__DSN`, `FJ_AUTH__JWT_SECRET`, `FJ_SCHEDULER__RUNNER`, `FJ_TELEMETRY__ENABLED`. See §5.

**Further reading.** The architecture decision record and build spec live in the project workspace. Roadmap items not in 1.0.0: the web UI, and LDAP/AD-mapped RBAC (Phase 4/5).
