# flamejob Administrator Guide

## 1. Introduction & audience

flamejob is a distributed hashcat job queue. A single control-plane service, `flamejobd`, holds the queue, splits each job across its keyspace, runs or dispatches the work, and exposes everything through one OpenAPI-described HTTP API. People reach it through the `fj` command-line client and a terminal dashboard (`flamejob-tui`); optional `fj-agent` worker nodes let the control plane farm cracking out to a fleet of GPU machines.

This guide is for the people who stand that system up and keep it running: the **superadmin** (the local break-glass account) and **admin** roles, plus anyone responsible for deployment, configuration, user and agent management, and monitoring. Running and watching jobs day to day is covered separately in the **Operator Guide** and the **Viewer Guide**.

It documents flamejob **1.0.5**, which adds a browser dashboard (§13) and multi-agent job parallelism. Directory-mapped (LDAP/AD) RBAC remains on the roadmap and is flagged as planned where it comes up.

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

**Prerequisites.** A Linux host — the packages and installer target **Ubuntu 22.04 or newer** — with `hashcat` on `PATH` and **PostgreSQL 16**. Ubuntu 22.04's own archive ships PostgreSQL 14, so for a local database on 22.04 add the PGDG repo (`apt.postgresql.org`) and install `postgresql-16`, or point at an external 16+ server. For GPU telemetry you also need the NVIDIA driver — without it flamejob still runs and reports host CPU/RAM only.

There are four ways to run flamejob; the `.deb` packages are the recommended path.

**Debian packages (recommended).** Each GitHub release attaches four `.deb`s, one per tool: `flamejob-server`, `flamejob-cli` (`fj`), `flamejob-tui`, and `flamejob-agent` (`fj-agent`). Install the ones a host needs with `apt` (use `./` and `apt`, not `dpkg -i`, so dependencies resolve):

```
# control-plane host
sudo apt install ./flamejob-server_1.0.5-1_amd64.deb \
                 ./flamejob-cli_1.0.5-1_amd64.deb \
                 ./flamejob-tui_1.0.5-1_amd64.deb
# a GPU worker
sudo apt install ./flamejob-agent_1.0.5-1_amd64.deb
```

Installing `flamejob-server` sets up a complete server: it creates the `flamejob` system user, generates `jwt.key` and `plain.key`, writes a default **local-mode** `/etc/flamejob/flamejob.toml` (only if one isn't already present, so upgrades keep your edits), installs the systemd unit, and **enables** the service. It does not *start* it — the database must be reachable first (see First boot). Edit the config for an external database or the remote runner before starting. `apt purge flamejob-server` removes the generated config and keys.

Installing `flamejob-agent` (on a worker) likewise sets up the worker: it creates the `flamejob-agent` system user, creates `/var/lib/flamejob-agent` (owned by that user, with the `pki`/`jobs`/`cache` subdirs the agent writes into), writes a default `/etc/flamejob-agent/agent.env`, and installs and **enables** a systemd unit that runs the agent as that user. It does not *start* it — set the control-plane URL and a one-time claim token in `agent.env` first (see §7), and ensure `hashcat` is installed on the worker. `apt purge flamejob-agent` removes the generated `agent.env`. The `flamejob-cli` and `flamejob-tui` packages simply place their binary on `PATH`.

**Docker Compose (quickest, for evaluation).** `deploy/docker-compose.yml` brings up PostgreSQL 16 and builds and runs `flamejobd`:

```
docker compose -f deploy/docker-compose.yml up --build
```

It wires the database and server together through `FJ_`-prefixed environment variables and publishes the API on `:8443`. The compose file sets `FJ_AUTH__JWT_SECRET` to a placeholder — change it before any real use.

**Native install from source + systemd.** From a source checkout, the interactive installer does the whole job — binaries, config, and service:

```
sudo deploy/install.sh
```

It checks for `hashcat`/`nvidia-smi`; creates the `flamejob` user; builds the binaries if they aren't already installed (this needs the Rust toolchain) and installs them to `/usr/bin`; asks whether PostgreSQL is `local` or `external`; **requires PostgreSQL 16** — it verifies an external DSN's server version or a local PG 16 install and stops with guidance if it can't confirm one (override with `FLAMEJOB_SKIP_PG_CHECK=1`); records the directory type (reserved for the LDAP/AD roadmap); generates the keys; writes `/etc/flamejob/flamejob.toml`; and installs and enables the systemd unit. Like the package, it enables but does not *start* the service. The unit runs `flamejobd` as the `flamejob` user with `FLAMEJOB_CONFIG=/etc/flamejob/flamejob.toml` and restarts on failure.

**Container image.** The `Dockerfile` builds a release `flamejobd` and runs it on `:8443` — use it if you deploy your own orchestration against an external database.

**First boot.** Once the database is reachable, start the service: `sudo systemctl start flamejob-server`. `flamejobd` runs its migrations on startup, then serves. Confirm it is up with `GET /healthz` (returns `ok`).

**Seeding the superadmin.** On the very first boot, when the `users` table is empty, flamejob seeds a break-glass local account named `superadmin`. To set its password, export `FJ_BOOTSTRAP_PASSWORD` before that first start — for the systemd service, add it to the unit's environment (or run `flamejobd` by hand once). Otherwise a random password is generated and written to the log at warn level exactly once; capture it with `journalctl -u flamejob-server`, log in, and create real accounts (§6).

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
| `[scheduler]` | `local_parallelism` | `1` | Concurrent hashcat processes for the active job on the **local** runner. The remote runner instead fans across the fleet's free slots. |
| `[telemetry]` | `enabled` | `true` | Run the local GPU/host collector. |
| `[telemetry]` | `sample_interval_secs` | `5` | Seconds between samples. |
| `[telemetry]` | `history_limit` | `500` | Max rows returned by the device-history endpoint. |
| `[web]` | `enabled` | `true` | Serve the browser dashboard (§13). |
| `[web]` | `bind` | `0.0.0.0:9443` | Dashboard listen address. |
| `[web]` | `tls_cert` / `tls_key` | *(none)* | PEM cert + key; both set ⇒ HTTPS, else plain HTTP. |
| `[web]` | `api_base` | *(none)* | API URL the browser calls; unset ⇒ derived from the page host and API port. |
| `[web]` | `theme` | `dark` | Default dashboard theme (`dark` / `light`). |
| `[web]` | `allowed_origins` | *(any)* | CORS origins allowed to call the API; empty = any. |

**Watch for these.** The shipped `deploy/flamejob.toml.example` and `install.sh` don't write every section — notably `[scheduler].runner` and the entire `[telemetry]` block are absent. That is harmless, because the defaults above fill them in, but it means distributed mode and telemetry tuning are enabled by adding those keys yourself (or via `FJ_` env vars). The `flamejob-server` package is the exception: its postinst writes a default config that already sets `[scheduler].runner = "local"` and points `[crypto].plaintext_key_file` at the generated key. Always replace the default `jwt_secret`, and point `[crypto].plaintext_key_file` at a real key so cracked plaintext is encrypted at rest (§9).

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

**The break-glass superadmin.** The `superadmin` seeded on first boot (§4) is a local account for bootstrapping and emergencies. Once it exists, log in as it and create named admin and operator accounts rather than sharing it. Version 1.0.5 ships account *creation* but not a password-change or disable endpoint, so rotating the superadmin password — or disabling any account — is a database operation today (the `users` table carries a `disabled` flag that login honours). Treat that as the current rotation path until later releases add self-service.

**Directory integration (roadmap).** The `ManageDirectory` capability and the installer's directory prompt are placeholders for planned LDAP/AD-mapped RBAC (Phase 5). Until then, all roles come from the local `user_roles` table.

## 7. Managing the agent fleet (distributed mode)

By default the scheduler runs hashcat locally (`[scheduler].runner = "local"`). Set `runner = "remote"` to dispatch chunk tasks to a fleet of enrolled `fj-agent` workers instead. The control plane schedules exactly as before — chunking, ETA and early-finish are unchanged — but each chunk executes on an agent. The active job's chunks run in parallel across the fleet: the scheduler keeps one chunk in flight for every free slot the connected agents advertise, so a job gets faster as you add agents. Each agent advertises one slot (runs one chunk at a time); scale throughput by enrolling more agents.

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

**Transport security.** The issued certificates are intended for mutual TLS, but in 1.0.5 the agent WebSocket (`/agent/stream`) and the agent file-download endpoint (`/agent/files/{id}`) both authenticate at the *application* layer — by certificate fingerprint — and do not themselves terminate transport TLS. For anything beyond a trusted network, terminate TLS in front of `flamejobd` with a rustls acceptor or a reverse proxy.

**File distribution.** As of 1.0.3 the control plane distributes wordlist and rule files to agents automatically. When a chunk task references a wordlist or rule (by file id), the agent fetches it from the control plane over `GET /agent/files/{id}` — authenticated with the same client certificate it uses on the WebSocket — and caches it under `{data_dir}/cache/{id}`, re-using the cached copy on later tasks. Mask attacks carry the mask string inline and need no download. So a wordlist attack in remote mode no longer requires pre-staging files on each agent; the first agent to run a chunk pulls the file on demand.

**Resilience and limits.** If an agent disconnects mid-task, the control plane fails its in-flight chunks so the scheduler can retry them. The scheduler runs **one job at a time but fans that job's chunks across the whole fleet in parallel** — it keeps as many chunks in flight as the connected agents advertise free slots, so adding agents speeds up a single job (per-job progress and ETA aggregate across the running chunks). It does not yet run several *different* jobs concurrently. One other limit to plan around: **hybrid attacks (`-a 6`/`-a 7`, wordlist + mask together) are not fully wired** — pure wordlist (`-a 0`) and pure mask (`-a 3`) attacks are the supported paths.

### Distributed quick start

A complete control plane + agent + dashboard bring-up, tying together the pieces above.

**1. Control plane (remote mode).** With Postgres 16 and hashcat in place, start `flamejobd` with the remote runner and a seeded superadmin:

```
export FJ_DATABASE__DSN='postgres://flamejob@localhost/flamejob'
export FJ_AUTH__JWT_SECRET='<a real secret>'
export FJ_SCHEDULER__RUNNER=remote
export FJ_BOOTSTRAP_PASSWORD='<superadmin password>'
flamejobd        # migrations run, superadmin seeded, listening on :8443
```

Check that `curl -s http://localhost:8443/healthz` returns `ok`.

**2. Log in and mint a one-time claim token** (needs `ManageAgents`; the superadmin has it). Claim minting isn't an `fj` subcommand, so use the cached token:

```
export FJ_SERVER=http://control-plane:8443
fj login --user superadmin --password '<superadmin password>'
TOKEN=$(cat ~/.config/flamejob/token)
curl -s -X POST http://control-plane:8443/admin/agent-claims \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"name":"gpu-box-1"}'          # -> { "claim_token": "<token>", ... }
```

**3. Start the agent (GPU box).** First run enrolls with the claim token (the CA signs its cert, stored under `--data-dir/pki`), then opens the WebSocket. Override `--server` — the agent defaults to port 8099:

```
fj-agent --server http://control-plane:8443 --name gpu-box-1 \
         --claim-token <token> --hashcat /usr/bin/hashcat
```

The token is single-use; later restarts reconnect with the stored cert (drop `--claim-token`). Verify with `GET /agents` (status `online`) or `GET /devices`.

**4. Submit work.**

```
fj hashlist create --name demo -m 1000        # -> <hashlist-id>
fj hashlist import <hashlist-id> hashes.txt
fj job submit --hashlist <hashlist-id> --name demo-run --attack-mode 0 --wordlist rockyou.txt
```

`--wordlist` accepts either an already-uploaded file id (UUID) or a path to a local wordlist, which `fj` uploads for you; here the local `rockyou.txt` is uploaded and its id used. The scheduler chunks the keyspace and dispatches chunks to the agent, which fetches the wordlist from the control plane on first use (§7, *File distribution*) — no pre-staging needed. A mask attack instead takes `--mask` (e.g. `--mask '?a?a?a?a'` with `--attack-mode 3`) and carries the mask inline.

**5. Watch it.** Run `FJ_SERVER=http://control-plane:8443 flamejob-tui` — the job shows its per-chunk progress and ETA, and the agent's GPUs appear in the devices panel.

This example uses plain `http://`; for anything off a trusted network, front `flamejobd` with TLS and point agents and clients at the `https://` address (see *Transport security* above).

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

**Scaling and current limits.** flamejob is a single control plane with a single scheduler. It processes one job at a time but parallelises that job across the fleet, keeping one chunk in flight per advertised agent slot; on the local runner, `[scheduler].local_parallelism` sets how many hashcat processes run at once (default 1). It does not yet run several different jobs concurrently. Uploaded wordlists and rules live on the control plane's `data_dir` and are distributed to agents on demand — each agent fetches and caches the files a chunk needs (§7, *File distribution*). Hybrid attacks (`-a 6`/`-a 7`) are not fully wired yet. Plan capacity with those constraints in mind.

## 11. Troubleshooting

**Server won't start.** Check the database first: the DSN, that PostgreSQL 16 is running and reachable, and that `max_connections` isn't exhausted. Because the server also runs migrations on first boot, a schema or permission error shows up here. One specific gotcha: a `local` Postgres whose unix socket path exceeds the 107-byte limit fails to connect — use a short data/socket path (this bites when running from a deep scratch directory).

**An agent won't enroll.** `POST /agent/enroll` returns *invalid or used claim token* when the token was already consumed or never existed — claim tokens are single-use, so mint a fresh one with `POST /admin/agent-claims`. A CSR error points to a mismatched or broken `fj-agent` build.

**An agent enrolls but won't connect.** On `WS /agent/stream` the server rejects a Hello whose certificate fingerprint isn't in the `agents` table, or whose agent is `revoked` (*certificate not enrolled*). Also check the URL scheme: the agent derives `ws://` from an `http://` server URL and `wss://` from `https://`, so with a TLS-terminating proxy in front the agent should point at the `https://` address.

**No devices appear.** If `GET /devices` is empty: confirm `[telemetry].enabled` is true; expect host-only rows (no GPU fields) when NVML/NVIDIA isn't present; and note that right after a fresh start — before the first sample is persisted — the snapshot falls back to an in-memory view.

**Auth failures.** A `401` with *invalid credentials* means a bad username/password or a disabled account. An otherwise-valid token that stops working has usually expired (`token_ttl_hours`) — log in again. If *every* token suddenly fails after a restart, `jwt_secret` changed between runs.

## 12. Reference & appendices

### Command-line reference (all tools)

flamejob ships four executables. `flamejobd`, `flamejob-tui` and `fj-agent` take no subcommands and are driven by flags and environment variables; `fj` is the subcommand-based client. Every documented flag and variable below is exhaustive for 1.0.5 — if a capability isn't listed here, it isn't exposed on the CLI yet.

#### `flamejobd` — control-plane server

Takes **no arguments or subcommands**. All behaviour comes from configuration (built-in defaults → TOML file → `FJ_` environment overrides; see §5). On start it loads config, connects to Postgres, runs migrations, seeds the superadmin on an empty database, and serves. Run it as `flamejobd` (the systemd unit does this as the `flamejob` user).

| Variable | Purpose |
| --- | --- |
| `FLAMEJOB_CONFIG` | Path to the TOML config. Default `/etc/flamejob/flamejob.toml`. |
| `FJ_<SECTION>__<KEY>` | Override any config key, e.g. `FJ_SCHEDULER__RUNNER=remote` (see §5). |
| `FJ_BOOTSTRAP_PASSWORD` | Password for the `superadmin` seeded on first boot. If unset, a random one is logged once at warn level. |
| `FJ_LOG` | Log level/filter (e.g. `info`, `debug`, `flamejob=debug`). Default `info`. |

#### `fj` — command-line client

**Global flags** (valid on every subcommand): `--server <url>` (env `FJ_SERVER`, default `http://localhost:8443`) and `--json` (emit raw JSON instead of formatted text). The login token is cached at `~/.config/flamejob/token` and reused by later commands and the TUI.

**Identity**

| Command | Required args / flags | Capability | Does |
| --- | --- | --- | --- |
| `fj login` | `--user <name>` `--password <pw>` | none | Authenticate; cache the token; print roles. |
| `fj whoami` | — | authenticated | Print the current username and roles. |
| `fj logout` | — | none | Delete the cached token. |

**Jobs** (`fj job <sub>`)

| Command | Args / flags | Capability | Does |
| --- | --- | --- | --- |
| `fj job ls` | — | `ViewJobs` | List jobs: id, name, state, priority. |
| `fj job show` | `<id>` | `ViewJobs` | Full job detail (always JSON). |
| `fj job submit` | `--hashlist <id>` `--name <n>` `[-a, --attack-mode <int>=0]` `[--wordlist <id\|path>]` `[--rule <id\|path>]…` `[--mask <str>]` `[--priority <int>=100]` | `SubmitJobs` | Create a job; print its id. See flag notes below. |
| `fj job pause` | `<id>` | `SubmitJobs` | Pause a running job (resumable). |
| `fj job resume` | `<id>` | `SubmitJobs` | Return a paused job to the queue. |
| `fj job cancel` | `<id>` | `SubmitJobs` | Cancel a job (terminal). |
| `fj job prio` | `<id> <priority>` | `SubmitJobs` | Re-prioritise a job (lower runs first). |
| `fj job watch` | `<id>` | `ViewJobs` | Follow that job's events over SSE until Ctrl-C. |

`fj job submit` flag notes:
- `--hashlist <id>` *(required)* — the target hashlist's UUID.
- `--name <n>` *(required)* — a human-readable job name.
- `-a, --attack-mode <int>` — hashcat's `-a` value; default `0` (dictionary). `3` is mask.
- `--wordlist <id|path>` — **either** an already-uploaded file id (UUID) **or** a path to a local wordlist file, which `fj` uploads for you (as kind `wordlist`) and then references. A value that is neither a known UUID nor an existing file is rejected. Omit for attacks that need no wordlist.
- `--mask <str>` — a hashcat mask (e.g. `?a?a?a?a`) for a mask / brute-force attack; pair with `-a 3`. Masks travel inline to agents, so they need no file distribution.
- `--rule <id|path>` — a rule file for a dictionary attack (`-a 0`): an uploaded file id (UUID) or a local path, uploaded for you as kind `rule`. Repeatable — pass `--rule` several times to apply rule files in order. Rules are distributed to remote agents like wordlists (§7, *File distribution*).
- `--priority <int>` — queue order, lower first; default `100`.
- *Not exposed as a flag in 1.0.5:* raw extra hashcat arguments exist in the API's job config but have no `fj` flag yet; submit those via the API directly if needed.

**Hashlists** (`fj hashlist <sub>`)

| Command | Args / flags | Capability | Does |
| --- | --- | --- | --- |
| `fj hashlist ls` | — | `ViewJobs` | List hashlists: id, name, `-m` type, cracked/total. |
| `fj hashlist create` | `--name <n>` `-m, --hash-type <int>` | `Ingest` | Create a hashlist; print its id. `-m` is hashcat's mode. |
| `fj hashlist import` | `<id> <file>` | `Ingest` | Import hashes from a file, one per line (blank lines skipped); print the new total. |
| `fj hashlist cracked` | `<id>` | `ViewPlaintext` | Print recovered `hash -> plaintext` pairs (decrypted for this call). |

**Files** (`fj file <sub>`)

| Command | Args / flags | Capability | Does |
| --- | --- | --- | --- |
| `fj file add` | `<path>` `[--kind <kind>=other]` | `Ingest` | Upload a file; print its id. `--kind` is one of `wordlist`, `rule`, `mask`, `other` (anything else is stored as `other`). **Set `--kind wordlist` for wordlists** — the default is `other`. |
| `fj file ls` | — | `ViewJobs` | List files: id, name, kind, size. |
| `fj file rm` | `<id>` | `Ingest` | Delete a file (removes it from disk too). |

#### `flamejob-tui` — dashboard

Takes **no arguments or subcommands**. Reads `FJ_SERVER` (default `http://localhost:8443`) and uses `FJ_TOKEN` if set, otherwise the token cached by `fj login`. It polls the API (auto-refreshing about once a second) and renders the job queue, per-job chunk breakdown, aggregate keyspace/ETA, and a devices panel.

| Key | Action | Capability |
| --- | --- | --- |
| `j` / `k` or ↓ / ↑ | Move the job selection | `ViewJobs` |
| `r` | Refresh now | `ViewJobs` |
| `p` | Pause the selected job | `SubmitJobs` |
| `c` | Cancel the selected job | `SubmitJobs` |
| `q` / `Esc` | Quit | — |

#### `fj-agent` — GPU worker

Takes **no subcommands**; enrollment and connection are automatic (§7). Flags and their environment equivalents:

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--server` | `FJ_AGENT_SERVER` | `http://127.0.0.1:8099` | Control-plane base URL — point at your `flamejobd` (note the port differs from flamejobd's default `8443`). |
| `--name` | `FJ_AGENT_NAME` | `agent` | Human-readable agent name (and certificate CN). |
| `--claim-token` | `FJ_AGENT_CLAIM_TOKEN` | — | One-time enrollment token; first run only. |
| `--data-dir` | `FJ_AGENT_DATA_DIR` | `/var/lib/flamejob-agent` | Certificate/key, fetched-file cache (`cache/`), and job scratch. |
| `--hashcat` | `FJ_AGENT_HASHCAT` | `/usr/bin/hashcat` | hashcat binary on the worker. |
| `--workload` | `FJ_AGENT_WORKLOAD` | `3` | hashcat workload profile (1–4). |

Log verbosity is set with `FJ_LOG`, as for `flamejobd`.

### REST API

Every route and the capability it requires. The authoritative, always-current contract is the OpenAPI document at `GET /openapi.json`.

| Method & path | Capability |
| --- | --- |
| `GET /healthz` | none |
| `GET /metrics` | none |
| `GET /openapi.json` | none |
| `GET /docs` | none (interactive API reference) |
| `POST /auth/login` | none |
| `GET /auth/me` | any authenticated |
| `GET /jobs` | `ViewJobs` |
| `POST /jobs` | `SubmitJobs` |
| `POST /jobs/clear` | `SubmitJobs` |
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
| `GET /agent/files/{id}` | agent certificate (`x-agent-cert` header) |
| `POST /admin/users` | `ManageUsers` |

**Capabilities.** `ManageUsers`, `ManageAgents`, `ManageDirectory` (roadmap), `SubmitJobs`, `Ingest`, `ViewPlaintext`, `ViewStats`, `ViewJobs` — see the role matrix in §6.

**Job states.** `queued` → `assigned` → `running`, with `paused` (resumable), and terminal states `completed`, `exhausted`, `cancelled`, `error`. Task states: `pending`, `running`, `paused`, `done`, `failed`.

**Config environment map.** Any key maps to `FJ_<SECTION>__<KEY>` (uppercase, `__` between levels): e.g. `FJ_SERVER__BIND`, `FJ_DATABASE__DSN`, `FJ_AUTH__JWT_SECRET`, `FJ_SCHEDULER__RUNNER`, `FJ_TELEMETRY__ENABLED`. See §5.

**Further reading.** The architecture decision record and build spec live in the project workspace. Roadmap items not yet shipped: LDAP/AD-mapped RBAC (Phase 4/5), running several different jobs concurrently (single-job parallelism across agents is done — §13, §7), and hybrid attack modes (`-a 6`/`-a 7`).

## 13. Web dashboard

flamejob ships a browser dashboard alongside the TUI. It is a static single-page app that calls the same API and shows the same metrics, gated by the signed-in user's capabilities — so each role sees exactly what it is allowed to (viewers and operators get jobs, chunk breakdowns and device/agent panels; operators also get job controls and "clear finished"; admins get the user- and agent-management forms). The logged-in username and a log-out button sit in the upper-right, next to a light/dark theme toggle.

**Where it runs.** A separate listener, configured under `[web]` (default `0.0.0.0:9443`). Set `tls_cert` and `tls_key` to serve it over HTTPS; leave them unset for plain HTTP. The dashboard calls the API on its existing port (`[server].bind`, default `:8443`), which now sends CORS headers so the browser can reach it cross-origin; bearer-token auth still gates every protected route. Point the browser at the API elsewhere with `[web].api_base` (e.g. behind a reverse proxy), or override it on the sign-in screen.

> **Mixed content:** if you serve the dashboard over HTTPS, the API must also be reachable over HTTPS (front it with TLS or a proxy, per §7) — a browser will block an HTTPS page calling an `http://` API.

**API reference.** The API is browseable at `GET /docs` (served on the API port): an interactive OpenAPI/RapiDoc view of every operation and schema, bound to `GET /openapi.json`. The dashboard links to it ("API docs"). The interactive reference loads its viewer from a CDN, so it needs outbound internet in the browser; the raw `GET /openapi.json` is always available offline.
