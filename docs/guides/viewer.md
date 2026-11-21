# flamejob Viewer Guide

## 1. Introduction & audience

This guide is for **viewers** — people who need to watch flamejob without changing anything. As a viewer you can see the job queue and each job's progress, follow live updates, and read device and host metrics. You cannot submit or control jobs, upload or import data, or read cracked plaintext — those need the operator role (see the **Operator Guide**), and running the system is covered in the **Administrator Guide**.

You'll use the `fj` command-line client and the `flamejob-tui` dashboard in read-only fashion, against a `flamejobd` an admin has deployed. This guide documents flamejob **1.0.5**.

## 2. Concepts primer

Just enough to read the dashboard:

- **Job** — a cracking run against a hashlist. It moves through states and reports progress.
- **Job states** — `queued` (waiting), `assigned` / `running` (being worked), `paused`, and the terminal `completed`, `exhausted`, `cancelled`, `error`.
- **Chunk / task** — a job is split across its keyspace into chunks; each shows its own progress and speed.
- **Keyspace, progress, ETA** — keyspace is the total number of candidates to try; progress is how far through it the job is; ETA is the estimated time to finish at the current speed.
- **Cracked / total** — for a hashlist, how many of its hashes have been recovered so far.
- **Device** — a GPU or host the work runs on; the dashboard shows its temperature, utilisation, memory, power, clocks and hashrate.

## 3. Getting started

**Get access.** Ask an admin for an account with the `viewer` role.

**Point `fj` at the server** with `--server` or the `FJ_SERVER` environment variable (default `http://localhost:8443`):

```
export FJ_SERVER=https://flamejob.example.com:8443
```

**Log in**, then check your identity:

```
fj login --user bob --password '...'
fj whoami
```

The token is cached at `~/.config/flamejob/token` and reused by later commands and the dashboard; `fj logout` clears it. Tokens expire (1 hour by default), so log in again if you start seeing auth errors. Add `--json` to any command for raw output.

## 4. Monitoring with the TUI dashboard

`flamejob-tui` is the main way to watch flamejob. It uses the same server and token as the CLI (set `FJ_SERVER`, or `FJ_TOKEN`; otherwise the cached login token). Launch it and you'll see the jobs queue, a per-job chunk breakdown, the aggregate keyspace / ETA, and a devices panel, refreshing continuously.

Navigation:

- `j` / `k` (or ↓ / ↑) — move between jobs
- `r` — refresh now
- `q` or Esc — quit

The dashboard also has `p` (pause) and `c` (cancel) keys, but those actions need the `SubmitJobs` capability, which viewers don't have — they'll be refused. Everything else is read-only and available to you.

## 5. Watching jobs & progress

*Requires the `ViewJobs` capability, which the viewer role has.*

From the CLI you can list and inspect jobs, hashlists and files:

```
fj job ls              # the queue: state, priority, progress
fj job show <id>       # full detail for one job
fj hashlist ls         # hashlists with cracked / total
fj file ls             # uploaded wordlists, rules, masks
```

To follow a job as it runs, stream its events:

```
fj job watch <id>
```

It prints job and task updates until you stop it with Ctrl-C. Note that `fj hashlist cracked` — the recovered plaintext — needs `ViewPlaintext` and is not available to viewers.

## 6. Monitoring devices & stats

*Requires the `ViewStats` capability, which the viewer role has.*

Device and host health is shown in the TUI's devices panel. The same data is available from the API if you query it directly: `GET /devices` (the current snapshot) and `GET /devices/{name}/history` (recent samples). They report temperature, utilisation, memory, power, clocks and hashrate for the control plane and any connected agents.

## 7. Read-only CLI reference

The commands available to a viewer. Global flags: `--server <url>` (or `FJ_SERVER`) and `--json`.

| Command | Purpose |
| --- | --- |
| `fj login` / `fj whoami` / `fj logout` | Authenticate, check identity, clear token. |
| `fj job ls` | List jobs with state, priority, progress. |
| `fj job show <id>` | Full job detail. |
| `fj job watch <id>` | Follow job / task events (SSE). |
| `fj hashlist ls` | List hashlists with cracked / total. |
| `fj file ls` | List uploaded files. |

Commands that change state or reveal plaintext are **not** available to viewers and return a *missing capability* error: `fj job {submit,pause,resume,cancel,prio}`, `fj hashlist {create,import,cracked}`, and `fj file {add,rm}`.

## 8. Troubleshooting

- **`missing capability` / `403`** — expected for anything beyond viewing. Submitting or controlling jobs, uploading or importing, and reading cracked plaintext are operator actions; ask an admin if you need them.
- **`p` / `c` in the dashboard do nothing** — pause and cancel need `SubmitJobs`, which viewers don't have. This is by design.
- **Auth errors after a while** — your token expired (default 1 hour). Run `fj login` again.
- **An empty dashboard or job list** — there may simply be no jobs yet, or the server may be unreachable. Confirm `FJ_SERVER` points at the right control plane and that you're logged in (`fj whoami`).

## 9. Reference

**Job states.** `queued` → `assigned` → `running`; `paused` is resumable; terminal states are `completed`, `exhausted`, `cancelled`, `error`. Task (chunk) states: `pending`, `running`, `paused`, `done`, `failed`.

**What a viewer can read** (capabilities `ViewJobs` + `ViewStats`): `GET /jobs`, `/jobs/{id}`, `/jobs/{id}/tasks`, `/hashlists`, `/files`, `/events` (via `ViewJobs`); `GET /devices`, `/devices/{name}/history` (via `ViewStats`). The full API contract is at `GET /openapi.json`.

**More.** To do more than watch, you'll need the operator role — see the **Operator Guide**. For deployment and administration, see the **Administrator Guide**.
