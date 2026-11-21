# flamejob Operator Guide

## 1. Introduction & audience

This guide is for **operators** — the people who load hashes, submit cracking jobs, and watch them run. As an operator you can do everything involved in getting work through flamejob: create hashlists and import hashes, upload wordlists / rules / masks, submit and control jobs, read recovered plaintext, and watch job and device stats. You cannot manage user accounts or the worker fleet — those are admin tasks (see the **Administrator Guide**), and strictly read-only users have their own **Viewer Guide**.

You'll work through the `fj` command-line client and the `flamejob-tui` dashboard, both talking to a `flamejobd` control plane an admin has already deployed. This guide documents flamejob **1.0.5**. A browser dashboard is also available (ask your admin for its URL) — sign in with the same credentials to submit jobs by dropping in a hash file, watch the agent pool, and read cracked passwords; the TUI's agents panel and the dashboard both show each agent's status as a coloured dot (green = usable, gray = away, red = error, orange = near overloaded).

## 2. Concepts primer

A few terms you'll use constantly:

- **Hashlist** — a named collection of hashes of one type; it tracks how many of its hashes are cracked out of the total.
- **Hash type** — hashcat's numeric mode (`-m`), e.g. `0` = MD5, `1000` = NTLM, `22000` = WPA. You set it when you create a hashlist.
- **File** — a wordlist, rule or mask file you upload for attacks (kind `wordlist`, `rule`, `mask`, or `other`).
- **Job** — a cracking run against one hashlist with one attack. It has a name, an attack mode, and a priority (lower runs first; default 100).
- **Attack mode** — hashcat's `-a` value: `0` dictionary (wordlist), `3` mask (brute-force), and so on.
- **Chunk / task** — the control plane splits a job's keyspace into chunks and runs them as tasks; you'll see per-chunk progress in the dashboard. This is automatic — you submit a job, not chunks.
- **Keyspace** — the total number of candidates an attack will try; it drives progress and ETA.

**Job lifecycle.** A job starts `queued`, becomes `assigned` then `running`, and may be `paused` and resumed. It ends `completed` (keyspace fully processed), `exhausted`, `cancelled`, or `error` — and finishes early as soon as every hash in the list is cracked.

## 3. Getting started

**Get access.** Ask an admin to create you an account with the `operator` role.

**Point `fj` at the server.** Every command takes `--server`, or reads the `FJ_SERVER` environment variable (default `http://localhost:8443`). Set it once:

```
export FJ_SERVER=https://flamejob.example.com:8443
```

**Log in.**

```
fj login --user alice --password '...'
```

This caches a token at `~/.config/flamejob/token` and prints your roles; later commands reuse it. Check who you are with `fj whoami`, and clear the token with `fj logout`. Tokens expire (the lifetime is set server-side — 1 hour by default), so log in again if commands start returning auth errors.

Add `--json` to any command to get raw JSON instead of the formatted output.

## 4. Working with hashlists & hashes

*Requires the `Ingest` capability (operators have it).*

**Create a hashlist** with a name and hash type (`-m`, hashcat's mode number):

```
fj hashlist create --name corp-ntlm -m 1000
```

It prints the new hashlist's id.

**Import hashes** from a file, one hash per line:

```
fj hashlist import <hashlist-id> hashes.txt
```

Blank lines are skipped, and the command reports the new total.

**List hashlists** and their progress (cracked / total) with `fj hashlist ls`.

## 5. Managing files

*Requires the `Ingest` capability.*

Upload the wordlists, rules and masks your attacks will use. Set `--kind` to `wordlist`, `rule`, or `mask` (anything else is stored as `other`):

```
fj file add rockyou.txt --kind wordlist
```

It prints the file's id. The default `--kind` is `other`, so **remember `--kind wordlist`** for a wordlist (likewise `rule` or `mask`); the kind is how the control plane and agents know what the file is. You can pass the printed id to `fj job submit --wordlist`, or skip this step entirely and give `fj job submit --wordlist` a local path — it uploads the file for you (see §6). List and remove files with `fj file ls` and `fj file rm <file-id>`.

**Remote mode.** As of 1.0.3, if your deployment runs jobs on remote agents, wordlist and rule files are distributed to the agents automatically — an agent fetches the files a job needs from the control plane the first time it runs a chunk and caches them. There is nothing to pre-stage. (Hybrid attacks, hashcat `-a 6`/`-a 7`, aren't wired up yet; stick to wordlist and mask attacks.)

## 6. Submitting & running jobs

*Requires the `SubmitJobs` capability.*

**Submit a wordlist job** against a hashlist:

```
fj job submit --hashlist <hashlist-id> --name corp-run-1 \
              --attack-mode 0 --wordlist rockyou.txt --priority 100
```

**Submit a mask (brute-force) job** with `--mask` and `-a 3`:

```
fj job submit --hashlist <hashlist-id> --name corp-mask-1 \
              --attack-mode 3 --mask '?a?a?a?a?a?a'
```

- `--attack-mode` / `-a` is hashcat's attack number (`0` wordlist, `3` mask; default `0`).
- `--wordlist` takes **either** a file id (from `fj file add`) **or** a path to a local wordlist, which `fj` uploads for you before submitting. A value that's neither a known id nor an existing file is rejected. Omit it for attacks that don't need a wordlist.
- `--mask` takes a hashcat mask string (e.g. `?a?a?a?a`) for a mask / brute-force attack; pair it with `-a 3`.
- `--rule` applies a rule file to a dictionary attack (`-a 0`): a file id (from `fj file add`) **or** a local path, uploaded for you as kind `rule`. Repeat `--rule` to apply several rule files in order, e.g. `--wordlist rockyou.txt --rule best64.rule`.
- `--priority` orders the queue — lower runs first; default `100`.

The command prints the new job id and the job enters the queue. (Wordlist, rule and mask/brute-force attacks are all driven from the CLI; only raw extra hashcat arguments remain unexposed as `fj` flags — they live in the API's job config if you need them.)

**Control a running job:**

```
fj job pause <id>
fj job resume <id>
fj job cancel <id>
fj job prio <id> <priority>
```

**Watch progress live** over the event stream with `fj job watch <id>` — it follows job and task events until you stop it with Ctrl-C. `fj job ls` and `fj job show <id>` give point-in-time status.

## 7. Viewing results & plaintext

*Requires the `ViewPlaintext` capability (operators have it; viewers do not).*

Read the recovered plaintext for a hashlist:

```
fj hashlist cracked <hashlist-id>
```

Each line shows a hash and its cracked plaintext. The control plane stores plaintext encrypted and decrypts it only for this call. Treat the output as sensitive — it is real recovered credentials.

## 8. Monitoring with the TUI dashboard

`flamejob-tui` is a live terminal dashboard. It reads the same server and token as the CLI: set `FJ_SERVER` (or it defaults to `http://localhost:8443`) and it uses your cached login token (or `FJ_TOKEN`). Launch it and you'll see the jobs queue, a per-job chunk breakdown, the aggregate keyspace / ETA, and a devices panel, all refreshing continuously.

Keys:

- `j` / `k` (or ↓ / ↑) — move between jobs
- `r` — refresh now
- `p` — pause the selected job
- `c` — cancel the selected job
- `q` or Esc — quit

Pausing and cancelling from the dashboard need the same `SubmitJobs` capability as the CLI.

## 9. Monitoring devices & stats

*Requires the `ViewStats` capability (operators have it).*

The TUI's devices panel is your main view of GPU and host health. The underlying data is also available from the API if you query it directly: `GET /devices` (current snapshot) and `GET /devices/{name}/history` (recent samples). They report temperature, utilisation, memory, power, clocks and hashrate for the control plane and any connected agents. For persistent dashboards, your admin can wire Grafana to the server's Prometheus metrics (see the Administrator Guide).

## 10. CLI command reference

This is the complete `fj` surface for an operator. **Global flags**, valid on every command: `--server <url>` (or the `FJ_SERVER` environment variable; default `http://localhost:8443`) and `--json` for raw JSON output instead of the formatted text. The login token is cached at `~/.config/flamejob/token` and reused by later commands and the TUI.

**Identity**

| Command | Purpose |
| --- | --- |
| `fj login --user <u> --password <p>` | Authenticate; cache the token; print your roles. Both flags required. |
| `fj whoami` | Show the current identity and roles. |
| `fj logout` | Forget the cached token. |

**Jobs** (`fj job …`)

| Command | Purpose |
| --- | --- |
| `fj job ls` | List jobs with id, name, state and priority. |
| `fj job show <id>` | Full job detail (always JSON). |
| `fj job submit --hashlist <id> --name <n> [-a <mode>] [--wordlist <id\|path>] [--rule <id\|path>]… [--mask <str>] [--priority <n>]` | Submit a job (see §6 for the flags). `--hashlist` and `--name` are required; `-a` defaults to `0`, `--priority` to `100`; `--rule` repeats. |
| `fj job pause <id>` | Pause a running job (resumable). |
| `fj job resume <id>` | Return a paused job to the queue. |
| `fj job cancel <id>` | Cancel a job (terminal). |
| `fj job prio <id> <priority>` | Re-prioritise a job; lower runs first. |
| `fj job watch <id>` | Follow that job's events over SSE until Ctrl-C. |

**Hashlists** (`fj hashlist …`)

| Command | Purpose |
| --- | --- |
| `fj hashlist ls` | List hashlists with cracked / total. |
| `fj hashlist create --name <n> -m <type>` | Create a hashlist; `-m` is hashcat's hash-type number. Prints the new id. |
| `fj hashlist import <id> <file>` | Import hashes from a file, one per line (blank lines skipped); reports the new total. |
| `fj hashlist cracked <id>` | Show recovered `hash -> plaintext` (needs `ViewPlaintext`). |

**Files** (`fj file …`)

| Command | Purpose |
| --- | --- |
| `fj file add <path> [--kind {wordlist,rule,mask,other}]` | Upload a file; prints its id. `--kind` defaults to `other` — set `wordlist` / `rule` / `mask` explicitly. |
| `fj file ls` | List files with id, name, kind and size. |
| `fj file rm <id>` | Delete a file. |

The `flamejob-tui` dashboard keys are in §8. Admin-only tools (`flamejobd`, `fj-agent`) and their flags are in the **Administrator Guide**.

## 11. Troubleshooting

- **`missing capability` / `403`** — your role doesn't permit that action. Reading cracked plaintext needs `ViewPlaintext`; submitting or controlling jobs needs `SubmitJobs`; uploading or importing needs `Ingest`. Ask an admin if you're missing one you need.
- **Auth errors after a while** — your token expired (default 1 hour). Run `fj login` again.
- **A job sits in `queued`** — nothing is running it yet. In local mode the scheduler runs one job at a time, so an earlier or higher-priority job may be ahead of yours; in remote mode, no agent may be connected. Check with your admin if it never starts.
- **No cracked results yet** — cracking may simply not have reached them. Watch progress with `fj job watch <id>` or the TUI; the `cracked / total` column in `fj hashlist ls` shows how far along the list is.
- **A remote job errors immediately with a file problem** — in remote mode the agent fetches wordlist/rule files from the control plane on demand (1.0.3). If a chunk fails fetching one, confirm the file still exists (`fj file ls`) and that your admin's agents can reach the control plane's address; a deleted or unreachable file is the usual cause.

## 12. Reference & appendices

**Attack modes** (hashcat `-a`, passed as `--attack-mode`): `0` dictionary (wordlist), `1` combinator, `3` mask (brute-force), `6` hybrid wordlist + mask, `7` hybrid mask + wordlist. The `fj` submit flow supports wordlist (`0`, via `--wordlist`, with optional `--rule` rule files) and mask / brute-force (`3`, via `--mask`) attacks; hybrid modes aren't wired up in 1.0.5.

**Job states.** `queued` → `assigned` → `running`; `paused` is resumable; terminal states are `completed`, `exhausted`, `cancelled`, `error`. A job finishes early once every hash is cracked. Task (chunk) states: `pending`, `running`, `paused`, `done`, `failed`.

**The API.** Everything `fj` does is HTTP against the control plane; the full contract is at `GET /openapi.json`. Operator-relevant endpoints and the capability each needs:

| Method & path | Capability |
| --- | --- |
| `POST /auth/login`, `GET /auth/me` | none / any |
| `GET /jobs`, `GET /jobs/{id}`, `GET /jobs/{id}/tasks` | `ViewJobs` |
| `POST /jobs`, `PATCH /jobs/{id}`, `POST /jobs/{id}/{pause,resume,cancel}` | `SubmitJobs` |
| `GET /hashlists` | `ViewJobs` |
| `POST /hashlists`, `POST /hashlists/{id}/hashes` | `Ingest` |
| `GET /hashlists/{id}/cracked` | `ViewPlaintext` |
| `GET /files` | `ViewJobs` |
| `POST /files`, `DELETE /files/{id}` | `Ingest` |
| `GET /events` | `ViewJobs` |
| `GET /devices`, `GET /devices/{name}/history` | `ViewStats` |

For deployment, roles and the full API, see the **Administrator Guide**.
