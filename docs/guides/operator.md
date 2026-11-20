# flamejob Operator Guide

> **Skeleton** — section structure from the documentation architecture plan.
> Prose to be written next. Each section below notes its intended content.
> Audience: the `operator` role — running and monitoring jobs day to day.

## 1. Introduction & audience

_Who it's for (the operator role) and a plain-language summary of what an operator can and can't do; what flamejob does from a user's seat._

## 2. Concepts primer

_Hashlists, hashes and cracked results; files (wordlists, rules, masks); jobs, attack modes, priority; chunks/tasks and keyspace (why a job splits); the job lifecycle and states._

## 3. Getting started

_Getting an account and the operator role from an admin. Obtaining the `fj` CLI and TUI. Pointing at the server (`--server` / `FJ_SERVER`, default). Logging in (`fj login`), the cached token location (`~/.config/flamejob/token`), `fj whoami`, `fj logout`._

## 4. Working with hashlists & hashes

_**Requires `Ingest`.** Create a hashlist (`fj hashlist create`, with `-m` hash type); import hashes (`fj hashlist import`); list hashlists and read cracked/total progress._

## 5. Managing files

_**Requires `Ingest`.** Upload wordlists/rules/masks (`fj file add --kind`); list and remove files; note that in remote mode wordlist files must already be present on the agent._

## 6. Submitting & running jobs

_**Requires `SubmitJobs`.** Submit a job (`fj job submit`: `--hashlist`, `--attack-mode`, `--name`, `--wordlist`, `--priority`); a short attack-mode primer (mask vs wordlist); control jobs (`pause` / `resume` / `cancel`, change priority with `fj job prio`); follow progress live with `fj job watch` (SSE)._

## 7. Viewing results & plaintext

_**Requires `ViewPlaintext`.** Read decrypted cracked results (`fj hashlist cracked`); handling/sensitivity note._

## 8. Monitoring with the TUI dashboard

_Launch and point it at the server/token; the panels (jobs queue, per-job chunk breakdown, keyspace/ETA aggregate, devices); keybindings (`j`/`k` navigate, `r` refresh, `p` pause, `c` cancel, `q`/Esc quit)._

## 9. Monitoring devices & stats

_**Requires `ViewStats`.** Reading the live device snapshot (`GET /devices`) and history; interpreting GPU/host metrics; pointer to Grafana dashboards in the Administrator Guide._

## 10. CLI command reference

_Global flags (`--server`, `--json`); the operator command tree: `login` / `whoami` / `logout`; `job ls|show|submit|pause|resume|cancel|prio|watch`; `hashlist ls|create|cracked|import`; `file add|ls|rm`._

## 11. Troubleshooting

_Login or "missing capability" errors; a job stuck in `queued` (no runner/agent available); no cracked results yet._

## 12. Reference & appendices

_REST API reference (operator-relevant endpoints plus the full table) and `/openapi.json`; job & task state glossary; attack-mode quick reference; pointer to the Administrator Guide._
