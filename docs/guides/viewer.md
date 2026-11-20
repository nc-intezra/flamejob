# flamejob Viewer Guide

> **Skeleton** — section structure from the documentation architecture plan.
> Prose to be written next. Each section below notes its intended content.
> Audience: the `viewer` role — read-only monitoring of jobs and metrics.

## 1. Introduction & audience

_Who the viewer role is; what you can see and, explicitly, what you can't (no job control, no ingest, no plaintext)._

## 2. Concepts primer

_Jobs and their states, keyspace/progress/ETA, and devices/metrics — just enough to read the dashboard._

## 3. Getting started

_Getting a viewer account from an admin; obtaining the `fj` CLI and TUI; pointing at the server and logging in (`fj login`, `fj whoami`, `fj logout`); token location._

## 4. Monitoring with the TUI dashboard

_Launching the dashboard; the panels; navigation keys; note that control keys (pause/cancel) are denied for viewers._

## 5. Watching jobs & progress

_**Requires `ViewJobs`.** List and inspect jobs and their tasks; read progress, ETA and cracked counts; follow live updates via the events stream._

## 6. Monitoring devices & stats

_**Requires `ViewStats`.** Reading the device snapshot and history; interpreting GPU/host metrics._

## 7. Read-only CLI reference

_The subset that works for a viewer (`whoami`, `job ls|show`, `hashlist ls`, device views) and what returns "missing capability."_

## 8. Troubleshooting

_Login/permission issues; an empty dashboard; why job controls are unavailable._

## 9. Reference

_State glossary; pointer to `/openapi.json`; where to go for more (ask an admin; see the Operator Guide)._
