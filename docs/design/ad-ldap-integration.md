# flamejob — Active Directory / LDAP Integration & Multi-Tenant Authorization (Phase 5 design)

**Status:** design / research. **Audience:** flamejob maintainers and operators planning large-scale, multi-user deployments.
**Scope:** directory-backed authentication, mapping AD/LDAP security groups to flamejob roles, **server-enforced restriction of each group to only the cracking agents it is authorized for**, and fairness/quotas when many groups submit to many agents concurrently.

This document is written against the current codebase (`main`, v1.3.1). It proposes concrete schema, config, and integration points rather than a greenfield system: the RBAC model already anticipates this work. `crates/flamejob-core/src/model.rs` carries the note *"In Phase 1 these come from the local `user_roles` table; in Phase 5 they are mapped from AD/LDAP group membership,"* and the `ManageDirectory` capability already exists and is granted to `Superadmin`.

---

## 0. Goals and non-goals

**Goals**

1. Let users sign in with their corporate AD/LDAP credentials; stop managing a parallel password database for them.
2. Derive flamejob roles/capabilities from AD **security-group membership**, administered centrally and keyed on a stable identifier.
3. **Confine each security group to a specific, authorized subset of cracking agents.** A group may only ever run work on the agents it has been granted — and this is enforced by the **server**, from **verified** directory membership, **never** from any value the client supplies.
4. Keep the shared fleet fair and bounded when dozens of groups submit thousands of chunks concurrently: guaranteed floors, burst ceilings, per-group concurrency caps, weighted fair share of leftover capacity, and anti-starvation.

**Non-goals (for this phase)**

- Replacing the internal `users` table outright. Local accounts remain for **break-glass** admin and for agents/service identities. Directory users are *shadowed* into `users` on first login.
- Multi-forest / cross-realm trust topologies beyond what a Global Catalog query covers. Called out in §2.
- Per-hash or per-hashlist data-level tenancy (row-level isolation of cracked plaintext). This design isolates *compute* (which agents a group may use) and *governance* (roles/quotas); data-scoping is noted as future work in §10.

---

## 1. How this fits the current architecture

A quick map of what exists today, because the Phase 5 enforcement points are all extensions of these.

**Authentication (`crates/flamejob-server/src/auth.rs`).**
- Login verifies an Argon2 password hash and issues an HS256 JWT. `Claims { sub: Uuid, username, roles: Vec<Role>, exp, iat }` — note that **roles already travel inside the signed token**, so a directory-derived role set needs no new transport.
- `AuthUser` is an axum extractor. Bearer tokens starting with `fj_` are **personal API keys**: `authenticate_api_key` looks the key up by SHA-256 hash and, critically, **re-loads roles live** from `user_roles` on every request (`load_roles_for`). So long-lived credentials pick up role/authorization changes immediately — a property we preserve and extend to directory-derived authorization.
- Route handlers gate on **capabilities**, not roles: `auth.require(Capability::SubmitJobs)?`. The role→capability table lives in `Role::capabilities()`. This indirection is what lets us remap roles from the directory without touching a single handler.

**RBAC model (`crates/flamejob-core/src/model.rs`).**
- `Role` ∈ {`Superadmin`, `Admin`, `Operator`, `Viewer`}; `Capability` ∈ {`ManageUsers`, `SubmitJobs`, `Ingest`, `ViewPlaintext`, `ViewStats`, `ViewJobs`, `ManageDirectory`, `ManageAgents`}. `roles_have()` is an any-of union across a user's roles.

**Agents (`migrations/0003_agents.sql`, `crates/flamejob-server/src/agent.rs`).**
- An agent enrolls with a one-time claim token, is issued a client cert, and is identified thereafter by the **SHA-256 fingerprint of that cert** (`agents.fingerprint`, UNIQUE). The `AgentHub` holds the live, in-memory view of connected agents and their free `slots`.
- Work dispatch is **fleet-global and tenant-blind today**: `AgentHub::drain()` assigns a queued chunk to *any* connected agent with `slots > 0` (`g.conns.iter().find(|(_, c)| c.slots > 0)`); `capacity()` sums free slots across the whole fleet; `keyspace_probe()` likewise grabs any free agent. There is no notion of which job, user, or group a chunk belongs to at the point of assignment.

**Scheduler (`crates/flamejob-server/src/scheduler.rs`).**
- A single control loop. `claim_and_start` pulls queued jobs by `(priority, created_at)`; `fill_fleet` asks the runner for `capacity()` and then, via `fillable_jobs()`, **round-robins one pending chunk from every running job in priority order** until the fleet is full. Fairness today is therefore *per-job round-robin over a global pool* — there is no per-user or per-group fairness, and no way to keep one group's flood of jobs from monopolizing the fleet.

**Jobs (`migrations/0001_init.sql`).**
- `jobs.owner_user_id` ties a job to a user; `jobs.priority` is a single global integer. No group column, no agent-affinity column.

The three Phase-5 enforcement points, then, are: **(a)** role resolution moves from `user_roles` to a directory-backed resolver feeding the *same* `Vec<Role>`; **(b)** the scheduler/`AgentHub` gain a **pool filter** so a job is only ever placed on agents its owner's groups are authorized for; **(c)** the scheduler gains a **fairness layer** keyed on the owning group. None of these require changing route handlers.

---

## 2. Directory authentication

### 2.1 Transport and connectivity

- **Use LDAPS (TCP 636)** by default, or StartTLS on 389 (extended-op OID `1.3.6.1.4.1.1466.20037`) where the directory requires it. Either way the server certificate **must** be validated (chain to a trusted CA **and** hostname match). A simple bind over an unvalidated or plaintext channel ships the user's password in the clear. Hardened DCs increasingly refuse plain-389 simple binds (LDAP channel binding + signing), so treat TLS as mandatory, not optional.
- **Domain-controller discovery and failover:** resolve DCs from DNS SRV records (`_ldap._tcp.dc._msdcs.<domain>`) and keep an ordered candidate list; try each with a short connect timeout and fail over on connect/bind errors. Do **not** hardcode a single DC. For forest-wide group data, query the **Global Catalog** (3268, or 3269 over TLS) rather than chasing referrals.
- **Referrals:** disable referral chasing. Auto-following a referral can leak the service-account credential to another server and invites SSRF-style pivots. Query the GC explicitly when you need cross-domain breadth.
- **RODCs:** reads work; a password bind may be proxied to a writable DC when the account isn't cached locally — budget for the extra latency.

### 2.2 Authentication flow — service-account *search-then-bind* (recommended default)

Direct simple bind only works when the login name maps trivially to a bind string (AD tolerates UPN `alice@corp.example` or `CORP\alice`). We want to read attributes (groups, SID, account status) and support flexible login identifiers, so the server uses **search-then-bind**:

1. Bind as a **read-only service account** (least privilege, no reset rights; password from a secret store / env, never the config file in plaintext).
2. **Search** under the configured base DN for the login identifier, retrieving the user DN plus the attributes we need. AD filter, with `%u` = the **RFC-4515-escaped** user input (see §8), and excluding disabled accounts at search time via the bitwise-AND matching rule `1.2.840.113556.1.4.803` against `userAccountControl` bit `0x2` (`ACCOUNTDISABLE`):

   ```
   (&(objectCategory=person)(objectClass=user)
     (!(userAccountControl:1.2.840.113556.1.4.803:=2))
     (|(sAMAccountName=%u)(userPrincipalName=%u)(mail=%u)))
   ```

3. **Reject empty/whitespace-only passwords before step 4** (see §8 — AD may treat a non-empty DN + empty password as a *successful* "unauthenticated bind"). A successful search is **not** authentication.
4. **Re-bind on a fresh connection** as the returned user DN + the supplied password. Success = credentials verified. Never reuse a pooled connection's bind state for this — binding mutates the connection's identity.
5. Resolve the user's effective groups (§2.4), map to roles (§3), then unbind / return the service connection to the pool.

### 2.3 Optional single sign-on (Kerberos / SPNEGO, SSSD)

For domain-joined deployments that want true SSO (no password touching flamejob):

- **SPNEGO/Kerberos at the web edge:** terminate `Authorization: Negotiate` in a reverse proxy (mod_auth_gssapi, or SSSD + Apache/nginx) and have flamejob trust an authenticated principal header **on a trusted, non-bypassable path**. This keeps Kerberos's keytab/SPN/clock-sync operational weight out of the Rust process.
- **SSSD on the host** can also provide cached, offline-capable identity/auth via PAM. Good availability story, at the cost of requiring a domain-joined host.
- Tradeoff: direct LDAPS search-then-bind is the most portable thing to ship and is the baseline. GSSAPI (`ldap3`'s `gssapi` feature, which FFIs into system Kerberos) or edge-SPNEGO are opt-in enhancements, not prerequisites.

### 2.4 Resolving effective group membership (the part that bites)

Role mapping is only as correct as the group set we resolve, and AD has three well-known traps. The design sidesteps all of them by reading **`tokenGroups`** and keying on **SID**:

- **`tokenGroups` (constructed attribute):** returns the **SIDs of every group the user effectively belongs to** — direct, **nested**, **and the primary group** — as computed by the DC. This is the authoritative "what would be in the access token" set and avoids hand-walking the graph. Two caveats baked into the resolver:
  - it is **constructed**, so it must be requested **by name** (not via `*`), and
  - it is only populated on a **base-scoped search of the user object itself** (`scope = base`, filter `(objectClass=*)`), not on a subtree search.
  Query a **Global Catalog** for the most complete cross-domain token; `tokenGroupsNoGCAcceptable` is the no-GC fallback.
- Why not `memberOf`: it is **direct memberships only** (no nesting), and it **omits the primary group** (default "Domain Users"), whose membership is carried in `primaryGroupID` as a RID, not in `memberOf`/`member`. Any logic built on `memberOf` silently misses the most common group. If a deployment must use plain LDAP without `tokenGroups`, fall back to the transitive matching rule `1.2.840.113556.1.4.1941` **and** reconstruct the primary group from `primaryGroupID` — but `tokenGroups` is strongly preferred.
- **Paging:** AD caps responses at 1000 rows (`MaxPageSize`). `tokenGroups` on a single user object avoids this, but any *group-member enumeration* we do (e.g. admin UI "who is in this group") must use the Simple Paged Results control `1.2.840.113556.1.4.319` and loop on the cookie, or it truncates silently.

### 2.5 Keying on `objectSID`, not DN or CN

flamejob maps **groups → roles/agent-grants by `objectSid`**, stored canonically as `S-1-5-21-…-<rid>`:

- **CN** is not forest-unique and changes on rename — never match on it.
- **DN** changes on rename **or** move (OU change) — fragile.
- **`objectSid`** is assigned at creation and is **immutable for the object's lifetime**; it survives rename and move. (Delete-and-recreate mints a new SID by design — that is a different principal. `sIDHistory` can be honored for migrations if needed.)

`tokenGroups` already hands us SIDs, so the loop closes cleanly: read `tokenGroups` → set of SIDs → look each up in the mapping tables. We render group CNs for humans in the admin UI (a best-effort GC lookup) but **authorization only ever matches on SID**.

### 2.6 Rust implementation notes

- **`ldap3`** (async, Tokio) is the client. Enable a TLS feature (`tls` = native-tls, or `tls-rustls-*`), use `LdapConnSettings::set_starttls(true)` for StartTLS or an `ldaps://` URL otherwise. Binary attributes like `objectSid`/`tokenGroups` arrive in `SearchEntry::bin_attrs`; format SIDs ourselves. Paged results via the `controls::PagedResults` + `adapters` streaming API. GSSAPI is behind the `gssapi` feature (needs system Kerberos/`libkrb5-dev` + clang/bindgen) and stays off unless a deployment opts into SSO.
- **Connection pooling:** a small pool of authenticated *service-account* connections for searches; a **separate short-lived connection per password-verify bind**. Health-check idle connections.
- **Caching + TTL:** cache the `user → {role set, authorized-agent/pool set}` resolution with a **short TTL (5–15 min)**. This bounds how long a revoked membership stays effective and caps DC load. **Passwords are never cached** — every interactive login does a live bind. (API keys don't bind; see §2.7.)
- **Directory unreachable → fail-closed.** Security-sensitive default: if membership cannot be verified and no unexpired cache entry exists, **deny**. A bounded cache may serve last-known authorization within TTL, but a cold cache + dead directory = denied. This is configurable but defaults closed. Break-glass local admin accounts (§2.7) remain usable so operators aren't locked out.
- **Account state:** honor `userAccountControl` `ACCOUNTDISABLE` (filtered in the search) and treat AD bind result code `49` sub-codes meaningfully for UX/alerting (`52e` bad credentials, `533` disabled, `775` locked out, `532`/`773` password expired/must-reset, `530` not-permitted-at-this-time). Rate-limit auth attempts so a bad-password storm from flamejob can't drive real AD lockouts.

### 2.7 Grafting onto the existing auth path

The changes are deliberately small because roles already live in the token and API-key roles already resolve live:

- **Interactive login (`POST /auth/login`-equivalent):** add an auth *provider* chain. If the directory is enabled, attempt directory auth (search-then-bind); on success, **upsert a shadow row** into `users` (so `owner_user_id` FKs, audit, and API keys keep working), store/refresh the user's `objectSid`, resolve roles (§3), and issue the **same** `Claims` JWT. Local password auth remains as a fallback/break-glass path, selected by username namespace or an explicit "local login" toggle.
- **JWT lifetime:** keep `token_ttl_hours` modest (e.g. ≤ 8h) so directory-derived roles in a token can't outlive a membership change by long. Roles in the JWT are a point-in-time snapshot; the TTL is the staleness bound for interactive sessions.
- **API keys:** `authenticate_api_key` keeps re-resolving authorization **live** per request. Extend `load_roles_for` to a `resolve_authorization(user)` that, for directory-shadowed users, returns the **cached** directory resolution (roles **and** authorized pools, §4) rather than reading `user_roles`. Because the cache TTL is short and keyed on the stored `objectSid`, a membership or grant change takes effect within one TTL even for long-lived keys — preserving today's "role changes take effect at once" property. If the directory is down and the cache is cold, the key fails closed.
- **Audit (`audit_events`):** log every auth decision — identifier (never the password), resolved DN/SID, which DC answered, result code, resolved groups/roles, and cache-hit vs live. This table already exists; add `action` values like `auth.directory.login`, `auth.directory.denied`.

---

## 3. Mapping AD security groups to flamejob roles & capabilities

### 3.1 Model

A new mapping table translates **group SID → flamejob role**. Because handlers gate on capabilities and `roles_have()` is a union, a user who lands in several mapped groups simply receives the **union** of their roles' capabilities — no new evaluation logic needed.

```sql
-- migrations/0005_directory.sql  (excerpt)
CREATE TABLE directory_role_map (
  group_sid   text    NOT NULL,            -- canonical S-1-5-21-...-RID
  role        role    NOT NULL,            -- reuses the existing `role` enum
  group_cn    text,                        -- display only; never used for matching
  created_by  uuid    REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_sid, role)
);
```

Resolution at login / cache-fill:

```
tokenGroups(user)  ->  { sid_1, sid_2, ... }
roles = ⋃ { r | (sid, r) ∈ directory_role_map, sid ∈ tokenGroups(user) }
```

- **Default deny:** a user in **no** mapped group gets **no roles** → no capabilities. (Optionally a configurable floor role such as `Viewer` for any authenticated directory user — off by default.)
- **Precedence is a non-issue** because capabilities union; there is no "deny" role. If deny-style scoping is ever needed it belongs in the agent-grant layer (§4), not here.

### 3.2 Administration

- Managed through new endpoints gated on the **existing** `Capability::ManageDirectory` (held by `Superadmin`): list/add/remove `(group_sid, role)` rows, plus a GC-backed "search groups by name" helper so admins pick a group by CN and the server records its SID. All mutations audited.
- The directory config itself (base DN, service account, URLs, TTLs) is server config (§7), not a per-request surface.

### 3.3 Why no handler changes

`Role::capabilities()` and `AuthUser::require()` are untouched. The only new producer of `Vec<Role>` is the directory resolver. This is the payoff of the capability indirection already in the codebase.

---

## 4. Restricting groups to only certain agents (the critical requirement)

> **Requirement.** Each security group may use **only** the cracking agents it is authorized for. This must be **enforced by the server** from **verified** group membership — **never** from an agent identifier or group claim supplied by the client.

### 4.1 Threat model and the non-negotiable invariant

The attack to design out: a user (or a stolen API key, or a malicious client build) submitting a job and *naming* a privileged agent, or *asserting* a group it isn't in, to run work on hardware it shouldn't touch. Therefore:

- The set of agents a job may run on is **derived on the server** from the **owner's `objectSid`-based group membership**, which came from a **TLS'd, service-account-verified directory query** (or a server-signed, short-TTL cache of it). It is **not** a request field. The API has **no parameter** that lets a caller choose an agent, a pool, or a group for a job. If such a field ever appears in a request body, it is **ignored**.
- Group membership enters the server only via the directory (verified) and is represented internally by SID. The JWT carries *roles* (server-signed), but **agent authorization is re-derived server-side from the stored SID**, not trusted from the token — so even a token minted before a grant change is bounded by the cache TTL, and a forged token can't widen agent access because the server recomputes against `directory_agent_grants`.

### 4.2 Concepts: agent pools and directory grants

Two new ideas, both server-side:

- **Agent pool** — a named set of agents (e.g. `gpu-farm-a`, `isolated-redteam`, `pci-scope`). Agents are assigned to pools by an admin (`ManageAgents`). An agent may belong to one or more pools. Pools are the unit of authorization and of fairness accounting.
- **Directory agent grant** — a row mapping a **group SID → pool**. A user's **authorized pool set** is the union of pools granted to any group in their `tokenGroups`. The job's **eligible agent set** = the agents in those pools.

```sql
CREATE TABLE agent_pools (
  id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name  text NOT NULL UNIQUE
);
CREATE TABLE agent_pool_members (
  pool_id  uuid NOT NULL REFERENCES agent_pools(id) ON DELETE CASCADE,
  agent_id uuid NOT NULL REFERENCES agents(id)       ON DELETE CASCADE,
  PRIMARY KEY (pool_id, agent_id)
);
CREATE TABLE directory_agent_grants (
  group_sid text NOT NULL,                       -- verified group SID
  pool_id   uuid NOT NULL REFERENCES agent_pools(id) ON DELETE CASCADE,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_sid, pool_id)
);
```

### 4.3 Binding a job to its eligible agents (snapshot + re-verify)

At **submit time**, `create_job` already runs under `auth.require(Capability::SubmitJobs)`. We add, server-side:

1. Resolve the submitter's authorized pool set from their stored `objectSid` via `directory_agent_grants` (using the short-TTL cached membership; re-query the directory if cold and fail closed).
2. Compute the eligible agent set = members of those pools. If **empty**, reject the submission with a clear 403 (`no authorized agents for your groups`) rather than silently queuing something that can never run.
3. **Snapshot** the resolved set onto the job, *and* record the owning group context for fairness (§5):

```sql
ALTER TABLE jobs
  ADD COLUMN owner_group_sid text,                 -- the group charged for fairness/quota
  ADD COLUMN eligible_pool_ids uuid[] NOT NULL DEFAULT '{}';
```

The snapshot is an **optimization and an audit record**, not the trust boundary. The scheduler **re-derives and intersects** the eligible agent set from `directory_agent_grants` **at assignment time** too, so that revoking a grant or moving an agent out of a pool takes effect on the *next* chunk even for an already-running job (see §4.5 edge cases). Belt and suspenders: the snapshot bounds what was authorized at submit; the live re-derivation ensures a *narrowing* of authorization is honored promptly.

Where multiple pools/groups apply, pick the **owning group** for fairness deterministically (e.g. an explicit per-user default group, else the lowest-SID granted group), and record it in `owner_group_sid`. Eligibility is still the **union** of all the user's pools; only the *accounting* identity is singular.

### 4.4 Enforcement point: the scheduler/`AgentHub`, not the API

Agent selection lives entirely in `AgentHub` today and is pool-blind. We make assignment **pool-aware** and drive it from the job's server-derived eligible set:

- `AgentHub::drain()` and `keyspace_probe()` change from "find any agent with a free slot" to "find a free agent **whose `agent_id` is in the allowed set for this chunk's job**." The allowed set is passed down from the scheduler (which owns the job→pool resolution); `AgentHub` never reads a client field.
- `capacity()` becomes **per eligible-set** (or per pool): the scheduler asks "how many free slots exist **among agents eligible for job J**," not "across the whole fleet," so it never plans more in-flight chunks than the job can actually be placed on.
- Concretely, carry the allowed `agent_id` set on the internal `AgentTask`/`RunnerTask` the scheduler already hands to the hub; the hub filters its `conns` iteration by it. No route handler and no wire message gains an agent selector.

```
// today (agent.rs, drain):
let Some((&agent_id, _)) = g.conns.iter().find(|(_, c)| c.slots > 0) else { ... };

// Phase 5:
let Some((&agent_id, _)) = g.conns.iter()
    .find(|(id, c)| c.slots > 0 && task.allowed_agents.contains(id)) else { ... };
```

Because `allowed_agents` originates only from the server-side resolution of a **verified** SID, there is no code path by which a client can place work on an agent outside its grant.

### 4.5 Edge cases

- **Membership or grant changes mid-job.** The scheduler re-derives eligibility per assignment, so a *narrowed* authorization (revoked grant, agent removed from pool) stops new chunks landing on now-forbidden agents within one tick/TTL; chunks already running there finish (chunks are short — prefer draining at boundaries over killing). A *widened* authorization simply makes more agents eligible on the next pass.
- **No eligible agent currently connected.** The job stays `queued` (it was validly authorized at submit) and the dashboard shows "waiting for an authorized agent," distinct from the submit-time **reject** when the user has *no* grants at all.
- **Agent in multiple pools.** Fine; it's eligible if it's in *any* of the job's pools. Fairness accounting still charges the job's single `owner_group_sid`.
- **Local/break-glass admin.** A local `Superadmin` with `ManageAgents` administers pools; whether a local account may submit jobs to all pools is a config choice (default: local non-directory users get an explicit pool grant or none).

### 4.6 Why this is "server-enforced from verified membership"

To restate the chain of custody: *TLS-validated directory* → *service-account-verified `tokenGroups`* → *SID set* → *`directory_agent_grants` (server table)* → *eligible agent set computed in the scheduler* → *`AgentHub` filters assignment by it*. The only client inputs are the login credentials (verified by bind) and the job parameters (hashlist, attack mode) — **never** the agent, pool, or group. That is the requirement, satisfied structurally rather than by validation of a client-provided value.

---

## 5. Fairness and quotas at scale

### 5.1 What today's scheduler can't do

`fill_fleet` round-robins **one chunk per running job** across a **global** capacity. With many groups this has two failure modes: a group that submits 50 jobs gets 50× the fleet share of a group with one job (fairness is per-job, not per-tenant), and nothing caps a single group's concurrent GPU occupancy. At scale we need **tenant-aware** fairness where **tenant = owning directory group** (`jobs.owner_group_sid`), composed with the per-group agent eligibility from §4.

Helpfully, the problem is **single-resource**: a chunk ≈ one GPU-slot of near-uniform size. That means the heavy multi-resource machinery (DRF) is unnecessary; **weighted max-min fairness via Deficit/Weighted Round Robin** is the right tool, and the HPC fair-share primitives (Slurm) and quota-with-borrowing primitives (Kueue) map almost directly.

### 5.2 Layered design (admission → ordering → dispatch), per pool

Fairness is computed **within each pool** (the fairness domain), because a group restricted to `gpu-farm-a` neither competes for nor is starved by activity on `isolated-redteam`.

**(a) Hard per-group caps — eligibility gate, checked first (cheap).**
A counting semaphore on in-flight chunks per group (optionally per group×pool):

```sql
CREATE TABLE group_quota (
  group_sid        text PRIMARY KEY,
  weight           integer NOT NULL DEFAULT 100,  -- fair-share weight
  floor_slots      integer NOT NULL DEFAULT 0,    -- guaranteed concurrent chunks
  ceil_slots       integer,                       -- burst ceiling (NULL = pool size)
  max_submit_jobs  integer                        -- queued+running backpressure (NULL = unlimited)
);
```

A group at `ceil_slots` (or `max_submit_jobs`) is simply **skipped** by the dispatcher — the Slurm `GrpTRES`/`GrpSubmitJobs` and Kueue `nominalQuota` analog. Keep floor and ceiling **separate**: the floor is always honorable; the ceiling is only reachable by borrowing idle capacity.

**(b) Weighted fair share of leftover capacity — Deficit Round Robin.**
Among groups in a pool that passed (a) and have pending chunks, dispatch via **weighted DRR**: each group queue carries a **deficit counter**; each sweep add a quantum `Q ∝ weight`; serve chunks while `deficit ≥ chunk_cost`, carrying the remainder. With uniform chunks this degenerates to **weighted round-robin + carry** and is **O(1) per chunk** — no WFQ virtual-clock bookkeeping. This replaces the per-job round-robin in `fill_fleet` with a **per-group** round-robin, and *within* a group, the existing per-job round-robin (or job `priority`) decides which of that group's jobs gets the slot.

**(c) Anti-starvation (aging + decay).**
Add an **age bonus** to a group's/job's effective priority that grows with queue wait and **saturates** at a cap (Slurm's `age_factor`→1.0 at `PriorityMaxAge`), so a low-weight group can't be indefinitely out-competed. Track per-group **decayed usage** (EWMA / half-life) so a once-heavy group isn't penalized forever; a Fair-Tree-style `shares/usage` bias can replace static weights if share-accuracy over long horizons matters. Without decay, fairness counters become a slow starvation mechanism.

**(d) Work-conserving borrowing + lazy reclaim.**
Idle agents in a pool should never sit idle while any eligible group has pending work. Let a group **borrow** above its floor up to `ceil_slots` when others are under-demanding (Kueue cohort borrowing / YARN `maximum-capacity` / HTB `ceil`). When an **under-floor** group gains demand, **stop handing the borrower new chunks** (lazy reclaim) and prefer **draining at chunk boundaries** to killing mid-chunk — chunks are short, so true preemption is rarely needed. If preemption is ever added, copy YARN's safeguards: grace-before-kill, a per-round reclaim cap, and a dead-zone to stop oscillation.

### 5.3 Mapping onto `scheduler.rs`

- `fillable_jobs()` → `fillable_groups_in_pool(pool)` returning groups with pending, eligible chunks, ordered by the DRR deficit + age bonus; within a chosen group, reuse the existing job ordering.
- `fill_fleet()` iterates **per pool**: `want = capacity_in_pool(pool)`, then weighted-DRR dispatch honoring each group's `floor/ceil` and in-flight count. The existing `next_pending_chunk(job)` and `start_chunk(...)` are reused unchanged for the actual placement; only the *selection* of whose chunk goes next changes.
- `capacity()` (agent.rs) gains a pool-scoped variant (§4.4). In-flight counts per group come from a cheap join (`tasks` running × `jobs.owner_group_sid`), or an in-memory counter kept alongside the `AgentHub` assignment map.
- Quotas and weights are read from `group_quota` (admin-managed under `ManageDirectory`/`ManageAgents`), cached with the directory resolution.

### 5.4 Why not more

DRF, WFQ, and full preemption are deliberately out of scope: uniform single-resource chunks make them unnecessary complexity. The design is the **minimal correct composition** — hard caps, weighted DRR for leftover, aging+decay, borrow-then-reclaim — which is exactly the shape Kueue (nominal/borrow/lend) and Slurm (QOS limits + Fair Tree + age) converge on for this class of problem.

---

## 6. New data model (summary)

`migrations/0005_directory.sql` (names illustrative):

- `directory_role_map(group_sid, role, group_cn, …)` — §3.
- `agent_pools(id, name)`, `agent_pool_members(pool_id, agent_id)` — §4.
- `directory_agent_grants(group_sid, pool_id, …)` — §4.
- `group_quota(group_sid, weight, floor_slots, ceil_slots, max_submit_jobs)` — §5.
- `users` gains `external_sid text UNIQUE NULL` (directory `objectSid`; NULL for local accounts) and `auth_source text` (`local` | `directory`).
- `jobs` gains `owner_group_sid text` and `eligible_pool_ids uuid[]` — §4.3.
- Reuse existing `role` enum, `agents`, `audit_events`, `user_roles` (now only for local accounts).

All matching is on SID; CNs are display-only.

## 7. Configuration (summary)

New `FJ_DIRECTORY__*` config block (mirrors the existing `FJ_*` env convention):

- `enabled` (bool), `url` (`ldaps://dc.corp.example`), `start_tls` (bool), `ca_bundle` (path), `verify_hostname` (default true).
- `base_dn`, `bind_dn` (service account), `bind_password` (secret ref/env — not inline), `user_filter` template, `login_attributes` (`sAMAccountName,userPrincipalName,mail`).
- `use_global_catalog` (bool), `dc_discovery` (`srv` | `static`), `servers` (static fallback list).
- `group_source` (`token_groups` default | `matching_rule_in_chain`), `cache_ttl_secs` (default 600), `on_directory_down` (`fail_closed` default | `cache_only`).
- `default_role` (default none), `jwt_ttl_hours` (keep ≤ 8).

## 8. Security considerations

- **LDAP injection:** every user-supplied value interpolated into a filter is escaped per **RFC 4515** (`*`→`\2a`, `(`→`\28`, `)`→`\29`, `\`→`\5c`, NUL→`\00`); DN components escaped per RFC 4514. Use an encoder, not string concat; additionally allowlist the login charset. `ldap3` does not parameterize filters — escaping is the app's responsibility.
- **Empty-password unauthenticated bind:** reject empty/whitespace passwords in flamejob **before** any bind; AD may return success (code 0) for a non-empty DN + empty password. Do not rely on the server.
- **Anonymous bind / referrals:** never use anonymous bind for the service account; disable referral chasing (credential-leak / SSRF risk).
- **Fail-closed by default** when the directory is unreachable and the cache is cold (§2.6). Break-glass **local** `Superadmin` remains usable.
- **Least privilege & secrets:** read-only service account with no reset rights; password in a secret manager/env, never plaintext config.
- **Lockout safety:** rate-limit auth so a bad-password storm can't lock out real AD users.
- **Audit everything** (§2.7) into `audit_events`.
- **Authorization trust boundary (the headline):** agent/pool/group are **never** client inputs; the server derives agent eligibility from verified SID membership and enforces it in the scheduler (§4).

## 9. Rollout and testing

**Phased:**
1. **Shadow auth, no enforcement.** Directory login + role mapping behind `FJ_DIRECTORY__ENABLED`; local auth still primary. Verify resolved roles/SIDs in the audit log against expectations.
2. **Pools + grants, advisory.** Create pools, assign agents, define grants; log what *would* be eligible per job without yet constraining placement. Compare against intent.
3. **Enforce agent eligibility.** Flip `AgentHub` to filter by the server-derived allowed set (§4.4). Jobs with no eligible agent now wait/reject.
4. **Fairness layer.** Enable per-group quotas + weighted DRR + aging (§5). Start with generous ceilings; tighten.

**Testing** (the repo's model is pure-unit + e2e harness; no GPU in sandbox):
- **Pure unit tests** (the codebase's strength): SID parsing/formatting; RFC-4515 escaping (including the SID-as-binary-filter case); `tokenGroups → roles` resolution; `tokenGroups → pools → eligible agents`; the empty-password guard; DRR dispatch order and deficit carry; floor/ceil cap enforcement; aging saturation; the "narrowed grant stops next chunk" re-derivation.
- **Directory integration tests** against a disposable **Samba AD DC** (implements `tokenGroups` and `1.2.840.113556.1.4.1941`) or OpenLDAP in CI — nested groups, primary group, disabled account, paging, StartTLS cert validation, fail-closed on DC-down.
- **Scheduler simulation** (no real agents, the existing pattern): mock `AgentHub` with virtual pools/slots; assert no chunk is ever placed outside a job's eligible set, that floors are honored under contention, that a flood group can't exceed its ceiling, and that a starved low-weight group eventually runs (aging).
- **Negative/abuse tests:** a request body carrying an `agent_id`/`pool`/`group` field is ignored; a forged/stale JWT cannot widen agent eligibility (server re-derives from SID); an API key reflects a grant revocation within one TTL.

## 10. Open questions / future work

- **Data-level tenancy:** this design isolates compute (agents) and governance (roles/quotas) but not cracked-plaintext visibility across groups. Row-scoping `hashlists`/`hashes`/`jobs` by owning group (and gating `ViewPlaintext` per group) is a natural follow-on.
- **Nested-pool / hierarchical groups** (org → team quotas) à la Slurm Fair Tree / HNC, if deployments need sub-group budgets.
- **Agent self-attestation to a pool** (e.g. pools inferred from enrollment claim metadata) vs purely admin-assigned membership.
- **GSSAPI/SPNEGO SSO** as a first-class in-process option rather than edge-terminated, if demand warrants the Kerberos operational surface.
- **SID history** honoring for AD migrations.

---

## Appendix A — concrete LDAP reference

- Transitive member (nested): `1.2.840.113556.1.4.1941` · Bitwise-AND: `1.2.840.113556.1.4.803` · Paged results: `1.2.840.113556.1.4.319` · StartTLS: `1.3.6.1.4.1.1466.20037`.
- `userAccountControl` `ACCOUNTDISABLE` = `0x2`. Bind failure sub-codes under result `49`: `52e` bad creds, `533` disabled, `775` locked, `532`/`773` password expired/must-reset, `530` time-restricted.
- Effective-groups read: base-scope search of the user DN, filter `(objectClass=*)`, request attribute `tokenGroups` (binary SIDs); prefer a Global Catalog (3268/3269).
- Key attributes: `sAMAccountName`, `userPrincipalName`, `mail`, `distinguishedName`, `memberOf`, `primaryGroupID`, `tokenGroups`, `objectSid`, `userAccountControl`.

## Appendix B — sources

**AD/LDAP**
- RFC 4515 (filter escaping): https://datatracker.ietf.org/doc/rfc4515/
- OWASP LDAP Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- MS-ADTS `tokenGroups`/`tokenGroupsNoGCAcceptable`: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/01002598-92db-4c59-822e-b22f53168c90
- AD schema — `tokenGroups`: https://learn.microsoft.com/en-us/windows/win32/adschema/a-tokengroups
- Samba wiki — TokenGroups / primary & nested groups: https://wiki.samba.org/index.php/TokenGroups
- MS KB305144 — `userAccountControl` flags: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
- Nested-group validation with OID 1.2.840.113556.1.4.1941 (Citrix): https://support.citrix.com/external/article/CTX237210/how-to-configure-ldap-nested-group-valid.html
- 389-ds matching-rule-in-chain design: https://www.port389.org/docs/389ds/design/matching-rule-in-chain.html
- MS-ADTS SSL/TLS (LDAPS/StartTLS): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81
- LDAP signing & channel binding: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/configure-ldap-signing-certificates
- Why unauthenticated binds should be disabled (Devolutions): https://devolutions.net/blog/why-active-directory-ldap-unauthenticated-binds-should-be-disabled-and-how-to-do-it/
- `ldap3` crate docs: https://docs.rs/ldap3/
- RFC 2696 (Simple Paged Results): https://datatracker.ietf.org/doc/rfc2696/

**Fairness & quotas**
- DRF paper (Ghodsi et al., NSDI 2011): https://www.cs.berkeley.edu/~alig/papers/drf.pdf
- Deficit Round Robin (Shreedhar & Varghese 1996; overview): https://en.wikipedia.org/wiki/Deficit_round_robin
- YARN Capacity Scheduler: https://hadoop.apache.org/docs/stable/hadoop-yarn/hadoop-yarn-site/CapacityScheduler.html
- Slurm Resource Limits (QOS, GrpTRES): https://slurm.schedmd.com/resource_limits.html
- Slurm Multifactor Priority (age, fair-share): https://slurm.schedmd.com/priority_multifactor.html
- Slurm Priority & Fair Tree (SLUG19): https://slurm.schedmd.com/SLUG19/Priority_and_Fair_Trees.pdf
- Kueue ClusterQueue (nominalQuota/borrowing/preemption): https://kueue.sigs.k8s.io/docs/concepts/cluster_queue/
- Kueue Cohort (borrow/lend): https://kueue.sigs.k8s.io/docs/concepts/cohort/
- Kubernetes ResourceQuota: https://kubernetes.io/docs/concepts/policy/resource-quotas/
- Nomad resource quotas: https://developer.hashicorp.com/nomad/docs/govern/resource-quotas
- Token bucket: https://en.wikipedia.org/wiki/Token_bucket
- Linux HTB (rate/ceil/borrow): https://www.iitk.ac.in/LDP/HOWTO/Traffic-Control-HOWTO/classful-qdiscs.html
- HPC job scheduling incl. EASY/conservative backfill (survey): https://arxiv.org/pdf/2109.09269

---

*Design doc prepared for the flamejob project. Internal code references are to `main` at v1.3.1.*
