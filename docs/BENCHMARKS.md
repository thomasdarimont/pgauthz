# Benchmarks

Reproducible microbenchmarks for the hot paths, organized as **suites** (one
per model). Run them yourself with:

```bash
./init.sh              # install the engine (once)
./bench/run.sh         # run every suite
./bench/run.sh drive   # run one suite by name
```

Each suite — [`bench/suites/<name>.sql`](../bench/suites/) — builds its own
model and dataset and times each operation in a loop (after warm-up), reporting
**ms per call**, via the shared harness
[`bench/lib/harness.sql`](../bench/lib/harness.sql). Tunables (user count,
group count, folder depth) are constants at the top of the suite's
data-generation block.

Five suites ship today, each a different model shape so the numbers cover
different resolution paths:

| Suite | Shape | Exercises |
|---|---|---|
| **`drive`** | Nested folders + groups, 50k users | direct, userset, `*` wildcard, deep TTU folder chain, time-travel |
| **`github`** | Orgs / teams / repos, role hierarchy | multi-level computed role chain, TTU to the parent org, **nested teams** (userset-of-userset) |
| **`rules`** | Synthetic rule-combination model | **intersection** (AND), **exclusion** (BUT NOT), **conditions** (ABAC) |
| **`adversarial`** | Diamond / converging graphs | stress for cross-branch re-evaluation — `2^depth` paths, collapsed to ~linear by the **per-check memo** (toggle with `authz.memoize`) |
| **`gates`** | Action log + temporal gates ([ADR 0012](adr/0012-action-log.md)) | what a gate adds to a check as a function of the events in its window (0 / 100 / 10k), containment matching, traced and two-pass paths, **gated enumeration**, recording, `reserve_event`, `list_events` |

Adding another — e.g. the demo's tax-advisor chain — is just another file in
`bench/suites/`.

## Methodology

Each suite builds its own store + dataset (the tunables are constants at the top
of the suite file) and times each operation in a warm loop.

**`drive` dataset** — a document system:

- 50,000 **users**, each owning/viewing a private document (the "large user
  base" that would make naïve `list_subjects` slow).
- 200 **groups** × 50 members (userset expansion).
- A 15-deep nested **folder** chain (`f1 ← … ← f15`) with `can_view` inheriting
  up the chain (`document.can_view = viewer OR owner OR parent→can_view`),
  exercising deep tuple-to-userset recursion.
- Special objects: a doc shared with 3 specific users, a `*`-wildcard public
  doc, a group-shared doc, and a doc at the bottom of the folder chain.
- **60,031 tuples** total, loaded in ~1.4 s. Every write also fires the audit
  trigger, so the audit log has ~60 k events for the time-travel test.

**`github` dataset** — 20,000 users, 40 orgs, 600 teams (×25 members), 2,000
repos. Roles chain `can_read ← can_write ← can_admin`, repos link to their org
via `parent_org` (TTU), and a 10-deep **nested-team** chain feeds one repo
(userset-of-userset). ~39 k tuples.

**`rules` dataset** — 20,000 users over 5,000 resources, plus a "hot" resource
with 500 subjects. `can_access = assigned AND cleared` (intersection),
`can_edit = editor BUT NOT banned` (exclusion), and `viewer` grants carry a
time-window **condition**. ~54 k tuples.

**`gates` dataset** — 2,000 users with tuples on one account; **220,100
events** bulk-loaded into the action log: 200 k background events of those
users spread over a day, plus one "heavy" principal with 10,000 `pay`
requests and 10,000 `approve_sale` responses inside the last hour and a
"mid" principal with 100. Two gates: a two-clause velocity gate
(`count_within` + `sum_within` keyed on the request) on `pay`, and a
`formerly_within` with payload `match` and a `recorded_by` allowlist on
`withdraw`. An ungated relation on the same store is the baseline.

**`adversarial` dataset** — tiny (~1 k tuples) but pathological. A `node` model
with `can_view = viewer OR parent_a→can_view OR parent_b→can_view`, and **diamond
chains** where every link is doubled (`node_i` has *both* `parent_a` and
`parent_b` pointing to `node_{i+1}`), so the root reaches the leaf via **2^depth**
acyclic paths. Plus a wide-convergence node (one root → 500 intermediates → one
dead-end leaf). All DENY (no grant), to force full traversal.

**Environment** — these numbers were taken on a developer laptop:

- **Host:** MacBook Pro, Apple M3 Max, 64 GB RAM, 1 TB NVMe, macOS.
- **Database:** PostgreSQL 18.4 in a single Docker container (Docker Desktop
  Linux VM; ~16 vCPU / ~7.7 GB visible to the container), default-ish tuning —
  not production hardware, and not a tuned/bare-metal Postgres.

**Treat the absolute numbers as illustrative; the point is the scaling
behavior** (what each operation's cost is bounded by), which is
hardware-independent. Re-run on your own box for your own baseline.

## Results

Steady-state (warm cache), PostgreSQL 18.4. Run `./bench/run.sh` to reproduce.

### `drive` — folders + groups + 50k users (60,031 tuples)

| Operation | ms/op | Bounded by |
|---|--:|---|
| `check_access` — shallow (direct grant) | **0.04** | one index probe |
| `check_access` — via group membership (userset) | **0.09** | userset expansion |
| `check_access` — via `*` wildcard | **0.05** | one index probe |
| `check_access` — deep (15-folder TTU chain) | **1.48** | recursion depth |
| `check_access` — DENY (no path, full traversal) | **1.63** | recursion depth |
| `list_objects` — grant-sparse user (10 of 50,000 docs) | **0.49** | the user's reachable objects |
| `list_actions` (one user, one doc) | **1.83** | number of relations on the type |
| `check_access_with_contextual_tuples` (inject 1) | **0.16** | one index probe + injected set |
| `list_subjects` — `*` wildcard doc | **12.4** | O(1) — one `('*', …)` row |
| `list_subjects` — shared doc (3 of 50,000 users) | **12.1** | the object's reachable subjects |
| `list_subjects` — group doc (userset of 50) | **15.9** | the object's reachable subjects |
| `audit_check_access` — time-travel (replay ~60 k events) | **108** | audit-log size up to `p_at` |

### `github` — orgs / teams / repos, role hierarchy (39,092 tuples)

| Operation | ms/op | Bounded by |
|---|--:|---|
| `check_access` — org-admin `can_read` (4-level role chain) | **0.37** | length of the computed-role chain |
| `check_access` — org-member `can_read` (parent_org TTU) | **0.47** | one TTU hop |
| `check_access` — nested-team reader (10-deep userset chain) | **0.54** | nesting depth |
| `check_access` — `can_write` DENY for a plain reader | **0.28** | partial chain, no match |
| `check_access` — DENY (no path, full traversal) | **1.02** | graph size explored |
| `list_objects` — org-admin's repos (50 of 2,000) | **41** | the subject's reachable objects |
| `list_subjects` — repo readers (org members + a team) | **233** | the object's reachable subjects |
| `list_actions` (admin on a repo) | **1.0** | relations on the type |

### `rules` — intersection / exclusion / conditions (53,596 tuples)

| Operation | ms/op | Bounded by |
|---|--:|---|
| `check_access` — intersection ALLOW (`assigned AND cleared`) | **0.06** | one probe per AND term |
| `check_access` — intersection DENY (one term missing) | **0.10** | one probe per AND term |
| `check_access` — exclusion ALLOW (`editor BUT NOT banned`) | **0.10** | base + negated probe |
| `check_access` — exclusion DENY (negated term present) | **0.06** | base + negated probe |
| `check_access_with_context` — condition ALLOW (within window) | **0.06** | one probe + condition eval |
| `check_access_with_context` — condition DENY (expired) | **0.09** | one probe + condition eval |
| `list_objects` — intersection (20 of 5,000 resources) | **1.0** | the subject's reachable objects |
| `list_subjects` — intersection on hot resource (500) | **20** | the object's reachable subjects |
| `list_subjects` — exclusion on hot resource (450 of 500) | **39** | the object's reachable subjects |

Numbers are steady-state on PostgreSQL 18.4; a cold buffer cache (e.g. the first
call right after a bulk load) is slower — `drive`'s `list_objects` was ~70 ms
cold vs ~0.5 ms warm.

### `adversarial` — diamond / converging graphs (~1k tuples)

A `check_access` DENY on a doubled-link diamond chain, by depth (paths =
2^depth), **with the memoization wrapper** (the default):

| Operation | ms/op (memoized) | was, un-memoized |
|---|--:|--:|
| diamond DENY — depth 6 (2^6 = 64 paths) | **1.2** | 12 |
| diamond DENY — depth 9 (2^9 = 512 paths) | **1.5** | 93 |
| diamond DENY — depth 12 (2^12 = 4,096 paths) | **1.9** | 732 |
| wide fan-out DENY — 500 parents converging on one leaf | **56** | 87 |

The cross-branch memo (below) collapses the `2^depth` blow-up to ~linear: a
depth-28 diamond (2^28 ≈ 270 M paths) resolves in ~12 ms and stays flat with
depth. **Un-memoized** (`SET authz.memoize = 'off'`) the same checks are
exponential — depth 14 ≈ 3 s, depth 16 ≈ 12 s, depth 18 exceeds 30 s.

### `gates` — action log + temporal gates (220,100 events)

| Operation | ms/op | Bounded by |
|---|--:|---|
| `check_access` — ungated relation (baseline) | **0.15** | one index probe |
| `check_access` — gated, 0 events in window | **0.24** | gate lookup + one empty window probe per clause |
| `check_access` — gated, 100 events in window | **0.34** | events in the window |
| `check_access` — gated, 10,000 events in window (count + sum) | **10.9** | events in the window (sum reads each payload) |
| `check_access` — `formerly_within` + `match` over 10,000 events | **3.6** | events in the window (containment scan) |
| `check_access` — gated DENY on a missing `$request` key | **0.24** | fails before any window query |
| `explain_access` — gated (traced, 2 clauses) | **0.73** | trace + every clause evaluated |
| `check_access_detailed` — `conditional` (two passes) | **0.78** | two evaluations |
| `list_subjects` — ungated (2,000 candidates) | **277** | the object's reachable subjects |
| `list_subjects` — gated (2,000 candidates, a window query each) | **485** | + ~0.1 ms per candidate |
| `list_objects` — gated (evaluated once up front) | **13.5** | one gate evaluation + the walk |
| `list_actions` — 3 relations, 2 gated | **0.73** | one gate lookup per relation |
| `audit_check_access` — gated (time-travel) | **3.8** | snapshot replay + as-of window |
| `record_event` — single | **0.054** | three btree inserts |
| `record_events_jsonb` — batch of 100 | **5.3** | ≈ 0.05 per event |
| `reserve_event` — decision + record under the per-subject lock | **0.83** | check + insert |
| `list_events` — page of 100 for a subject | **0.26** | `idx_events_subject_list` (was 23 ms — see addendum) |

## Takeaways

- **`check_access` is sub-millisecond** for typical direct/userset/wildcard
  checks, and ~1.5 ms for a 15-level folder-inheritance chain. A full DENY
  traversal (no granting path) costs about the same as the deepest allow — the
  engine explores the graph, not the store.
- **Search is bounded by the reachable set, not the store size.** `list_subjects`
  resolves a 3-grantee object in a **50,000-user** store in ~12 ms — it does
  *not* scan the user base. (Before the reverse-expansion rewrite, the same
  query was O(users): ~11 s for a 3-grantee object in a 100 k-user store.)
  `list_objects` is likewise bounded by what the *subject* can reach, not the
  document count.
- **Wildcards collapse the broad cases to O(1).** A `*`-granted public doc
  returns a single `('*', is_wildcard)` row regardless of user count — model
  all-access/public relationships as wildcards (see the README "Object
  Wildcards" / "Wildcard Tuples" sections).
- **Depth is cheap; each hop is an index probe** (`github`). A 4-level computed
  role chain (`can_read ← can_write ← can_admin`), a TTU hop to the parent org,
  and a **10-deep nested-team** userset all resolve in ~0.4–0.5 ms — graph depth
  adds probes, not scans. The widest case, `list_subjects` for a repo readable by
  a whole org (~233 ms), is bounded by the *answer* size, not the store.
- **Rule combination and conditions add negligible cost** (`rules`).
  Intersection (`assigned AND cleared`), exclusion (`editor BUT NOT banned`), and
  a per-tuple SQL **condition** each resolve in ~0.06–0.10 ms — the AND/BUT-NOT
  combine operators and the zero-privilege condition sandbox are not where time
  goes; reachable-set size still dominates the `list_*` variants.
- **Converging graphs are memoized — `O(2^depth)` → linear** (`adversarial`).
- **A gate costs a fixed ~0.1 ms plus the events in its window** (`gates`):
  0.24 ms for an empty window against a 0.15 ms ungated check, then ~1 µs per
  event for a count and ~3× that for a sum (each payload is read). Keep windows
  and event volumes per principal in the thousands, not millions, or use
  calendar buckets. Enumeration pays the gate per candidate (`list_subjects`)
  or once (`list_objects`, subject-scoped gates).
  The evaluator prunes *cycles* (a path array stops a node already on the current
  path); without memoization a node reachable via many distinct acyclic paths is
  re-evaluated once per path, so a **diamond** graph (each link doubled) costs
  `O(2^depth)`. `_check_access` therefore wraps the resolver with a **per-check
  memo** (`access_internal.sql`): each `(relation, object)` sub-result is cached
  within one root check, collapsing diamonds and converging fan-out to ~linear (a
  depth-28 diamond went from "minutes / timeout" to ~12 ms).
  - **Correctness with cycles:** a result is cached **only** when its subtree
    triggered no cycle prune (a zero-prune subtree is provably path-independent),
    so the memoized decision is identical to the path-based one on every input —
    asserted differentially in `tests/sql/tests_memoization.sql` (memo on ≡ off
    across a cyclic graph). Cyclic subtrees are recomputed, never cached.
  - **Cost / control:** shallow nodes (`depth < 2`) skip the cache, so typical
    checks are unaffected (A/B: +~2% on a shallow check). Toggle with
    `SET authz.memoize = 'off'` (an ops kill-switch). Note `authz.max_depth`
    bounds recursion *depth*, not *path count*, so the memo — not the depth
    limit — is what makes deep lattices tractable; `statement_timeout` remains the
    final backstop.
  - **Read replicas:** the memo's session temp table can't be created in a
    read-only transaction, so on a hot standby (and any `READ ONLY` txn) the memo
    switches to a session-GUC `jsonb` backend — the only mutable scratch a
    standby allows. `set_config` is session-local, so the backend is
    concurrency-safe (no cross-session sharing). The visited (object, decision)
    payload is **cleared from the GUC before the check returns** (success or
    error, via a root-level handler), so it doesn't linger in the session.
    - *Typical checks* (a handful to a few hundred distinct subproblems): the
      GUC backend is essentially free. On an 18-deep converging diamond
      (DENY/full traversal): temp-table memo **4.6 ms**, GUC **3.9 ms**, no memo
      **1322 ms** — protected, ~340× faster than no memo.
    - *Pathological checks* (thousands of distinct subproblems in a single
      decision): the GUC re-parses/serializes the whole map per probe, so it
      degrades — measured on a fan of K leaves (DENY): K=1 000 → temp 150 ms /
      GUC 273 ms; K=10 000 → temp 1.5 s / GUC ~13–27 s. To bound this on a
      replica, `authz.memo_max_entries` (**default 5 000**) caps the GUC map and
      **fails fast** when a check would exceed it: it raises `memo_limit_exceeded`
      (SQLSTATE `53400`) rather than silently continuing un-memoized (which would
      reintroduce the pathological re-work). The caller should catch that and
      **retry on the primary** — a writable connection uses the uncapped
      temp-table backend, which handles such checks (and the primary is already
      ~seconds for them). Set `authz.memo_max_entries = 0` to disable the cap
      (unlimited, no abort). `statement_timeout` is the final backstop on both
      backends. *(Client-side automatic primary-fallback on `memo_limit_exceeded`
      is a consumer responsibility — the engine on a replica can't reach the
      primary itself.)*

    The map lives in normal backend memory (not `work_mem` / `temp_buffers`).
    Normal tree/DAG hierarchies are unaffected.
  - **Time-travel too:** the point-in-time evaluator (`audit_check_access`,
    `audit_list_actions`) is a separate snapshot resolver but mirrors the same
    structure, so it gets the **same wrapper** (`_check_access_snapshot` in
    `audit_internal.sql`, independent `_snap` memo + prune counter, same
    `authz.memoize` switch). A depth-12 diamond DENY against the replayed
    snapshot dropped from **1.6 s → 6 ms**; equivalence (memo on ≡ off, and
    snapshot ≡ live) is asserted by the same differential test.
- **Time-travel cost scales with the audit-log size** replayed up to the
  target timestamp (~108 ms at 60 k events here). It is a forensic/compliance
  path, not a hot path — keep it off latency-critical flows, and retain the
  audit log per your needs (see [PRODUCTION.md → Audit retention](PRODUCTION.md#audit-retention)).
  Effectively all of that cost is rebuilding the point-in-time snapshot (a full
  scan + `DISTINCT ON` sort of the store's audit log); the graph traversal
  itself is ~0.1 ms. If time-travel ever needs to be sublinear, the lever is
  periodic **materialized snapshots/checkpoints** so a replay only covers the
  delta since the last checkpoint (the deferred materialized-permissions
  direction in `db/replication/`) — not worth it for a forensic path today.

## Scaling the benchmark / adding suites

Edit the tunable constants at the top of a suite's data-generation block (e.g.
`bench/suites/drive.sql`: `n_users`, `n_groups`, `grp_size`, `depth`) and re-run
`./bench/run.sh <suite>`. The search and check numbers should stay roughly flat
as `n_users` grows (they are bounded by the reachable set, not the store size) —
the property worth verifying on your own data shapes.

To benchmark a **different model**, add `bench/suites/<name>.sql`: build a store
+ data, then time scenarios with the shared helpers (`pg_temp._bench(label,
sql, iters)` and `pg_temp._bench_title(text)` from the harness). `./bench/run.sh
<name>` runs it; `./bench/run.sh` with no args runs every suite.

## Addendum: re-run 2026-07-05 (native expiry / RLS in place)

Re-measured after `tuples.expires_at` landed (row-level security on
`authz.tuples` enforces expiry structurally on every read path). Two
findings, kept separate deliberately:

**1. Expiry/RLS overhead (A/B on the same build, drive suite):** checks pay
roughly **+5–15%** (shallow 0.144 → 0.157 ms/op; userset ~unchanged), large
`list_objects` scans up to **~+50%** (81.5 → 127 ms/op on the grant-sparse
case). The transaction-local escape-GUC arm of the policy is free within
noise (127 vs 132 ms/op). This buys fail-closed structural enforcement — an
expired tuple cannot grant through ANY of the ~37 tuple-scan sites, present
or future.

**2. `list_objects` partition-count scaling defect — FOUND AND FIXED
(2026-07-05).** The apparent 160–270× "baseline drift" was neither drift nor
a code regression: `list_objects`' reachability expansion scans tuples
**by subject**, leaving the partition key (`object_type`) unconstrained — so
every recursion iteration scanned **every tuple partition of every store in
the database** (168 partitions from just 3 stores here; hash sub-partitioning
multiplies). The original table was measured on a clean, few-partition
database, which masked it. This would have degraded linearly with tenant
count in store-per-tenant deployments. **Fix:** the three subject-rooted
scans now carry `object_type IN (SELECT id FROM authz.types WHERE store_id =
…)` — a tautology the executor turns into startup-time partition pruning
down to the store's own partitions. Measured: raw expansion 94.6 → 0.8 ms;
end-to-end sparse `list_objects` 133.9 → 4.6 ms/op, rules-suite intersection
124 → 12 ms/op, github 243 → 129 ms/op (the remainder is real per-candidate
confirmation work). The check paths are object-rooted and were never
affected.

Representative 2026-07-05 numbers (expiry enforcement active, pruning fix
in, 168-partition database): shallow 0.16 · deep TTU 3.2 · userset 0.28 ·
DENY 3.4 · wildcard 0.15 · list_objects sparse 4.6 · list_subjects shared
13 · list_actions 4.5 · contextual 0.28 ms/op. Residual ~2× vs the original
table on deep checks / list_subjects is environmental (audit-log growth,
expiry-RLS overhead, machine state) — to be re-baselined properly in the
production-scale benchmark milestone.

## Addendum: 2026-09-26 (action log + temporal gates, ADR 0012)

**1. The `_decide` seam on gate-free stores — A/B against `main` on the same
machine, both after a fresh install:** every existing suite is within
run-to-run noise. The cheapest allow paths move a few percent (drive
shallow 0.137 → 0.141, wildcard 0.146 → 0.152, rules intersection ALLOW
0.154 → 0.161 ms/op) and `list_actions` ~10% (drive 3.01 → 3.36; it now
performs one gate lookup per relation), while several DENY and deep paths
came out marginally *faster* (drive DENY 2.50 → 2.27, github nested-team
0.82 → 0.80). A first run right after `docker compose --build` and on a
test-bloated database had shown +50–200% across the board — environmental
(concurrent image build, index bloat), reproduced neither way after the
reinstall. Relations without gates pay one probe on the
`model_gates (store_id, object_type, relation, name)` index and nothing
else.

**2. `list_events` — FOUND AND FIXED.** A page of 100 events for one subject
took **23 ms and 191k buffers** on a 220k-row log: the filters were written
as `(param IS NULL OR col = param)`, which the generic plan a plpgsql function
settles on cannot fold into index conditions, and the only usable index
carried `action` before `occurred_at`, so the planner walked the time-ordered
primary key until it had found a page of that subject's rows — the whole log
when the subject's events sit at the end of the time order (a recently
active subject). Two changes, needed *together* (each alone measured no
gain): `list_events` builds its predicate list dynamically from the filters
supplied, and migration 0012 adds `idx_events_subject_list (store_id,
subject_type, subject_id, occurred_at, seq)`. Result **0.26 ms**;
`record_event` pays the extra btree (0.050 → 0.054 ms). Because the index is
keyed on the pair, `p_subject_id` now requires `p_subject_type` (a subject
*is* a pair). Listing by `action` alone still walks the primary key
(24 ms here); bound it with `p_since` or a cursor, or ask for an index if it
becomes a workload.

**3. A `kind`-inclusive window index was measured and rejected:** it turned
the raw count into an index-only scan (2.2 → 1.6 ms over 10k events) but the
gated check moved only 9.6 → 8.9 ms — the sum clause's payload reads
dominate, and the index would not help those.

## Addendum: 2026-09-28 (payload schemas, migration 0014)

All five suites rerun after a fresh install; every number outside the
recording paths is within run-to-run noise of the table above (the machine
alternates between a "quiet" and a ~10–20 % slower run — `check_access`
ungated baseline 0.136 / 0.147 / 0.161 ms across three consecutive gates runs,
`audit_check_access` 3.9 / 4.0 / 9.9 ms — so compare like with like).

**Recording paid for the schema lookup once, then didn't.** The first cut
called a separate `_event_check_payload(action, …)` per event which probed
`relations` by primary key even when the relation declares no schema:
`record_event` 0.054 → 0.060–0.064 ms, batch of 100 5.3 → 5.9–6.1 ms (+10 %).
Folding the schema into the relation-name lookup `record_event` already does
(one `SELECT id, payload_schema … WHERE store_id = $1 AND name = $2`) and
skipping the check when the schema is NULL brought both back to parity:
0.056 / 5.5 ms on a quiet run, 0.061 / 5.7 on a slow one. A relation *with*
a schema pays the check itself — a handful of `#>` path extractions per
declared path, microseconds — which is the price of the guarantee, not of the
feature's existence.

Gate evaluation is untouched by W5 (the cross-check runs at `add_gate` time
only): gated check with 0 / 100 / 10k events 0.24 / 0.35 / 11.8 ms,
`reserve_event` 0.86 ms, `list_events` page 0.26 ms.

**Second run, same day (after the `allowed` write precondition, the gate
cross-check change and the agents/aia-acme examples):** all five suites
within the noise band above; nothing on the read path changed and nothing
moved. One drive wildcard sample read 0.43 ms once and 0.16 / 0.15 on two
reruns — a single-sample outlier, not a regression. Not covered by this
suite: the `allowed` precondition (a write-path check; costs one
`check_access` inside the write's transaction) and pgauthzd's decision log
(ADR 0013; daemon-side, one JSON encode per decision, off by default).
