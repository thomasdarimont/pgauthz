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

Three suites ship today, each a different model shape so the numbers cover
different resolution paths:

| Suite | Shape | Exercises |
|---|---|---|
| **`drive`** | Nested folders + groups, 50k users | direct, userset, `*` wildcard, deep TTU folder chain, time-travel |
| **`github`** | Orgs / teams / repos, role hierarchy | multi-level computed role chain, TTU to the parent org, **nested teams** (userset-of-userset) |
| **`rules`** | Synthetic rule-combination model | **intersection** (AND), **exclusion** (BUT NOT), **conditions** (ABAC) |
| **`adversarial`** | Diamond / converging graphs | worst case for an evaluator with **no cross-branch memoization** — exponential `2^depth` re-evaluation |

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

A `check_access` DENY on a doubled-link diamond chain, by depth (paths = 2^depth):

| Operation | ms/op | Bounded by |
|---|--:|---|
| diamond DENY — depth 6 (2^6 = 64 paths) | **12** | re-evaluated sub-problems |
| diamond DENY — depth 9 (2^9 = 512 paths) | **93** | ~×8 per +3 depth |
| diamond DENY — depth 12 (2^12 = 4,096 paths) | **732** | ~×8 per +3 depth (= **2^depth**) |
| wide fan-out DENY — 500 parents converging on one leaf | **87** | linear in fan-out (500× one leaf) |

This is a **known worst case, not a representative workload** — see the takeaway
below. Probed further: depth 14 ≈ 3.0 s, depth 16 ≈ 12 s, depth 18 exceeds 30 s.

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
- **⚠️ Converging graphs are an exponential worst case — no cross-branch
  memoization** (`adversarial`). The evaluator prunes *cycles* (a path array
  stops a node already on the current path) but does **not** cache a completed
  `(relation, object)` sub-result, so a node reachable via many distinct acyclic
  paths is re-evaluated once per path. A **diamond** graph (each link doubled)
  therefore costs `O(2^depth)` — ~×8 per +3 depth, 0.7 s at depth 12, ~12 s at
  depth 16. **`authz.max_depth` does not protect against this** — it bounds the
  recursion *depth* (default 32), not the *number of paths* within that depth, so
  a depth-30 diamond stays under the limit yet explores ~10⁹ paths.
  `statement_timeout` is the only backstop today.
  - **Mitigations now:** avoid diamond/lattice-shaped models (multiple
    relations/parents converging on the same node through many paths); keep
    `authz.max_depth` modest; rely on `statement_timeout` to fail-close runaway
    checks. Normal hierarchical models (tree-shaped parents, the `drive`/`github`
    shapes) do **not** hit this — they stay linear.
  - **Fix:** a per-call memo (cache each `(relation, object)` sub-result within a
    single `check_access`) collapses both the diamond and the fan-out to roughly
    linear. Tracked as future work; this suite is the before/after harness for it.
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
