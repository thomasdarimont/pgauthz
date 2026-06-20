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

One suite ships today — **`drive`** (below). The structure makes adding more —
e.g. a GitHub-style model or the demo's tax-advisor chain — a matter of
dropping a new file in `bench/suites/`.

## Methodology

**Dataset** — a `bench` store modelling a document system:

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

**Environment** — these numbers were taken on a developer laptop:

- **Host:** MacBook Pro, Apple M3 Max, 64 GB RAM, 1 TB NVMe, macOS.
- **Database:** PostgreSQL 18.4 in a single Docker container (Docker Desktop
  Linux VM; ~16 vCPU / ~7.7 GB visible to the container), default-ish tuning —
  not production hardware, and not a tuned/bare-metal Postgres.

**Treat the absolute numbers as illustrative; the point is the scaling
behavior** (what each operation's cost is bounded by), which is
hardware-independent. Re-run on your own box for your own baseline.

## Results

Steady-state (warm cache); `drive` suite, 60,031 tuples.

| Operation | ms/op | Bounded by |
|---|--:|---|
| `check_access` — shallow (direct grant) | **0.05** | one index probe |
| `check_access` — via group membership (userset) | **0.13** | userset expansion |
| `check_access` — via `*` wildcard | **0.06** | one index probe |
| `check_access` — deep (15-folder TTU chain) | **2.47** | recursion depth |
| `check_access` — DENY (no path, full traversal) | **2.53** | recursion depth |
| `list_objects` — grant-sparse user (10 of 50,000 docs) | **0.97** | the user's reachable objects |
| `list_actions` (one user, one doc) | **3.06** | number of relations on the type |
| `check_access_with_contextual_tuples` (inject 1) | **0.19** | one index probe + injected set |
| `list_subjects` — `*` wildcard doc | **13.0** | O(1) — one `('*', …)` row |
| `list_subjects` — shared doc (3 of 50,000 users) | **13.1** | the object's reachable subjects |
| `list_subjects` — group doc (userset of 50) | **18.6** | the object's reachable subjects |
| `audit_check_access` — time-travel (replay ~60 k events) | **27.4** | audit-log size up to `p_at` |

Numbers are measured after warm-up; a cold buffer cache (e.g. the first call
right after a bulk load) is slower — `list_objects` here was ~70 ms cold vs
~1 ms warm.

## Takeaways

- **`check_access` is sub-millisecond** for typical direct/userset/wildcard
  checks, and ~2.3 ms for a 15-level folder-inheritance chain. A full DENY
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
- **Time-travel cost scales with the audit-log size** replayed up to the
  target timestamp (~28 ms at 60 k events here). It is a forensic/compliance
  path, not a hot path — keep it off latency-critical flows, and retain the
  audit log per your needs (see [PRODUCTION.md → Audit retention](PRODUCTION.md#audit-retention)).

## Scaling the benchmark / adding suites

Edit the constants in [`bench/suites/drive.sql`](../bench/suites/drive.sql)
(`n_users`, `n_groups`, `grp_size`, `depth`) and re-run `./bench/run.sh drive`.
The search and check numbers should stay roughly flat as `n_users` grows (they
are bounded by the reachable set, not the store size) — the property worth
verifying on your own data shapes.

To benchmark a **different model**, add `bench/suites/<name>.sql`: build a store
+ data, then time scenarios with the shared helpers (`pg_temp._bench(label,
sql, iters)` and `pg_temp._bench_title(text)` from the harness). `./bench/run.sh
<name>` runs it; `./bench/run.sh` with no args runs every suite.
