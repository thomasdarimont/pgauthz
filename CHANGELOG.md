# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While
pre-1.0, minor versions may include breaking changes.

## [Unreleased]

### Added

- **Synchronous-replication / zero-RPO failover knob in the Helm chart.**
  CloudNativePG already does automatic write failover when
  `database.instances >= 2` (promotes a standby, repoints the `-rw` Service); the
  new `database.replication.synchronous` block lets a commit wait for a standby
  ack so an acknowledged grant/revoke is never lost on failover (RPO 0). Off by
  default (asynchronous); enable via the new
  [`values-ha.yaml`](deploy/helm/pgauthz/values-ha.yaml) overlay. A render-time
  guard fails the install if `maxSyncReplicas >= instances`. Documented in
  [`docs/PRODUCTION.md` → High availability & failover](docs/PRODUCTION.md) and
  the chart README, with a copy-paste **failover game-day runbook** (planned
  `cnpg promote` switchover + unplanned pod-kill + the single-node-k3d
  stuck-`Terminating` gotcha). `start.sh` gained an `HA=1` toggle (and
  multi-file `VALUES` layering) to deploy the synchronous overlay. The drill was
  validated live on k3d: auto-promotion, `-rw` repoint, and RPO 0 (a
  pre-failover acked write survived) all confirmed.

### Changed

- **Read-replica memo now fails fast at its cap instead of silently degrading.**
  `authz.memo_max_entries` defaults to **5000** (was unlimited), and when a check
  on the GUC (read-only/replica) backend would exceed it, `check_access` raises
  `memo_limit_exceeded` (SQLSTATE `53400`) rather than continuing un-memoized —
  silent degradation past the cap would reintroduce the ~quadratic re-work the
  memo prevents (raised in the external project review). Callers should catch it
  and **retry on the primary** (whose temp-table backend is uncapped). Set
  `authz.memo_max_entries = 0` to restore the old unlimited/no-abort behavior.
  The primary/temp-table path is unaffected. Test:
  `tests/sql/tests_readonly.sql` (`ro_08`/`ro_09`).

### Fixed

- Helm `Chart.yaml` `home:` pointed at the wrong repo (`…/authz-dev`); now
  `https://github.com/thomasdarimont/pgauthz`.

## [0.2.2] - 2026-06-29

### Added

- **`STORE_RETIRED` watch/changefeed event.** `retire_store` now records one
  store-lifecycle event (`action = 'STORE_RETIRED'`) in the audit log and fires
  the `authz_changes` doorbell, so watch consumers learn a store was retired and
  can invalidate everything for it. The event is store-wide: it bypasses the
  per-tuple object-type / namespace / relation filters, and `watch_changes` /
  `watch_cursor` now resolve retired stores (so a consumer can drain the
  changefeed's final events). Time-travel ignores it (the snapshot builders
  filter `action = 'INSERT'`).

### Changed

- **`retire_store` is now O(1), not O(tuples), in audit terms.** It previously
  ran `DELETE FROM authz.tuples` before dropping the live partitions purely to
  make the audit trigger record the removal — writing **one `tuples_audit` row
  per tuple**, a huge-transaction / WAL / replication-lag / partition-lock hazard
  for stores with millions of tuples (raised in the external project review).
  The redundant `DELETE` is gone: dropping the partitions (DDL) already removes
  the data, and a single `STORE_RETIRED` lifecycle event (+ the `deleted_at`
  marker) records the retirement once, regardless of tuple count. The time-travel
  evaluator (`_build_audit_snapshot`) treats a retired store as denying
  everything as of `>= deleted_at`, while the kept INSERT history still answers
  "could X do Y at time T `<` retirement?". Tradeoff: the audit log no longer
  holds a per-tuple deletion record at retirement — the lifecycle event replaces
  it; `audit_list_user`/`audit_list_object` still show the full INSERT history.

## [0.2.1] - 2026-06-29

### Added

- **`retire_store(store)` — soft-delete for audit retention.** Drops only a
  store's live tuples (reclaiming their partitions) and marks it retired
  (`stores.deleted_at`, migration `0002_store_retire.sql`), while keeping the
  dictionary (`types`/`relations`/`models`/`conditions`) and full audit log.
  The `audit_*` time-travel API still resolves a retired store **by name**, so
  preserved history stays queryable — closing the gap where `delete_store`
  removed the name dictionary and orphaned its own preserved audit rows (raised
  in the external project review). Live APIs reject a retired store and its name
  stays reserved; `delete_store` remains the explicit physical-removal/erasure
  path and can later purge a retired store.

### Changed

- `authz._s(name)` now resolves **live (non-retired) stores only**, so every
  live API rejects a retired store with a clear error; the `audit_*` functions
  opt into resolving retired stores. `delete_store` resolves retired stores too,
  so a retired store can be purged.

### Fixed

- **Memoization broke `check_access` on read replicas.** The per-check memo
  builds a session temp table, which cannot be created in a read-only
  transaction (a hot standby), so checks on a replica failed with `cannot
  execute CREATE TABLE in a read-only transaction`. On a read-only transaction
  the memo now switches to a session-GUC `jsonb` backend (the only mutable
  scratch a standby allows) instead of the temp table — so checks on replicas
  are both **correct and still protected** against converging/diamond graphs
  (the GUC backend is slower than the temp table but still polynomial). The
  fast temp-table backend is unchanged on the primary. The GUC payload (visited
  object ids + decisions) is cleared before the check returns (success or error)
  so it never lingers in the session, and `authz.memo_max_entries` (default
  `0` = unlimited) can hard-cap the map size; a check with thousands of distinct
  subproblems is slow on a replica regardless and should be routed to the
  primary (`statement_timeout` is the backstop). Time-travel
  (`audit_check_access`) is unaffected: it materializes its as-of state into
  temp tables, so it already requires a writable transaction and is primary-only.
  Regression test: `tests/sql/tests_readonly.sql`.
- Logical-replication demo (`db/replication/init-replication.sh`) hardcoded
  applying only `0001_baseline.sql`, so the new `0002_store_retire.sql` column
  (`stores.deleted_at`) was missing and every `authz._s()` call failed with
  `column "deleted_at" does not exist`. It now replays **all**
  `db/migrations/*.sql` in order, staying correct as future structural deltas
  land.

### Performance

- **Memoized the `check_access` evaluator** (and the time-travel
  `audit_check_access` twin): converging / diamond relationship graphs that
  re-evaluated a node once per path (`O(2^depth)`) are now collapsed to ~linear
  with a per-check memo that caches only path-independent (cycle-free)
  sub-results — identical decisions on every input, proven differentially in
  `tests/sql/tests_memoization.sql`. A depth-12 diamond DENY dropped from
  ~732 ms to ~1.9 ms (live) / ~1.6 s to ~6 ms (time-travel). Toggle with
  `SET authz.memoize = 'off'`.

## [0.2.0] - 2026-06-29

### ⚠️ Breaking

- **Widened all identifier columns from `smallint` to `integer`** — stores,
  types, relations, models, conditions, and every FK referencing them, including
  the `tuples` partition key `object_type` and the `_tuple_key` / `access_check`
  composite types. This lifts the previous **32,767** cumulative-ID ceiling
  (IDENTITY never reuses values) to ~**2.1 billion**, removing the practical limit
  for dynamic / multi-tenant deployments that create and delete many
  stores/types/relations over time (raised in the external project review).
- **No in-place upgrade from 0.1.x.** Because `tuples` is partitioned by
  `object_type`, a partition-key column type cannot be altered in place, so 0.2.0
  **re-baselines** the schema (`0001_baseline.sql`). Upgrading from a 0.1.x
  install is a **reinstall**, not a migration. (There are no production 0.1.x
  deployments; the `upgrade-test` CI job skips the pre-0.2.0 boundary and resumes
  for 0.2.x onward.) **Performance is unchanged** — verified A/B on one machine:
  integer ≡ smallint within run-to-run noise.

## [0.1.4] - 2026-06-29

Release-process tooling and docs (no engine changes).

### Added
- `docs/RELEASING.md` — a release runbook + pre-release checklist (the bump →
  notes → push → CI-green → tag flow, with the gotchas we've hit); linked from
  `CONTRIBUTING.md`.
- `scripts/release.sh` automation:
  - `--auto` — wait for the GitHub CI run on HEAD to pass, then tag and push
    (= `--wait-ci` + `--push` + `--strict-changelog`).
  - `--wait-ci` — block until CI is green before tagging, so a red commit is
    never tagged (needs the `gh` CLI).
  - `--strict-changelog` — fail instead of warn when the release notes are empty.
- `scripts/release.sh` now warns when the `## [X.Y.Z]` CHANGELOG section has no
  notes (empty-release-notes guard).

## [0.1.3] - 2026-06-29

### Added
- CI `scaling-test` job + `tests/test-scaling.sh` covering the streaming-
  replication (read-replica) demo: the standby streams the schema + data,
  resolves `check_access` on the read-only replica, and serves the
  OPA → PostgREST → replica read path.
- `-version` flag on the AuthZEN Go apps (`authzen-direct` / `authzen-opa`),
  stamped at build time via ldflags (tracks the image tag; `dev` for local
  builds). No HTTP endpoint.

### Fixed
- Streaming-replication scaling demo (`compose-scaling.yml`) was broken in four
  places:
  - `db/scaling/start-replica.sh`: the standby FATAL'd because
    `max_connections` (100) was below the primary's 250 — pin it to 250.
  - `env.sh` ignored the documented `COMPOSE_FILE=compose-scaling.yml ./init.sh`
    override and aborted under `set -e` on `ps -q authz-db` — honor
    `COMPOSE_FILE` and resolve `authz-db` or `authz-primary`.
  - `compose-scaling.yml`: OPA was missing the `REQUIRE_TOKEN_FOR_READS`
    mapping the base stack has, so it denied the documented tokenless demo read.

## [0.1.2] - 2026-06-29

### Added
- CI `replication-test` job + `tests/test-replication.sh` covering the logical-
  replication demo end to end: subscribers reach `ready`, the full replica
  resolves `check_access` on replicated data, the derived replica receives the
  flat `materialized_permissions` table, and a live write on the primary
  propagates.

### Fixed
- Logical-replication demo (`db/replication/`) was silently broken
  (`init-replication.sh` lacked `ON_ERROR_STOP`, so SQL errors left a broken
  setup but the script still exited 0). Four fixes:
  - `init-replication.sh` resolved `PG_DIR` to `db/db/...` after the script
    moved under `db/replication/` — point it at the repo root.
  - `setup-publication.sql`: `ALTER DEFAULT PRIVILEGES … GRANT SELECT` was
    missing `ON TABLES` (syntax error).
  - `setup-subscription.sql`: the metadata subscription copied data into tables
    the subscriber already populates by loading the model, causing duplicate-key
    crash-loops — use `copy_data = false` (stream changes only).
  - `materialized_permissions.sql` `_queue_permissions_refresh()`: an `INSERT`
    had three target columns but two expressions — add the missing `store_id`.

## [0.1.1] - 2026-06-29

### Added
- **Non-destructive in-place upgrade** — `upgrade.sh` (`SKIP_RESET=1 ./init.sh`)
  applies pending migrations and reloads the idempotent engine code without
  `DROP SCHEMA`, preserving stores/tuples/audit. The local analog of the
  CloudNativePG `deploy/migrations/run-migrations.sh` path.
- CI `upgrade-test` job: install the previous release tag, seed fixtures,
  upgrade in place to HEAD, and assert the data survived and access still
  resolves (ADR 0001 step 6).
- `scripts/bump-version.sh` — bump every pinned version reference and roll the
  CHANGELOG; pairs with `scripts/release.sh`.

### Fixed
- sqlx migration-ledger shadowing on re-runs / in-place upgrades: connecting as
  role `authz` let the baseline-created `authz` schema shadow the real
  `public._sqlx_migrations` via `search_path`, so sqlx treated the baseline as
  unapplied and tried to re-run it. Pin `search_path=public` on every sqlx
  connection (`env.sh`, `deploy/migrations/run-migrations.sh`,
  `scripts/gen-schema.sh`). Fresh installs and the CloudNativePG path (which
  connects as `postgres`) were unaffected.

## [0.1.0] - 2026-06-29

Initial tagged release: a PostgreSQL-native authorization engine implementing
Google Zanzibar / OpenFGA relationship-based access control (ReBAC) in pure
PL/pgSQL.

### Engine
- Recursive relationship resolution with union (OR), intersection (AND), and
  exclusion (BUT NOT) rule semantics; type restrictions and wildcards.
- Multi-store architecture — every operation scoped to a `store_id`.
- `check_access`, `list_objects` / `list_subjects` (search) with keyset
  pagination, and `explain_access` (decision trace + human-readable summary).
- Conditions / ABAC with a `lang` discriminator: `sql` built-in plus optional
  `cel` via the `pg_cel` extension; conditions evaluate in the zero-privilege
  `authz_eval` sandbox. Management API (`create_condition*` / `delete_condition`).
- Atomic, conditional writes with optimistic-concurrency preconditions
  (`write_tuples_checked`).
- Immutable, monthly-partitioned audit trail with time-travel queries and a
  cursored changefeed (`watch_changes` + `NOTIFY`).
- `describe_model` renders a stored model as OpenFGA-DSL text; OpenFGA JSON
  model/tuple import.

### Deployment
- Three-tier reference stack: PostgreSQL engine, PostgREST REST bridge, OPA as
  the single front door for reads and writes (JWT authn, policy-as-code).
- Go AuthZEN 1.0 API services: `authzen-direct` (Go→PostgreSQL) and
  `authzen-opa` (Go→OPA→PostgREST→PostgreSQL).
- Deployment profiles (substrate / read / write / audit) via a manifest;
  read-only install (`init-readonly.sh`) for an embedded engine fed by logical
  replication.
- Helm chart on CloudNativePG, with `extraRoles` for declarative app roles.
- Logical-replication and streaming-replication (read-replica) topologies.

### Schema management
- Forward-only structural migrations in `db/migrations/` applied by `sqlx-cli`
  and tracked in `public._sqlx_migrations`; idempotent engine code loaded after.
  Install and upgrade are the same non-destructive operation — no `DROP SCHEMA`
  (see [ADR 0001](docs/adr/0001-schema-migrations.md)).

### Requirements
- PostgreSQL 18.x (developed/tested on 18.4). PostgREST, OPA, the AuthZEN
  services, and `pg_cel` are optional components of the reference deployment.

[Unreleased]: https://github.com/thomasdarimont/pgauthz/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/thomasdarimont/pgauthz/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/thomasdarimont/pgauthz/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/thomasdarimont/pgauthz/releases/tag/v0.1.0
