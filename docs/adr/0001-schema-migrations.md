# ADR 0001 — Schema migrations (non-destructive upgrades)

- **Status:** Accepted (design) — implementation pending
- **Date:** 2026-06-26
- **Deciders:** maintainers
- **Supersedes:** the current full-reset install model

> This is also the first ADR. Future ADRs live in `docs/adr/NNNN-*.md`, numbered
> sequentially, recording decisions to authorization semantics, security
> boundaries, or operational contracts. Status flows Proposed → Accepted →
> (Superseded). Keep them short.

## Context

Installation today is a **full reset**: `db/engine/schema.sql` begins with
`DROP SCHEMA authz CASCADE`, and `init.sh` / `deploy/migrations/run-migrations.sh`
re-run the whole engine. Correct for a fresh install, but it **destroys all
stores, tuples, and audit history**, so it cannot upgrade a running deployment.
No version tracking, no upgrade path, no rollback story. This is the main gate to
running pgauthz as an upgradeable product.

Two existing properties make this tractable:

1. **Code is already idempotent** — every function/view is `CREATE OR REPLACE`,
   safe to re-apply on every deploy.
2. **Structure is separated from code** by the deployment profiles
   (`db/engine/manifest.sh`): the *only* files that create persistent state are
   the DDL ones (`schema.sql`, `schema_audit.sql`).

So the migration problem is narrow: **only structural DDL needs versioning.**

## Decision

Adopt **`sqlx-cli`** (`sqlx migrate`) as the migration runner, in a
**migrations-only** model.

- MIT OR Apache-2.0, single static binary, plain `.sql` migrations, not coupled
  to any ORM. Tracks a `_sqlx_migrations` table with per-file **checksums**
  (an applied migration that is later edited becomes an error). Slim Postgres
  build: `cargo install sqlx-cli --no-default-features --features rustls,postgres`
  — in-family with the Rust toolchain we already use for `extensions/pg-cel`.
- *Imperative* (we hand-write each DDL delta). It runs/tracks migrations; it does
  not author them. We accept that boundary: a dumb, reliable runner over a
  declarative tool (Atlas) keeps the "just SQL" ethos and avoids an open-core
  dependency. See Alternatives.

### Structural DDL vs idempotent code (the key boundary)

PostgreSQL 14+ supports `CREATE OR REPLACE TRIGGER` (and already `… VIEW`,
`… FUNCTION`). So the **only** non-idempotent DDL is table/index/type/schema
structure. That gives a clean split:

| Goes in **migrations** (versioned, immutable) | Stays **idempotent code** (re-applied every deploy via the manifest) |
|---|---|
| `CREATE SCHEMA`, roles, `CREATE TABLE`, `CREATE INDEX`, `CREATE TYPE`, partitions, and later `ALTER TABLE` / backfills | all `CREATE OR REPLACE FUNCTION`, `CREATE OR REPLACE VIEW`, `CREATE OR REPLACE TRIGGER` |

**Prerequisite refactor** (continues the profile split): move the trigger
*functions*, the `CREATE … TRIGGER` statements (→ `CREATE OR REPLACE TRIGGER`),
and the views out of `schema.sql` / `schema_audit.sql` into code files loaded by
the manifest. What remains in those two files is **pure structural DDL** — which
becomes the baseline migration verbatim (minus `DROP SCHEMA`).

This ordering then just works, for both fresh and upgrade:

```
1. sqlx migrate run            # structural: tables/indexes/types exist (baseline + deltas)
2. load code via the manifest  # functions, views, triggers (CREATE OR REPLACE) attach to them
```

Functions reference tables only at runtime (deferred); views/triggers are created
in step 2 when the tables already exist.

### Layout

```
db/migrations/
  0001_baseline.sql            # = current schema.sql + schema_audit.sql STRUCTURE, no DROP SCHEMA
  0002_<change>.sql            # forward-only ALTER/CREATE deltas, one per structural change
  ...
db/engine/                     # unchanged: idempotent code, loaded by manifest.sh
db/schema.generated.sql        # NEW: pg_dump --schema-only after `sqlx migrate run`, checked in for review
```

- **Sequential** integer versions (`sqlx migrate add --sequential`), forward-only
  (no `down` files); rollback = restore from backup (see below).
- `0001_baseline.sql` is **frozen** once tagged; every later structural change is
  a new file. Intra-development churn before the first release may still edit the
  baseline.
- A migration needing non-transactional DDL (`CREATE INDEX CONCURRENTLY`, for
  zero-downtime) is marked accordingly (`sqlx` `-- no-transaction`).

### Partitions

Partition *creation* is **not** migration-driven and needs no change:

- `authz.tuples` (LIST by object_type) — leaf partitions are created per type at
  runtime by `authz._ensure_tuple_partition` (called from model registration).
  Data-driven; existing partitions persist across upgrades.
- `authz.tuples_audit` (RANGE by month) — created ahead by
  `authz.ensure_audit_partitions()`. Time-driven; unaffected by upgrades.
- The `*_default` partitions are part of the baseline structure (in
  `0001_baseline.sql`).

Migrations are needed only for changes to the **partitioned parent's structure**
— a normal `ALTER TABLE authz.tuples …` cascades to all partitions (add column,
add index, etc.) and is an ordinary migration. Changing the **partition key or
scheme** is the rare, hard case: handle it as an explicit, carefully reviewed
migration (expand/contract — `pgroll` territory if it must be online).

### Install / upgrade flow

`init.sh`, `init-readonly.sh`, and `deploy/migrations/run-migrations.sh` all
become:

```
sqlx migrate run --source db/migrations          # fresh AND upgrade: apply pending only
load <profiles> code via engine_files_for ...     # full: substrate+read+write+audit; read-only: substrate+read
```

- **Fresh == upgrade**: there is no separate baseline path and no `DROP SCHEMA`.
  A new DB applies `0001…` onward; an existing DB applies only what's pending.
- Profiles still choose which **code** loads (full vs read-only); migrations
  always run (they create the structure the replica/embedded engine reads).
- **`_sqlx_migrations` lives in `public`** (the default; it must exist before the
  baseline runs, and `authz` doesn't exist yet on a fresh DB — so `public` avoids
  a chicken-and-egg). It is migration *metadata*, not authz data, so this keeps
  `authz` clean. It is **per-database, never replicated**: each replica / embedded
  engine runs its own migrations to build structure, and the publications only
  cover `authz.*`, so `public._sqlx_migrations` is naturally excluded — keep it
  that way.

### Rollback

Forward-only. Rollback = restore from backup / PITR (already recommended in
`docs/PRODUCTION.md`). Document "take a backup before upgrading." Optional `down`
migrations may be added per change but are not required.

### CI / verification

- **Generated-schema freshness** (replaces the old "baseline-vs-migrations drift"
  problem — which *disappears* under migrations-only, since structure has a single
  source): CI runs `sqlx migrate run` on an empty DB, `pg_dump --schema-only`,
  and asserts the result matches the checked-in `db/schema.generated.sql`. Keeps a
  human-readable current schema in the repo and current.
- **Upgrade test:** **regenerate the prior state from git, no stored snapshots** —
  check out the previous release tag, install it (its migrations + code), load
  fixtures, then check out HEAD, `sqlx migrate run`, and run the full SQL suite —
  assert green and data preserved. The immutable migration history *is* the
  record, so there are no per-release dump artifacts to maintain. (No-op until the
  first tagged release exists; ties to the release policy in `SECURITY.md`.)
- **Fresh-install test:** existing `bootstrap.sh` stays green.

## Alternatives considered

- **Bespoke runner** (version table + numbered SQL + bash). ~50 lines, zero deps.
  Rejected only because `sqlx-cli` gives the same for free *plus* checksums and is
  "known to work" — but it's a fine fallback if we want no binary at all.
- **Atlas (declarative).** Would *author* migrations by diffing `schema.sql` and
  detect drift built-in. More automation, but open-core (Pro gates governance) and
  against the "just SQL" ethos. Migrations-only already removes the drift problem,
  which was Atlas's main draw here. *Revisit only if hand-authoring deltas becomes
  a burden.*
- **Other Rust runners.** `refinery` (MIT, embeddable, forward-only philosophy)
  is the alternative if we ever want to run migrations from inside a Rust binary;
  `diesel_cli` pulls in the Diesel ORM (unwanted). `sqlx-cli` wins on standalone +
  dual-license + adoption.
- **Flyway / Liquibase.** JVM weight; Liquibase 5.x is FSL (not OSI open source).
  Only compelling if the target enterprise already standardizes on Flyway.

## Consequences

- A structural change now ships with a `db/migrations/NNNN_*.sql` and an updated
  `db/schema.generated.sql` in the same PR (the freshness test enforces it).
- The prerequisite refactor (triggers/views/trigger-functions → idempotent code)
  is a one-time change that further sharpens the substrate/code boundary.
- `deploy/migrations/run-migrations.sh` and the Helm post-install hook flip from
  full-reset to migrate-then-load → safe on an existing database.
- New surface: `db/migrations/`, the `sqlx-cli` binary in the migration image, the
  generated-schema file, and three CI jobs. Small, because code stays idempotent.
- Requires **PostgreSQL 14+** for `CREATE OR REPLACE TRIGGER` (we target 18 — fine).

## Implementation plan

Ordered; each step keeps `./init.sh` + `./tests/test.sh` green.

1. **Prerequisite refactor.** Move the trigger *functions*, the
   `CREATE … TRIGGER` statements (rewritten as `CREATE OR REPLACE TRIGGER`), and
   the views out of `schema.sql` / `schema_audit.sql` into manifest-loaded code
   files; register them in `db/engine/manifest.sh`. After this, those two files
   hold only structural DDL.
2. **Baseline migration.** Create `db/migrations/0001_baseline.sql` = the
   remaining structure (schema, roles, tables, indexes, types, default
   partitions), with `CREATE SCHEMA authz` instead of `DROP SCHEMA … CASCADE`.
3. **Runner image.** Bake a pinned `sqlx-cli` (slim Postgres build) into
   `deploy/migrations/` (and document local install for `init*.sh`).
4. **Rewire installers.** `init.sh`, `init-readonly.sh`,
   `deploy/migrations/run-migrations.sh`: `sqlx migrate run` → load the relevant
   profiles' code via `engine_files_for`. Remove the destructive reset path.
5. **Generated schema.** Add `db/schema.generated.sql` (`pg_dump --schema-only`
   after a clean migrate) + the CI freshness check.
6. **CI.** Add the upgrade test (regenerate-from-tag) and keep the fresh-install
   (`bootstrap.sh`) test.
7. **Docs.** README *Compatibility* (add `sqlx-cli`), CLAUDE.md (engine layout +
   "add a migration" note), CONTRIBUTING (how to author a migration and refresh
   the generated schema), PRODUCTION (backup-before-upgrade procedure).

All three earlier open questions are resolved above: `_sqlx_migrations` →
`public` (never replicated); upgrade-test baselines → regenerate from the
previous tag (no stored snapshots); partition creation → existing runtime
helpers, migrations only for parent-table structure changes.
