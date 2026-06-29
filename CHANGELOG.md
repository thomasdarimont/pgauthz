# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While
pre-1.0, minor versions may include breaking changes.

## [Unreleased]

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

[Unreleased]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/thomasdarimont/pgauthz/releases/tag/v0.1.0
