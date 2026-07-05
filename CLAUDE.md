# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pgauthz is a **PostgreSQL-native authorization engine** implementing Google Zanzibar / OpenFGA relationship-based access control (ReBAC) in pure SQL. It answers "Can user X do action Y on object Z?" without requiring an external authorization service.

## Architecture

Three-tier deployment:
```
Application → pgauthzd (front door — validates JWT) → OPA (optional internal policy sidecar) → pgauthzd native callback (service-token / optional mTLS) → PostgreSQL (engine)
```

- **PostgreSQL 18.4** — Core engine: ~4200 lines of PL/pgSQL implementing recursive relationship resolution, conditions/ABAC, audit trail, time-travel queries
- **pgauthzd** — Single Go daemon exposing the engine over HTTP (native `/pgauthz/v1` API + AuthZEN 1.0), capability-scoped by **profile**: `decision-only` (read-only DB role), `full` (read+write, writer role), `compat-opa` (fronts OPA). Replaces PostgREST as the read/write bridge. OPA's Rego calls **back** into pgauthzd's native `/pgauthz/v1` API for both reads and writes — reads to a `decision-only` instance, writes to a `full` instance (reader/writer separation follows the instance's profile/DB role). The callback listener is authenticated by a shared service token (`INTERNAL_SERVICE_TOKEN` on pgauthzd / `NATIVE_SERVICE_TOKEN` on OPA) and optional mTLS; it trusts OPA's asserted subject + per-app role (`X-Authz-Role`) and does **not** re-verify the end-user JWT (pgauthzd is the external front door; the callback listener trusts OPA, its upstream policy sidecar). PostgREST has been removed entirely — the OPA policy and every deployment (compose, scaling, Helm) use the native callback
- **OPA 1.18.2** — Internal policy sidecar reachable only by pgauthzd (the sole external caller of OPA); the `compat-opa` profile forwards the verified token to it for policy-as-code Rego (re-validating the JWT — defense in depth), and OPA calls **back** into pgauthzd's native callback for graph reads and writes
- **Go AuthZEN API** — AuthZEN 1.0 services, now profiles of `pgauthzd`: `authzen-direct` (Go→PostgreSQL, `decision-only`, port 8090) and `authzen-opa` (Go→OPA→pgauthzd native callback→PostgreSQL, `compat-opa`, port 8091)
- **Nginx gateway** (`gateway/`) — Optional OPA edge proxy (TLS termination / optional mTLS / endpoint allowlist); not wired into the default compose

## Common Commands

### Start/Stop the Stack
```bash
./start.sh          # Start all services via docker compose
./stop.sh           # Stop services
./stop.sh --clean   # Stop and remove volumes
```

### Initialize Database
```bash
./init.sh            # Install the full engine (substrate + read + write + audit) + roles
./init-readonly.sh   # Install only the read-only excerpt (substrate + read) for an app
                     # DB fed by replication — no write API, no audit tables
./reload-engine.sh   # Fast dev reload of engine CODE + roles.sql into a running DB
                     # (no migrations/data/examples). Re-runs roles.sql so
                     # SECURITY DEFINER is restored — CREATE OR REPLACE resets it.
./bootstrap.sh       # Full init + run all tests
```

> Reloading engine code with plain `CREATE OR REPLACE` resets a function's
> `SECURITY DEFINER` to INVOKER, breaking non-owner callers with
> `permission denied for function _s`. Always follow an engine reload with
> `roles.sql` — `./init.sh` and `./reload-engine.sh` both do this in order.

### Run Tests
```bash
./tests/test.sh          # SQL unit tests only
./tests/test-opa.sh      # OPA integration tests
./tests/test-authzen.sh  # AuthZEN API tests
./tests/test-all.sh      # init.sh + all test suites
```

SQL tests use helper assertions defined in `tests/sql/tests_helpers.sql`. Individual test files can be run via psql against the running database (source `env.sh` first for the `$PSQL` alias).

### Build AuthZEN Go Services
```bash
cd authzen && go build ./cmd/authzen-direct
cd authzen && go build ./cmd/authzen-opa
```

## Key Directories

- `db/migrations/` — Forward-only structural migrations (`0001_baseline.sql` + deltas), applied by `sqlx`; the single source of schema *structure*
- `db/engine/` — Core authorization engine *code* (access checks, tuples, models, audit, conditions) — idempotent functions/views/triggers loaded after migrations
- `scripts/gen-schema.sh` — Regenerates the gitignored `db/schema.generated.sql` (full assembled schema reference) on demand
- `tests/sql/` — SQL test suites (API, search, contextual tuples, namespaces, intersections, wildcards, type restrictions)
- `examples/models/` — Example authorization models (demo, gdrive, github), each with model.sql, seed.sql, demo.sql; demo also has tests.sql and demo_cel.sql (CEL-condition showcase, needs the pg_cel extension). Not part of the deployable engine — `init.sh` does not load them; `test.sh`/`bootstrap.sh` load the demo model as a test fixture
- `examples/watch/` — Runnable setup example for the watch/changefeed feature (compose overlay + Python consumer)
- `db/security/` — PostgreSQL role definitions (authz_reader, authz_writer, authz_admin, authz_auditor)
- `db/openfga/` — Import functions for existing OpenFGA JSON models/tuples
- `db/replication/` — Logical replication and materialized permissions patterns
- `authzen/` — Go AuthZEN 1.0 HTTP API (cmd/, internal/api/, internal/pgbackend/, internal/opabackend/)
- `opa/policies/` — Rego policies (pgauthz client, application policy, JWT authn, system authz)
- `gateway/` — Nginx OPA edge-proxy template (TLS / optional mTLS); optional, not wired into the default compose

## SQL Engine Conventions

- All public functions are `SECURITY DEFINER` — app roles never need direct table access
- **Structure vs code are tracked separately** (see [`docs/adr/0001-schema-migrations.md`](docs/adr/0001-schema-migrations.md)):
  - **Structure** (tables, indexes, types, partitioned parents + default partitions, the `authz_eval` role) lives in **forward-only migrations** under `db/migrations/`, applied by `sqlx migrate run` and tracked in `public._sqlx_migrations`. `0001_baseline.sql` is the frozen baseline; later structural changes are new `NNNN_*.sql` files. There is no `DROP SCHEMA` install path.
  - **Code** (functions, views, triggers) lives in `db/engine/`, all idempotent (`CREATE OR REPLACE …`, incl. `CREATE OR REPLACE TRIGGER`), loaded **after** migrations.
- Engine code files are grouped by **deployment profile** in `db/engine/manifest.sh` (the single source of truth for code load order, sourced by `init.sh`, `init-readonly.sh`, `deploy/migrations/run-migrations.sh`, and `db/replication/init-replication.sh`):
  - **substrate** (`core_internal.sql`, `conditions.sql`, `model_constraints.sql`, `views.sql`) — core internals, condition evaluation, model-validation trigger, base views; every deployment
  - **read** (`access_internal.sql`, `access.sql`, `explain.sql`) — checks, search (`list_*`), explain, condition validation (dry-run)
  - **write** (`store.sql`, `tuples.sql`, `maintenance.sql`, `model.sql`, `conditions_admin.sql`) — tuple/model/store management, redundant-tuple cleanup, condition create/delete + write-time validation trigger
  - **audit** (`audit_triggers.sql`, `audit_internal.sql`, `audit.sql`, `watch.sql`) — audit trigger functions/triggers, time-travel, changefeed
  - Read-only deployment = substrate + read (`init-readonly.sh`); full = all four (`init.sh`). The migrations always run (they create *all* tables incl. audit); profiles only select which **code** loads, so on a read-only install the audit tables exist but stay inert (no triggers/functions). To add an engine file, register it in the manifest with its profile.
- Within a profile the order is internal helpers → public API (structure already exists from migrations; functions reference tables at runtime)
- Multi-store architecture: every operation is scoped to a `store_id`
- Tuples are the core data: `(store_id, object_type, object_id, relation, user_type, user_id, user_relation, condition_name, context)`
- Model rules use rule groups supporting union (OR), intersection (AND), and exclusion (BUT NOT) semantics
- Audit trail is immutable, monthly-partitioned, with `performed_by` tracking

## Docker Compose Configurations

- `compose.yml` — Base stack (PostgreSQL, pgauthzd reader/writer instances, OPA)
- `compose-authzen.yml` — Adds AuthZEN Go services
- `compose-replication.yml` — Logical replication demo (primary + subscriber databases)
- `compose-scaling.yml` — Streaming replication with read replicas

## Environment

`env.sh` is sourced by all scripts and sets up docker compose file lists and psql connection helpers. PostgreSQL runs on port 55433 locally.
