# AGENTS.md

Guidance for coding agents working in this repository (the [agents.md](https://agents.md/)
convention). `CLAUDE.md` imports this file, so Claude Code reads the same instructions.

## Project Overview

pgauthz is a **PostgreSQL-native authorization engine** implementing Google Zanzibar / OpenFGA relationship-based access control (ReBAC) in pure SQL, plus **pgauthzd**, a stateless Go daemon that serves the engine over HTTP (AuthZEN 1.0, native API, JWT). It answers "Can user X do action Y on object Z?" with a query for co-located applications and over HTTP for everyone else; the data and decisions stay in PostgreSQL, there is no separate authorization database.

## Where to read

Do not read `README.md` or `CHANGELOG.md` whole. The README's
**Documentation map** lists one owner per topic; open that file for the task:

- `docs/API.md` — SQL function signatures, return shapes, recipes
- `docs/MODEL_DESIGN.md` — modelling (rules, wildcards, conditions, gates, registry, import)
- `docs/AUDIT.md` — audit trail, time travel, changefeed
- `docs/ARCHITECTURE.md` — how it works / how it is deployed (arc42)
- `docs/PRODUCTION.md` — operations, roles, replicas, retention, upgrades
- `docs/DEVELOPMENT.md` — HTTP write API, integration, debugging, repository layout
- `pgauthzd/README.md`, `pgauthzctl/README.md`, `playground/README.md`, `opa/README.md` — the components
- `CHANGELOG.md` — `grep -n '^## \[' CHANGELOG.md`, then read the one version block you need

**One owner per topic.** A feature is documented in its owning doc; the README
gets one sentence and a link (and a row in the Documentation map if it is a
new topic). Do not add a new `##` section to README.md. Every relative link
and `#anchor` must resolve: `./scripts/check-links.sh` runs in CI.

## Architecture

Deployment (OPA is opt-in — the default stack is OPA-free):
```
Default:          Application → pgauthzd (front door — validates JWT) → PostgreSQL (engine)
With OPA overlay: Application → pgauthzd (validates JWT) → OPA (Rego policy-as-code)
                                → pgauthzd native callback (service-token / optional mTLS) → PostgreSQL
```

- **PostgreSQL 18.4** — Core engine: ~4200 lines of PL/pgSQL implementing recursive relationship resolution, conditions/ABAC, audit trail, time-travel queries
- **pgauthzd** — Single Go daemon exposing the engine over HTTP (native `/pgauthz/v1` API + AuthZEN 1.0), capability-scoped by **profile** (DB capability only): `decision-only` (read-only DB role), `full` (read+write, writer role). Fronting an OPA policy sidecar is orthogonal to the profile, controlled by the `OPA_URL` env var (not a third profile): with `OPA_URL` set, pgauthzd consults OPA for the AuthZEN `/access/v1` surface (forwarding the token); the native `/pgauthz/v1` surface stays direct pgx and is exposed on the public listener only when NOT fronting OPA. pgauthzd also authorizes writes itself via a `WRITER_ROLE` claim gate (default role `authz_writer`; `JWT_ROLES_CLAIM` defaults to `roles`). Replaces PostgREST as the read/write bridge. OPA's Rego calls **back** into pgauthzd's native `/pgauthz/v1` API for both reads and writes — reads to a `decision-only` instance, writes to a `full` instance (reader/writer separation follows the instance's profile/DB role). The callback listener is authenticated by a shared service token (`INTERNAL_SERVICE_TOKEN` on pgauthzd / `NATIVE_SERVICE_TOKEN` on OPA) and optional mTLS; it trusts OPA's asserted subject + per-app role (`X-PGAuthz-Role`) and does **not** re-verify the end-user JWT (pgauthzd is the external front door; the callback listener trusts OPA, its upstream policy sidecar). PostgREST has been removed entirely — the OPA policy and every deployment (compose, scaling, Helm) use the native callback
- **OPA 1.18.2** — **OPT-IN** policy sidecar (the default stack is OPA-free — pgauthzd answers directly from PostgreSQL, with conditions for ABAC; see [ADR 0008](docs/adr/0008-opa-is-opt-in.md)). Enable with `./start.sh --opa` (compose) or `authzen.opa.enabled` (Helm). When enabled it is internal — reachable only by pgauthzd (the sole external caller of OPA); a pgauthzd instance with `OPA_URL` set forwards the verified token to it for policy-as-code Rego (re-validating the JWT — defense in depth), and OPA calls **back** into pgauthzd's native callback for graph reads and writes
- **Go AuthZEN API** — AuthZEN 1.0 services, now instances of `pgauthzd`: `authzen-direct` (Go→PostgreSQL, `decision-only`, port 8090) and `authzen-opa` (Go→OPA→pgauthzd native callback→PostgreSQL, `decision-only` + `OPA_URL` set, port 8091)

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

### Build pgauthzd
```bash
cd pgauthzd && go build ./... && go test ./...
```

## Key Directories

- `db/migrations/` — Forward-only structural migrations (`0001_baseline.sql` + deltas), applied by `sqlx`; the single source of schema *structure*
- `db/engine/` — Core authorization engine *code* (access checks, tuples, models, audit, conditions) — idempotent functions/views/triggers loaded after migrations
- `scripts/gen-schema.sh` — Regenerates the gitignored `db/schema.generated.sql` (full assembled schema reference) on demand
- `tests/sql/` — SQL test suites (API, search, contextual tuples, namespaces, intersections, wildcards, type restrictions)
- `examples/models/` — Example authorization models (helloworld, demo, gdrive, github, todo, aia-acme, agents, fourquestions), each with model.sql, seed.sql, demo.sql; demo, todo, gdrive, aia-acme and agents also have tests.sql (gdrive showcases temporal gates on `doc.download`; aia-acme is the *Authorization in Action* Cedar example as ReBAC — global `forbid` = conditional object-wildcard tuple intersected into every employee path), demo additionally demo_cel.sql (CEL-condition showcase, needs the pg_cel extension). helloworld is the README "complete example" as loadable files. Not part of the deployable engine — `init.sh` does not load them; `test.sh`/`bootstrap.sh` load the demo, todo, gdrive, aia-acme, agents and fourquestions models as test fixtures
- `examples/watch/` — Runnable setup example for the watch/changefeed feature (compose overlay + Python consumer)
- `db/security/` — PostgreSQL role definitions (authz_reader, authz_writer, authz_admin, authz_auditor, authz_recorder)
- `db/openfga/` — Import functions for existing OpenFGA JSON models/tuples
- `db/replication/` — Logical replication and materialized permissions patterns
- `pgauthzd/` — The Go daemon (cmd/, internal/api/, internal/app/, internal/authz/, internal/config/, internal/metrics/, internal/pgbackend/, internal/opabackend/)
- `opa/policies/` — Rego policies (pgauthz client, application policy, JWT authn, system authz)

## SQL Engine Conventions

- All public functions are `SECURITY DEFINER` — app roles never need direct table access
- **Structure vs code are tracked separately** (see [`docs/adr/0001-schema-migrations.md`](docs/adr/0001-schema-migrations.md)):
  - **Structure** (tables, indexes, types, partitioned parents + default partitions, the `authz_eval` role) lives in **forward-only migrations** under `db/migrations/`, applied by `sqlx migrate run` and tracked in `public._sqlx_migrations`. `0001_baseline.sql` is the frozen baseline; later structural changes are new `NNNN_*.sql` files. There is no `DROP SCHEMA` install path.
  - **Code** (functions, views, triggers) lives in `db/engine/`, all idempotent (`CREATE OR REPLACE …`, incl. `CREATE OR REPLACE TRIGGER`), loaded **after** migrations.
- Engine code files are grouped by **deployment profile** in `db/engine/manifest.sh` (the single source of truth for code load order, sourced by `init.sh`, `init-readonly.sh`, `deploy/migrations/run-migrations.sh`, and `db/replication/init-replication.sh`):
  - **substrate** (`core_internal.sql`, `conditions.sql`, `model_constraints.sql`, `views.sql`) — core internals, condition evaluation, model-validation trigger, base views; every deployment
  - **read** (`events.sql`, `gates.sql`, `access_internal.sql`, `access.sql`, `explain.sql`, `consistency.sql`, `stats.sql`) — action-log inspection (`list_events`), temporal-gate validator/primitives/evaluator, checks, search (`list_*`), explain, condition validation (dry-run)
  - **write** (`store.sql`, `tuples.sql`, `maintenance.sql`, `model.sql`, `conditions_admin.sql`, `model_registry.sql`, `events_admin.sql`, `gates_admin.sql`) — tuple/model/store management, redundant-tuple cleanup, condition create/delete + write-time validation trigger, model registry, action-log recording (`record_event(s)`, event partitions/retention), gate management (`add_gate`/`drop_gate`)
  - **audit** (`audit_triggers.sql`, `audit_internal.sql`, `audit.sql`, `watch.sql`) — audit trigger functions/triggers, time-travel, changefeed
  - Read-only deployment = substrate + read (`init-readonly.sh`); full = all four (`init.sh`). The migrations always run (they create *all* tables incl. audit); profiles only select which **code** loads, so on a read-only install the audit tables exist but stay inert (no triggers/functions). To add an engine file, register it in the manifest with its profile.
- Within a profile the order is internal helpers → public API (structure already exists from migrations; functions reference tables at runtime)
- Multi-store architecture: every operation is scoped to a `store_id`
- Tuples are the core data: `(store_id, object_type, object_id, relation, user_type, user_id, user_relation, condition_name, context)`
- Model rules use rule groups supporting union (OR), intersection (AND), and exclusion (BUT NOT) semantics
- Audit trail is immutable, monthly-partitioned, with `performed_by` tracking
- Action log (`authz.events`, ADR 0012): what principals *actually did*, recorded by the PEP via `record_event(s)` / `POST /pgauthz/v1/events` — never by the check path; actions must be declared relations; append-only, monthly-partitioned on `occurred_at`; `event_id` idempotency requires `occurred_at`
- Temporal gates (`authz.model_gates`, ADR 0012 phase 2): `all_of` clauses (`count_within`, `count_distinct_within`, `sum_within`, `formerly_within`) evaluated after the graph allows, for the checked principal only. **Every public decision entry point calls `authz._decide` (live) / `_decide_snapshot` (time-travel), never `_check_access` directly** — `tests/test.sh` lints this. Grammar in `docs/MODEL_DESIGN.md` §17. The gate evaluation path is `VOLATILE` and clocked by `clock_timestamp()` on purpose (`reserve_event` evaluates after waiting for its per-subject advisory lock); write caps with `"plus": 1`

## Docker Compose Configurations

- `compose.yml` — Base stack (PostgreSQL, pgauthzd reader/writer instances, OPA)
- `compose-authzen.yml` — Adds AuthZEN Go services
- `compose-replication.yml` — Logical replication demo (primary + subscriber databases)
- `compose-scaling.yml` — Streaming replication with read replicas

## Environment

`env.sh` is sourced by all scripts and sets up docker compose file lists and psql connection helpers. PostgreSQL runs on port 55433 locally.
