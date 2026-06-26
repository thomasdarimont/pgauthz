# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pgauthz is a **PostgreSQL-native authorization engine** implementing Google Zanzibar / OpenFGA relationship-based access control (ReBAC) in pure SQL. It answers "Can user X do action Y on object Z?" without requiring an external authorization service.

## Architecture

Three-tier deployment:
```
Application → OPA (optional policy layer) → PostgREST (REST bridge) → PostgreSQL (engine)
```

- **PostgreSQL 18.4** — Core engine: ~4200 lines of PL/pgSQL implementing recursive relationship resolution, conditions/ABAC, audit trail, time-travel queries
- **PostgREST v14.13** — Exposes SQL functions as REST API (read on port 3000, write on port 3001 behind Nginx)
- **OPA 1.17.1** — Rego policies for JWT authn and policy-as-code authz
- **Go AuthZEN API** — Two services implementing AuthZEN 1.0 standard: `authzen-direct` (Go→PostgreSQL, port 8090) and `authzen-opa` (Go→OPA→PostgREST→PostgreSQL, port 8091)
- **Nginx gateway** — Restricts write API to POST `/rpc/*` only

## Common Commands

### Start/Stop the Stack
```bash
./start.sh          # Start all services via docker compose
./stop.sh           # Stop services
./stop.sh --clean   # Stop and remove volumes
```

### Initialize Database
```bash
./init.sh            # Load schema, functions, models, seed data, security roles
./bootstrap.sh       # Full init + run all tests
```

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

- `db/engine/` — Core authorization engine SQL (schema, access checks, tuples, models, audit)
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
- Functions are organized: `schema.sql` (DDL) → `core_internal.sql` / `access_internal.sql` / `audit_internal.sql` (internal helpers) → `access.sql` / `explain.sql` / `tuples.sql` / `model.sql` / `audit.sql` (public API)
- Multi-store architecture: every operation is scoped to a `store_id`
- Tuples are the core data: `(store_id, object_type, object_id, relation, user_type, user_id, user_relation, condition_name, context)`
- Model rules use rule groups supporting union (OR), intersection (AND), and exclusion (BUT NOT) semantics
- Audit trail is immutable, monthly-partitioned, with `performed_by` tracking

## Docker Compose Configurations

- `compose.yml` — Base stack (PostgreSQL, PostgREST reader/writer, OPA)
- `compose-authzen.yml` — Adds AuthZEN Go services
- `compose-replication.yml` — Logical replication demo (primary + subscriber databases)
- `compose-scaling.yml` — Streaming replication with read replicas

## Environment

`env.sh` is sourced by all scripts and sets up docker compose file lists and psql connection helpers. PostgreSQL runs on port 55433 locally.
