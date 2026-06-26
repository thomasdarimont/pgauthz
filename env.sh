#!/usr/bin/env bash
#
# Shared environment for init.sh and test.sh.
# Starts PostgreSQL if needed and exports helper functions.
#
# Sourced, not executed directly.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load local customizations (passwords, JWT, etc.) from .env if present, so the
# shell (psql connections) and docker compose use the same values. See
# .env.example. docker compose also reads .env on its own; this just makes the
# variables available to this script too.
if [ -f "$SCRIPT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/.env"
  set +a
fi

PG_USER="${PG_USER:-authz}"
PG_DB="authz"
PG_PASSWORD="${PG_PASSWORD:-authz}"

# Compose files — base stack + optional authzen overlay
COMPOSE_FILES=(-f "$SCRIPT_DIR/compose.yml")
if [ -f "$SCRIPT_DIR/compose-authzen.yml" ]; then
  COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-authzen.yml")
fi

# Optional: CEL condition support. When PGAUTHZ_CEL is truthy, overlay
# compose-cel.yml so the Postgres image is (re)built with the pg_cel extension
# (extensions/pg-cel). init.sh then runs CREATE EXTENSION pg_cel, enabling
# lang='cel' conditions. Off by default → stock postgres, sql conditions only.
# Enable with: PGAUTHZ_CEL=1 ./bootstrap.sh   (or ./start.sh --cel / .env).
case "${PGAUTHZ_CEL:-}" in
  1|true|yes|on)
    COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-cel.yml")
    ;;
esac

# The demo/test stack runs the AuthZEN services in trusted-PEP mode (the
# integration tests evaluate access for arbitrary subjects supplied in the
# request body). The compose file itself defaults to the SAFE token-only mode,
# so a copied-to-production compose isn't permissive by accident — the demo
# opts in here, explicitly.
export ALLOW_SUBJECT_OVERRIDE="${ALLOW_SUBJECT_OVERRIDE:-true}"

# Same for the OPA read path: the demo's OPA integration tests evaluate access
# for explicit subjects with no JWT, so the demo opts into trusted-PEP mode
# here. compose.yml defaults to the SAFE token-only mode (REQUIRE_TOKEN_FOR_READS
# true), so production stays token-only unless explicitly opted out.
export REQUIRE_TOKEN_FOR_READS="${REQUIRE_TOKEN_FOR_READS:-false}"

# Ensure containers are running
docker compose "${COMPOSE_FILES[@]}" up -d --build --wait

# Resolve the authz-db container
DB_CONTAINER=$(docker compose "${COMPOSE_FILES[@]}" ps -q authz-db)
if [ -z "$DB_CONTAINER" ]; then
  echo "ERROR: authz-db container not running." >&2
  exit 1
fi

# Run psql inside the container
psql_exec() {
  local db="$1"
  shift
  docker exec -i -e PGPASSWORD="$PG_PASSWORD" "$DB_CONTAINER" psql -U "$PG_USER" -d "$db" "$@"
}

# Run a SQL file by piping it into the container.
# ON_ERROR_STOP makes psql exit non-zero on the first SQL error — without it,
# failing test assertions (RAISE EXCEPTION) would not fail the test scripts.
psql_file() {
  local db="$1"
  local file="$2"
  docker exec -i -e PGPASSWORD="$PG_PASSWORD" "$DB_CONTAINER" psql -v ON_ERROR_STOP=1 -U "$PG_USER" -d "$db" < "$file"
}
