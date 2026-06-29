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

# Host-side connection for sqlx-cli (migrations). The compose stack maps the
# DB to localhost:55433; sqlx connects over that port (psql still goes through
# docker exec). DATABASE_URL is what sqlx reads.
PG_HOST="${PG_HOST:-localhost}"
PG_PORT="${PG_PORT:-55433}"
export DATABASE_URL="${DATABASE_URL:-postgres://${PG_USER}:${PG_PASSWORD}@${PG_HOST}:${PG_PORT}/${PG_DB}}"

# Compose files. COMPOSE_FILE overrides the default stack with a single
# alternative topology, e.g. the streaming-replication primary:
#   COMPOSE_FILE=compose-scaling.yml ./init.sh
# Otherwise: base stack + optional authzen / CEL overlays.
if [ -n "${COMPOSE_FILE:-}" ]; then
  COMPOSE_FILES=(-f "$SCRIPT_DIR/$COMPOSE_FILE")
else
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
fi

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

# Ensure containers are running. COMPOSE_NO_BUILD=1 skips the implicit --build
# and reuses already-present images (e.g. CI pre-builds the pg_cel image with a
# cached buildx step, then brings the stack up without rebuilding it).
COMPOSE_BUILD_FLAG="--build"
[ "${COMPOSE_NO_BUILD:-}" = "1" ] && COMPOSE_BUILD_FLAG=""
docker compose "${COMPOSE_FILES[@]}" up -d $COMPOSE_BUILD_FLAG --wait

# Resolve the database container. The default stack names it authz-db; the
# streaming-replication topology (compose-scaling.yml) names the writable
# primary authz-primary. DB_SERVICE overrides; otherwise try both.
DB_SERVICE="${DB_SERVICE:-}"
# ps -q errors ("no such service") for a service absent from the active compose
# files; tolerate that (|| true) so the fallback can try the other name.
if [ -n "$DB_SERVICE" ]; then
  DB_CONTAINER=$(docker compose "${COMPOSE_FILES[@]}" ps -q "$DB_SERVICE" 2>/dev/null || true)
else
  DB_CONTAINER=$(docker compose "${COMPOSE_FILES[@]}" ps -q authz-db 2>/dev/null || true)
  [ -z "$DB_CONTAINER" ] && DB_CONTAINER=$(docker compose "${COMPOSE_FILES[@]}" ps -q authz-primary 2>/dev/null || true)
fi
if [ -z "$DB_CONTAINER" ]; then
  echo "ERROR: database container not running (looked for authz-db / authz-primary)." >&2
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

# Locate sqlx-cli (PATH, then the default cargo bin dir).
SQLX_BIN="${SQLX_BIN:-sqlx}"
if ! command -v "$SQLX_BIN" >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/sqlx" ]; then
  SQLX_BIN="$HOME/.cargo/bin/sqlx"
fi

# Apply structural migrations (db/migrations) via sqlx-cli. Idempotent — only
# pending migrations run; tracked in public._sqlx_migrations.
apply_migrations() {
  if ! { command -v "$SQLX_BIN" >/dev/null 2>&1 || [ -x "$SQLX_BIN" ]; }; then
    echo "ERROR: sqlx-cli not found. Install it:" >&2
    echo "  cargo install sqlx-cli --no-default-features --features rustls,postgres" >&2
    return 1
  fi
  DATABASE_URL="$(sqlx_url_public "$DATABASE_URL")" \
    "$SQLX_BIN" migrate run --source "$SCRIPT_DIR/db/migrations"
}

# Pin search_path=public on a sqlx connection URL. sqlx tracks applied
# migrations in an UNQUALIFIED `_sqlx_migrations` table, so the lookup follows
# search_path. We connect as role `authz`, whose default search_path is
# "$user",public = authz,public — and the baseline CREATEs an `authz` schema.
# On a re-run (existing schema) the unqualified name would resolve to a fresh,
# empty `authz._sqlx_migrations`, shadowing the real `public._sqlx_migrations`,
# so sqlx would think the baseline is unapplied and try to re-run it. Forcing
# search_path=public keeps the ledger unambiguous. (CNPG connects as `postgres`,
# which has no shadowing schema, but we pin it everywhere for consistency.)
sqlx_url_public() {
  local url="$1"
  case "$url" in
    *search_path*) printf '%s' "$url" ;;                      # caller already pinned
    *\?*)          printf '%s&options=-csearch_path%%3Dpublic' "$url" ;;
    *)             printf '%s?options=-csearch_path%%3Dpublic' "$url" ;;
  esac
}

# Wipe the engine for a clean (re)install: drop the authz schema and the sqlx
# migration ledger so the baseline re-applies. Dev/CI only (init.sh) — never in
# production (run-migrations.sh migrates in place).
reset_schema() {
  psql_exec "$PG_DB" -q -c \
    "DROP SCHEMA IF EXISTS authz CASCADE; DROP TABLE IF EXISTS public._sqlx_migrations;" >/dev/null
}
