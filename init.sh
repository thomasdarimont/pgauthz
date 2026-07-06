#!/usr/bin/env bash
#
# Starts PostgreSQL and installs the authorization engine: schema,
# functions, OpenFGA import, audit partitions, and security roles.
# Idempotent — safe to re-run.
#
# This installs the ENGINE ONLY — no example models or stores. To load
# an example, see examples/ (e.g. ./bootstrap.sh loads the demo model
# and runs the test suite).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
source "$SCRIPT_DIR/db/engine/manifest.sh"

# init.sh is the dev/CI full installer: reset to a clean slate, then apply the
# structural baseline + migrations and (re)load the idempotent engine code.
# (Production upgrades use deploy/migrations/run-migrations.sh, which migrates
# in place without the reset.)
#
# SKIP_RESET=1 turns this into a non-destructive in-place upgrade: skip the
# reset and let `apply_migrations` run only pending migrations on top of the
# existing schema (preserving stores/tuples/audit). `upgrade.sh` is the wrapper.
if [ "${SKIP_RESET:-}" = "1" ]; then
  echo "==> Upgrading in place (SKIP_RESET=1) — preserving existing data..."
else
  echo "==> Resetting schema (clean install)..."
  reset_schema
fi

echo "==> Applying structural migrations (sqlx)..."
apply_migrations

echo "==> Loading engine code (substrate + read + write + audit)..."
while IFS= read -r f; do
  psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/$f"
done < <(engine_files_for substrate read write audit)

echo "==> Creating audit partitions (current + next month)..."
psql_exec "$PG_DB" -c "SELECT authz.ensure_audit_partitions();"

echo "==> Loading OpenFGA import functions..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/openfga/functions_openfga.sql"

echo "==> Setting up security roles..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/security/roles.sql"

# Optional: enable the CEL condition evaluator if the pg_cel extension is
# present in this image (see extensions/pg-cel + compose-cel.yml). This is a
# no-op on the stock postgres image, so the default stack is unaffected and
# only lang='sql' conditions are available; with the extension installed,
# lang='cel' conditions become writable and evaluable.
echo "==> Enabling CEL evaluator (pg_cel) if available..."
# Install into the engine's own schema: the CEL evaluator is an engine
# dependency, so it belongs in authz (not public), and the engine references
# authz.cel_eval_bool / authz.cel_compile_check explicitly. SCHEMA authz also
# makes DROP SCHEMA authz CASCADE clean it up with everything else on re-init.
if psql_exec "$PG_DB" -c "CREATE EXTENSION IF NOT EXISTS pg_cel SCHEMA authz;" >/dev/null 2>&1; then
  echo "    pg_cel enabled — CEL conditions available"
else
  echo "    pg_cel not installed — CEL conditions disabled (sql conditions unaffected)"
fi

# Optional env-driven overrides on top of the roles.sql defaults (see
# .env.example). Service-role PASSWORDS are set at initdb instead (changing them
# needs a fresh DB: down -v + init); these knobs apply on every init.
if [ -n "${CONDITION_STATEMENT_TIMEOUT:-}" ]; then
  echo "==> Setting statement_timeout=$CONDITION_STATEMENT_TIMEOUT on service roles..."
  psql_exec "$PG_DB" -c "ALTER ROLE authzen_direct SET statement_timeout = '$CONDITION_STATEMENT_TIMEOUT';
                         ALTER ROLE pgauthzd_rw    SET statement_timeout = '$CONDITION_STATEMENT_TIMEOUT';" >/dev/null
fi
if [ -n "${AUTHZ_CONTEXTUAL_READER_GRANTEE:-}" ]; then
  echo "==> Granting authz_contextual_reader to $AUTHZ_CONTEXTUAL_READER_GRANTEE..."
  psql_exec "$PG_DB" -c "GRANT authz_contextual_reader TO \"$AUTHZ_CONTEXTUAL_READER_GRANTEE\";" >/dev/null
fi

echo ""
echo "==> Engine installed (no example stores). Connect with:"
echo "    docker exec -it $DB_CONTAINER psql -U $PG_USER -d $PG_DB"
echo ""
echo "    Load an example model (creates the 'demo' store):"
echo "      ./tests/test.sh        # loads + tests the demo model"
echo "      # or manually:"
echo "      cat examples/models/demo/model.sql examples/models/demo/seed.sql | \\"
echo "        docker exec -i $DB_CONTAINER psql -U $PG_USER -d $PG_DB"
echo ""
