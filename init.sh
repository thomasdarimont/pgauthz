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

echo "==> Loading schema..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/schema.sql"

echo "==> Loading internal functions..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/core_internal.sql"
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/access_internal.sql"
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/audit_internal.sql"

echo "==> Loading public API functions..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/store.sql"
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/access.sql"
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/explain.sql"
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/tuples.sql"
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/audit.sql"
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/model.sql"

echo "==> Creating audit partitions (current + next month)..."
psql_exec "$PG_DB" -c "SELECT authz.ensure_audit_partitions();"

echo "==> Loading OpenFGA import functions..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/openfga/functions_openfga.sql"

echo "==> Setting up security roles..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/security/roles.sql"

# A PostgREST instance that connected before the engine schema existed (e.g. a
# freshly started stack, as in CI) holds a stale/empty schema cache and its
# /rpc/* endpoints won't see the engine functions. Nudge a reload now that the
# schema is installed. No-op if no PostgREST is listening on the channel.
echo "==> Reloading PostgREST schema cache (NOTIFY pgrst)..."
psql_exec "$PG_DB" -c "NOTIFY pgrst, 'reload schema';" >/dev/null 2>&1 || true

echo ""
echo "==> Engine installed (no example stores). Connect with:"
echo "    docker exec -it $DB_CONTAINER psql -U $PG_USER -d $PG_DB"
echo ""
echo "    Load an example model (creates the 'demo' store):"
echo "      ./tests/test.sh        # loads + tests the demo model"
echo "      # or manually:"
echo "      cat examples/demo/model.sql examples/demo/seed.sql | \\"
echo "        docker exec -i $DB_CONTAINER psql -U $PG_USER -d $PG_DB"
echo ""
