#!/usr/bin/env bash
#
# Starts PostgreSQL and loads the authorization schema, functions,
# model rules, and seed data. Idempotent — safe to re-run.
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
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/tuples.sql"
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/audit.sql"
psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/model.sql"

echo "==> Loading OpenFGA import functions..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/openfga/functions_openfga.sql"

echo "==> Loading demo model rules..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/models/demo/model.sql"

echo "==> Loading demo model seed data..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/models/demo/seed.sql"

echo "==> Setting up security roles..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/security/roles.sql"

echo "==> Creating test login users..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/tests/test_users.sql"

echo ""
echo "==> Done. Connect with:"
echo "    docker exec -it $DB_CONTAINER psql -U $PG_USER -d $PG_DB"
echo ""
echo "    Example queries:"
echo "      SELECT authz.check_access('demo','internal_user','alice','can_read','document','doc_payroll_001');"
echo "      SELECT * FROM authz.list_objects('demo','internal_user','bob','can_read','document');"
echo ""
