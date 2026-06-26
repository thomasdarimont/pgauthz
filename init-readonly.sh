#!/usr/bin/env bash
#
# Installs the READ-ONLY engine excerpt: the substrate + read profiles only
# (see db/engine/manifest.sh) — access checks, search (list_*), explain, and
# condition evaluation, with NO write/management API and NO audit tables.
#
# Intended for an APPLICATION database that holds a replicated copy of the
# tuples + model (see db/replication/) and answers access queries locally,
# the in-database alternative to calling a central authz service per check.
# The replicated authz.* tables are populated by logical replication; this
# script only installs the engine that reads them.
#
# WARNING: like init.sh, this runs schema.sql which does DROP SCHEMA authz
# CASCADE. Point it at the target app database, never at a primary that holds
# the authoritative write side.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
source "$SCRIPT_DIR/db/engine/manifest.sh"

echo "==> Loading engine (read-only: substrate + read)..."
while IFS= read -r f; do
  psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/$f"
done < <(engine_files_for substrate read)

echo "==> Setting up read-only security role..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/security/roles_readonly.sql"

# Optional CEL evaluator, only if the replicated store uses lang='cel'
# conditions and the pg_cel extension is present in this image.
echo "==> Enabling CEL evaluator (pg_cel) if available..."
if psql_exec "$PG_DB" -c "CREATE EXTENSION IF NOT EXISTS pg_cel SCHEMA authz;" >/dev/null 2>&1; then
  echo "    pg_cel enabled — CEL conditions evaluable"
else
  echo "    pg_cel not installed — sql conditions only"
fi

echo ""
echo "==> Read-only engine installed (no write API, no audit tables)."
echo "    Populate authz.* via replication from the central store, then run"
echo "    access checks locally: SELECT authz.check_access(...);"
