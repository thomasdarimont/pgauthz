#!/usr/bin/env bash
#
# Fast dev reload of the idempotent engine CODE (functions / views / triggers)
# plus security roles, into an already-running database. It does NOT touch
# structure (migrations), data (stores/tuples/audit), or example models —
# so it's much quicker than ./init.sh for iterating on db/engine/*.sql.
#
# IMPORTANT: it always re-runs db/security/roles.sql last. A plain
# `CREATE OR REPLACE FUNCTION` resets a function's SECURITY DEFINER attribute
# back to INVOKER, so reloading engine code alone would silently break
# non-owner callers (e.g. the playground's authz_metadata role → "permission
# denied for function _s"). roles.sql re-applies SECURITY DEFINER + grants.
#
# For STRUCTURAL changes (db/migrations/*.sql) use ./init.sh or ./upgrade.sh.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
source "$SCRIPT_DIR/db/engine/manifest.sh"

echo "==> Reloading engine code (substrate + read + write + audit)..."
while IFS= read -r f; do
  psql_file "$PG_DB" "$SCRIPT_DIR/db/engine/$f"
done < <(engine_files_for substrate read write audit)

echo "==> Reloading OpenFGA import functions..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/openfga/functions_openfga.sql"

echo "==> Re-applying security roles (restores SECURITY DEFINER + grants)..."
psql_file "$PG_DB" "$SCRIPT_DIR/db/security/roles.sql"

echo "==> Engine code reloaded (structure/data untouched)."
