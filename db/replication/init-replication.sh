#!/usr/bin/env bash
#
# Sets up selective logical replication from the central authz database
# to two application databases demonstrating different approaches:
#
#   1. accounting-app-db         — full authz replica (schema + functions + selective tuples)
#   2. accounting-app-derived-db — derived replica (flat permissions table only, no authz schema)
#
# Usage:
#   docker compose -f compose-replication.yml up -d --wait
#   ./replication/init-replication.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PG_DIR/compose-replication.yml"

psql_primary() {
    docker exec -i -e PGPASSWORD=authz \
        "$(docker compose -f "$COMPOSE_FILE" ps -q authz-primary)" \
        psql -U authz -d authz "$@"
}

psql_accounting() {
    docker exec -i -e PGPASSWORD=authz \
        "$(docker compose -f "$COMPOSE_FILE" ps -q accounting-app-db)" \
        psql -U authz -d authz "$@"
}

psql_derived() {
    docker exec -i -e PGPASSWORD=authz \
        "$(docker compose -f "$COMPOSE_FILE" ps -q accounting-app-derived-db)" \
        psql -U authz -d authz "$@"
}

wait_for_sync() {
    local psql_fn=$1
    local label=$2
    echo "==> Waiting for $label sync..."
    for i in $(seq 1 20); do
        status=$($psql_fn -t -A -c \
            "SELECT coalesce(string_agg(srsubstate, ''), '') FROM pg_subscription_rel WHERE srsubstate NOT IN ('r', 's');" \
            2>&1)
        if [ "$status" = "" ]; then
            echo "    Sync complete."
            return 0
        fi
        echo "    Waiting... ($i) [pending states: $status]"
        sleep 2
    done
    echo "    WARNING: sync not confirmed after 40s. Current state:"
    $psql_fn -c "SELECT s.subname, r.srsubstate, r.srsublsn FROM pg_subscription_rel r JOIN pg_subscription s ON s.oid = r.srsubid;"
}

# ══════════════════════════════════════════════════════════════════════
# Primary: full schema + model + seed data + materialized permissions
# ══════════════════════════════════════════════════════════════════════

echo "==> [primary] Loading schema..."
psql_primary < "$PG_DIR/db/engine/schema.sql"

echo "==> [primary] Loading internal functions..."
psql_primary < "$PG_DIR/db/engine/core_internal.sql"
psql_primary < "$PG_DIR/db/engine/access_internal.sql"
psql_primary < "$PG_DIR/db/engine/audit_internal.sql"

echo "==> [primary] Loading public API functions..."
psql_primary < "$PG_DIR/db/engine/store.sql"
psql_primary < "$PG_DIR/db/engine/access.sql"
psql_primary < "$PG_DIR/db/engine/tuples.sql"
psql_primary < "$PG_DIR/db/engine/audit.sql"
psql_primary < "$PG_DIR/db/engine/model.sql"

echo "==> [primary] Loading OpenFGA import functions..."
psql_primary < "$PG_DIR/db/openfga/functions_openfga.sql"

echo "==> [primary] Loading demo model..."
psql_primary < "$PG_DIR/examples/demo/model.sql"

echo "==> [primary] Loading materialized permissions infrastructure..."
psql_primary < "$SCRIPT_DIR/materialized_permissions.sql"

echo "==> [primary] Loading demo seed data..."
psql_primary < "$PG_DIR/examples/demo/seed.sql"

echo "==> [primary] Building materialized permissions (initial full refresh)..."
psql_primary -c "SELECT authz.refresh_all_materialized_permissions('demo') AS permissions_created;"
psql_primary -c "DELETE FROM authz.permissions_refresh_queue;" 2>/dev/null

echo "==> [primary] Creating publications..."
psql_primary < "$SCRIPT_DIR/setup-publication.sql"

# ══════════════════════════════════════════════════════════════════════
# Approach 1: Full authz replica (schema + functions + selective tuples)
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "==> [accounting-app] Loading schema..."
psql_accounting < "$PG_DIR/db/engine/schema.sql"

echo "==> [accounting-app] Loading internal functions..."
psql_accounting < "$PG_DIR/db/engine/core_internal.sql"
psql_accounting < "$PG_DIR/db/engine/access_internal.sql"
psql_accounting < "$PG_DIR/db/engine/audit_internal.sql"

echo "==> [accounting-app] Loading public API functions..."
psql_accounting < "$PG_DIR/db/engine/store.sql"
psql_accounting < "$PG_DIR/db/engine/access.sql"
psql_accounting < "$PG_DIR/db/engine/tuples.sql"
psql_accounting < "$PG_DIR/db/engine/audit.sql"
psql_accounting < "$PG_DIR/db/engine/model.sql"

echo "==> [accounting-app] Loading OpenFGA import functions..."
psql_accounting < "$PG_DIR/db/openfga/functions_openfga.sql"

echo "==> [accounting-app] Loading demo model (creates partitions, no tuples)..."
psql_accounting < "$PG_DIR/examples/demo/model.sql"

echo "==> [accounting-app] Creating subscriptions..."
psql_accounting < "$SCRIPT_DIR/setup-subscription.sql"

# ══════════════════════════════════════════════════════════════════════
# Approach 2: Derived permissions (flat table only, no authz schema)
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "==> [accounting-app-derived] Loading minimal schema..."
psql_derived < "$SCRIPT_DIR/schema-derived.sql"

echo "==> [accounting-app-derived] Creating subscription..."
psql_derived < "$SCRIPT_DIR/setup-subscription-derived.sql"

# ══════════════════════════════════════════════════════════════════════
# Wait for sync
# ══════════════════════════════════════════════════════════════════════

echo ""
wait_for_sync psql_accounting "accounting-app"
wait_for_sync psql_derived "accounting-app-derived"

# ══════════════════════════════════════════════════════════════════════
# Verify
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "================================================================"
echo "  Approach 1: Full authz replica (check_access on local tuples)"
echo "================================================================"
echo ""
echo "--- Tuple counts ---"
echo "Primary (all types):"
psql_primary -c "SELECT count(*) AS total_tuples FROM authz.tuples;"
echo "Accounting app (accounting-relevant types only):"
psql_accounting -c "SELECT count(*) AS total_tuples FROM authz.tuples;"

echo ""
echo "--- eva can_read doc_acc_001 (should be TRUE) ---"
psql_accounting -c \
    "SELECT authz.check_access('demo','internal_user','eva','can_read','document','doc_acc_001');"

echo "--- carol can_read doc_client_001 (should be FALSE — client_data_space not replicated) ---"
psql_accounting -c \
    "SELECT authz.check_access('demo','client_user','carol','can_read','document','doc_client_001');"

echo ""
echo "================================================================"
echo "  Approach 2: Derived permissions (flat lookup, no authz schema)"
echo "================================================================"
echo ""
echo "--- Permissions replicated ---"
psql_derived -c "SELECT count(*) AS total_permissions FROM authz.materialized_permissions;"

echo ""
echo "--- eva can_read doc_acc_001 (should be TRUE) ---"
psql_derived -c \
    "SELECT authz.check_permission('demo','internal_user','eva','can_read','document','doc_acc_001');"

echo "--- bob can_read doc_acc_001 (should be FALSE — bob is not in accounting_team) ---"
psql_derived -c \
    "SELECT authz.check_permission('demo','internal_user','bob','can_read','document','doc_acc_001');"

echo ""
echo "--- All permissions for doc_acc_001 ---"
psql_derived -c \
    "SELECT user_type, user_id, permission FROM authz.materialized_permissions
      WHERE object_type = 'document' AND object_id = 'doc_acc_001'
      ORDER BY user_type, user_id, permission;"

echo ""
echo "================================================================"
echo "  Done."
echo "================================================================"
echo ""
echo "  Primary:              localhost:55433  (full authz database)"
echo "  Accounting app:       localhost:55435  (full replica, selective tuples)"
echo "  Accounting app (derived): localhost:55436  (flat permissions table only)"
echo ""
echo "  Connect with:"
echo "    docker exec -it \$(docker compose -f compose-replication.yml ps -q authz-primary) psql -U authz -d authz"
echo "    docker exec -it \$(docker compose -f compose-replication.yml ps -q accounting-app-db) psql -U authz -d authz"
echo "    docker exec -it \$(docker compose -f compose-replication.yml ps -q accounting-app-derived-db) psql -U authz -d authz"
echo ""
