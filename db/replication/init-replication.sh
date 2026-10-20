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
#   ./db/replication/init-replication.sh
#
# REPLICATION_COMPOSE_FILES (colon-separated, default compose-replication.yml,
# relative to the repo root) adds override files — e.g. one that moves the
# host ports so the demo can run next to the main stack; set
# COMPOSE_PROJECT_NAME as well to keep the two stacks' networks apart.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # db/replication
PG_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"                    # repo root
cd "$PG_DIR"
source "$PG_DIR/db/engine/manifest.sh"

COMPOSE=(docker compose)
IFS=: read -ra _compose_files <<< "${REPLICATION_COMPOSE_FILES:-compose-replication.yml}"
for _f in "${_compose_files[@]}"; do COMPOSE+=(-f "$_f"); done

psql_primary() {
    docker exec -i -e PGPASSWORD=authz \
        "$("${COMPOSE[@]}" ps -q authz-primary)" \
        psql -U authz -d authz "$@"
}

psql_accounting() {
    docker exec -i -e PGPASSWORD=authz \
        "$("${COMPOSE[@]}" ps -q accounting-app-db)" \
        psql -U authz -d authz "$@"
}

psql_derived() {
    docker exec -i -e PGPASSWORD=authz \
        "$("${COMPOSE[@]}" ps -q accounting-app-derived-db)" \
        psql -U authz -d authz "$@"
}

psql_dms() {
    docker exec -i -e PGPASSWORD=authz \
        "$("${COMPOSE[@]}" ps -q accounting-app-dms-db)" \
        psql -U authz -d authz "$@"
}

# Apply ALL structural migrations in order via psql (the demo has no sqlx
# migration ledger — it does not do upgrades — so it replays every
# db/migrations/NNNN_*.sql, not just the frozen baseline, to stay in sync as
# new structural deltas land).
apply_migrations_via() {
    local psql_fn=$1
    local m
    for m in "$PG_DIR"/db/migrations/*.sql; do
        "$psql_fn" < "$m"
    done
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

echo "==> [primary] Applying structural migrations + loading engine (full)..."
# One-shot demo setup: apply the structural migrations via psql (the connection
# is already authz, so SET LOCAL ROLE is a harmless no-op), then the idempotent
# engine code.
apply_migrations_via psql_primary
while IFS= read -r f; do
  psql_primary < "$PG_DIR/db/engine/$f"
done < <(engine_files_for substrate read write audit)

echo "==> [primary] Loading OpenFGA import functions..."
psql_primary < "$PG_DIR/db/openfga/functions_openfga.sql"

echo "==> [primary] Loading demo model..."
psql_primary < "$PG_DIR/examples/models/demo/model.sql"

echo "==> [primary] Loading materialized permissions infrastructure..."
psql_primary < "$SCRIPT_DIR/materialized_permissions.sql"

echo "==> [primary] Loading demo seed data..."
psql_primary < "$PG_DIR/examples/models/demo/seed.sql"

echo "==> [primary] Namespace 'dms' = the document application's types (document, folder); the worker's login role may read every namespace..."
psql_primary -c "SELECT authz.model_set_type_namespace('demo', 'document', 'dms'), authz.model_set_type_namespace('demo', 'folder', 'dms');"
psql_primary -c "SELECT authz.grant_namespace_access('demo', 'dms', 'authz', p_can_read => true, p_can_write => true);"

echo "==> [primary] Building materialized permissions (initial snapshot; registers the store for incremental refresh from the audit changefeed)..."
psql_primary -c "SELECT authz.refresh_all_materialized_permissions('demo') AS permissions_created;"

echo "==> [primary] Creating publications..."
psql_primary < "$SCRIPT_DIR/setup-publication.sql"

# ══════════════════════════════════════════════════════════════════════
# Approach 1: Full authz replica (schema + functions + selective tuples)
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "==> [accounting-app] Applying structural migrations + loading engine (full)..."
apply_migrations_via psql_accounting
while IFS= read -r f; do
  psql_accounting < "$PG_DIR/db/engine/$f"
done < <(engine_files_for substrate read write audit)

echo "==> [accounting-app] Loading OpenFGA import functions..."
psql_accounting < "$PG_DIR/db/openfga/functions_openfga.sql"

echo "==> [accounting-app] Loading demo model (creates partitions, no tuples)..."
psql_accounting < "$PG_DIR/examples/models/demo/model.sql"

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
# Approach 2b: one application's namespace only (row-filtered publication)
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "==> [accounting-app-dms] Loading minimal schema..."
psql_dms < "$SCRIPT_DIR/schema-derived.sql"

echo "==> [accounting-app-dms] Creating the namespace-scoped subscription (publication authz_derived_dms)..."
psql_dms < "$SCRIPT_DIR/setup-subscription-dms.sql"

# ══════════════════════════════════════════════════════════════════════
# Wait for sync
# ══════════════════════════════════════════════════════════════════════

echo ""
wait_for_sync psql_accounting "accounting-app"
wait_for_sync psql_derived "accounting-app-derived"
wait_for_sync psql_dms "accounting-app-dms"

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

echo "--- alice can_read doc_acc_001 (should be FALSE — no path into the accounting engagement) ---"
psql_derived -c \
    "SELECT authz.check_permission('demo','internal_user','alice','can_read','document','doc_acc_001');"

echo ""
echo "--- All permissions for doc_acc_001 ---"
psql_derived -c \
    "SELECT user_type, user_id, permission FROM authz.materialized_permissions
      WHERE object_type = 'document' AND object_id = 'doc_acc_001'
      ORDER BY user_type, user_id, permission;"

echo "--- nadia_auditor (viewer on document:*) can_read a document the engine has never seen (should be TRUE: the '*' row applies to unknown objects) ---"
psql_derived -c \
    "SELECT authz.check_permission('demo','internal_user','nadia_auditor','can_read','document','doc_never_touched');"

echo ""
echo "================================================================"
echo "  Approach 2b: one namespace only (dms = document, folder)"
echo "================================================================"
echo ""
echo "--- object types on the dms subscriber (only the namespace's) ---"
psql_dms -c "SELECT object_type, count(*) FROM authz.materialized_permissions GROUP BY 1 ORDER BY 1;"
echo "--- subjects are store-wide; eva reads doc_acc_001 here too ---"
psql_dms -c "SELECT (SELECT count(*) FROM authz.materialized_subjects) AS known_subjects, authz.check_permission('demo','internal_user','eva','can_read','document','doc_acc_001') AS eva_can_read, authz.permissions_as_of('demo') AS as_of;"

echo ""
echo "================================================================"
echo "  Done."
echo "================================================================"
echo ""
echo "  Primary:              localhost:55433  (full authz database)"
echo "  Accounting app:       localhost:55435  (full replica, selective tuples)"
echo "  Accounting app (derived): localhost:55436  (flat permissions table only)"
echo "  Accounting app (dms):     localhost:55437  (flat permissions, namespace dms only)"
echo ""
echo "  Connect with:"
echo "    docker exec -it \$(docker compose -f compose-replication.yml ps -q authz-primary) psql -U authz -d authz"
echo "    docker exec -it \$(docker compose -f compose-replication.yml ps -q accounting-app-db) psql -U authz -d authz"
echo "    docker exec -it \$(docker compose -f compose-replication.yml ps -q accounting-app-derived-db) psql -U authz -d authz"
echo "    docker exec -it \$(docker compose -f compose-replication.yml ps -q accounting-app-dms-db) psql -U authz -d authz"
echo ""
