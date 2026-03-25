#!/usr/bin/env bash
#
# Interactive demo: shows how authorization changes on the primary
# propagate to the derived app database via logical replication.
#
# Prerequisites:
#   docker compose -f compose-replication.yml up -d --wait
#   ./replication/init-replication.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$(dirname "$SCRIPT_DIR")/compose-replication.yml"

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[32m'
BLUE='\033[34m'
YELLOW='\033[33m'
RESET='\033[0m'

primary() {
    docker exec -i -e PGPASSWORD=authz \
        "$(docker compose -f "$COMPOSE_FILE" ps -q authz-primary)" \
        psql -U authz -d authz "$@"
}

derived() {
    docker exec -i -e PGPASSWORD=authz \
        "$(docker compose -f "$COMPOSE_FILE" ps -q accounting-app-derived-db)" \
        psql -U authz -d authz "$@"
}

section() {
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  $1${RESET}"
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo ""
}

step() {
    echo -e "${YELLOW}▸ $1${RESET}"
}

pause() {
    echo ""
    echo -e "${DIM}  Press Enter to continue...${RESET}"
    read -r
}

run_primary() {
    echo -e "${GREEN}  [primary]${RESET} $1"
    primary -c "$1"
}

run_derived() {
    echo -e "${BLUE}  [derived]${RESET} $1"
    derived -c "$1"
}

# ─────────────────────────────────────────────────────────────────────

section "1. Current state after init"

step "Who can read doc_acc_001? (primary — full check_access)"
run_primary "
SELECT user_type, user_id, permission
  FROM authz.materialized_permissions
 WHERE object_type = 'document' AND object_id = 'doc_acc_001'
 ORDER BY user_type, user_id, permission;
"

step "Same data on the derived app DB (flat lookup, no authz functions):"
run_derived "
SELECT user_type, user_id, permission
  FROM authz.materialized_permissions
 WHERE object_type = 'document' AND object_id = 'doc_acc_001'
 ORDER BY user_type, user_id, permission;
"

step "Can grace read doc_acc_001? (she has no access yet)"
run_primary "SELECT authz.check_access('demo','internal_user','grace','can_read','document','doc_acc_001');"
run_derived "SELECT authz.check_permission('demo','internal_user','grace','can_read','document','doc_acc_001');"

pause

# ─────────────────────────────────────────────────────────────────────

section "2. Grant access: add grace to accounting_team"

step "Write tuple on primary: grace → member → team:accounting_team"
run_primary "SELECT authz.write_tuple('demo', 'internal_user', 'grace', 'member', 'team', 'accounting_team');"

step "Verify on primary (immediate — check_access resolves the full graph):"
run_primary "SELECT authz.check_access('demo','internal_user','grace','can_read','document','doc_acc_001');"

step "Derived app DB doesn't know yet (queue not processed):"
run_derived "SELECT authz.check_permission('demo','internal_user','grace','can_read','document','doc_acc_001');"

pause

# ─────────────────────────────────────────────────────────────────────

section "3. Process the refresh queue → replicates to derived DB"

step "Pending queue entries on primary:"
run_primary "SELECT count(*) AS pending FROM authz.permissions_refresh_queue;"

step "Process the queue:"
run_primary "SELECT authz.process_permissions_refresh_queue() AS permissions_refreshed;"

step "Wait for replication..."
sleep 2

step "Now check derived app DB — grace can read doc_acc_001:"
run_derived "SELECT authz.check_permission('demo','internal_user','grace','can_read','document','doc_acc_001');"

step "Full permission set for doc_acc_001 on derived DB:"
run_derived "
SELECT user_type, user_id, permission
  FROM authz.materialized_permissions
 WHERE object_type = 'document' AND object_id = 'doc_acc_001'
 ORDER BY user_type, user_id, permission;
"

pause

# ─────────────────────────────────────────────────────────────────────

section "4. Add a new accounting document"

step "Create doc_acc_002 in the accounting internal space (primary):"
run_primary "SELECT authz.write_tuple('demo', 'internal_data_space', 'eng_42_accounting_internal', 'in_internal_space', 'document', 'doc_acc_002');"

step "Verify on primary — eva and grace can read it (accounting_team members):"
run_primary "SELECT authz.check_access('demo','internal_user','eva','can_read','document','doc_acc_002');"
run_primary "SELECT authz.check_access('demo','internal_user','grace','can_read','document','doc_acc_002');"

step "bob can also read it (advisor on parent engagement):"
run_primary "SELECT authz.check_access('demo','internal_user','bob','can_read','document','doc_acc_002');"

step "alice cannot read it (payroll_team, not accounting_team):"
run_primary "SELECT authz.check_access('demo','internal_user','alice','can_read','document','doc_acc_002');"

step "Process queue and wait for replication:"
run_primary "SELECT authz.process_permissions_refresh_queue() AS permissions_refreshed;"
sleep 2

step "Derived app DB — all permissions for doc_acc_002:"
run_derived "
SELECT user_type, user_id, permission
  FROM authz.materialized_permissions
 WHERE object_type = 'document' AND object_id = 'doc_acc_002'
 ORDER BY user_type, user_id, permission;
"

pause

# ─────────────────────────────────────────────────────────────────────

section "5. Revoke access: remove grace from accounting_team"

step "Delete tuple on primary:"
run_primary "SELECT authz.delete_tuple('demo', 'internal_user', 'grace', 'member', 'team', 'accounting_team');"

step "Primary — grace can no longer read doc_acc_001:"
run_primary "SELECT authz.check_access('demo','internal_user','grace','can_read','document','doc_acc_001');"

step "Process queue and replicate:"
run_primary "SELECT authz.process_permissions_refresh_queue() AS permissions_refreshed;"
sleep 2

step "Derived app DB — grace is gone:"
run_derived "SELECT authz.check_permission('demo','internal_user','grace','can_read','document','doc_acc_001');"
run_derived "
SELECT user_type, user_id, permission
  FROM authz.materialized_permissions
 WHERE object_type = 'document' AND object_id = 'doc_acc_001'
   AND user_id = 'grace';
"

pause

# ─────────────────────────────────────────────────────────────────────

section "6. Access revoked on primary stops working on derived DB"

step "eva currently has access to doc_acc_001 (she's in accounting_team):"
run_primary "SELECT authz.check_access('demo','internal_user','eva','can_read','document','doc_acc_001');"
run_derived "SELECT authz.check_permission('demo','internal_user','eva','can_read','document','doc_acc_001');"

step "The accounting app grants eva access to an internal workflow based on this permission."
echo "    (e.g., the app shows eva an 'Approve' button on doc_acc_001)"
echo ""

pause

step "Meanwhile, eva is removed from accounting_team on the primary:"
run_primary "SELECT authz.delete_tuple('demo', 'internal_user', 'eva', 'member', 'team', 'accounting_team');"

step "Primary immediately reflects the change — eva can no longer read:"
run_primary "SELECT authz.check_access('demo','internal_user','eva','can_read','document','doc_acc_001');"

step "Derived app DB still shows the old permission (queue not processed yet):"
run_derived "SELECT authz.check_permission('demo','internal_user','eva','can_read','document','doc_acc_001');"

step "Process queue and wait for replication:"
run_primary "SELECT authz.process_permissions_refresh_queue() AS permissions_refreshed;"
sleep 2

step "Now the derived app DB reflects the revocation — eva's access is gone:"
run_derived "SELECT authz.check_permission('demo','internal_user','eva','can_read','document','doc_acc_001');"

step "All remaining permissions for doc_acc_001 (eva is no longer listed):"
run_derived "
SELECT user_type, user_id, permission
  FROM authz.materialized_permissions
 WHERE object_type = 'document' AND object_id = 'doc_acc_001'
 ORDER BY user_type, user_id, permission;
"

step "Restoring eva to accounting_team for subsequent runs..."
run_primary "SELECT authz.write_tuple('demo', 'internal_user', 'eva', 'member', 'team', 'accounting_team');"
run_primary "SELECT authz.process_permissions_refresh_queue() AS permissions_refreshed;"
sleep 1

pause

# ─────────────────────────────────────────────────────────────────────

section "7. Summary"

echo "  The demo showed two integration patterns:"
echo ""
echo "  Primary (port 55433):"
echo "    - Full authz engine: check_access() resolves the graph in real-time"
echo "    - Writes tuples, evaluates conditions, traverses TTU chains"
echo ""
echo "  Derived app DB (port 55436):"
echo "    - No authz schema or functions — just a flat permissions table"
echo "    - Simple EXISTS lookup via check_permission()"
echo "    - Updated via: trigger → queue → process → logical replication"
echo ""
echo "  Latency: change on primary → available on derived app DB"
echo "    = queue processing time + replication lag (typically < 1s)"
echo ""

# ── Cleanup demo data ───────────────────────────────────────────────

step "Cleaning up demo data (removing doc_acc_002)..."
primary -c "SELECT authz.delete_tuple('demo', 'internal_data_space', 'eng_42_accounting_internal', 'in_internal_space', 'document', 'doc_acc_002');" > /dev/null 2>&1
primary -c "SELECT authz.process_permissions_refresh_queue();" > /dev/null 2>&1

echo ""
echo "  Done."
echo ""
