#!/usr/bin/env bash
#
# Interactive demo: shows how authorization changes on the primary
# propagate to the derived app database via logical replication.
#
# Prerequisites:
#   docker compose -f compose-replication.yml up -d --wait
#   ./db/replication/init-replication.sh
#
# REPLICATION_COMPOSE_FILES (colon-separated, relative to the repo root) adds
# compose override files, as for init-replication.sh.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE=(docker compose)
IFS=: read -ra _compose_files <<< "${REPLICATION_COMPOSE_FILES:-compose-replication.yml}"
for _f in "${_compose_files[@]}"; do COMPOSE+=(-f "$_f"); done

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[32m'
BLUE='\033[34m'
YELLOW='\033[33m'
RESET='\033[0m'

primary() {
    # Notices off: the engine's per-session memo table announces itself on
    # every check the worker makes, which only clutters the narration.
    docker exec -i -e PGPASSWORD=authz \
        "$("${COMPOSE[@]}" ps -q authz-primary)" \
        psql -U authz -d authz -c "SET client_min_messages = warning" "$@"
}

derived() {
    docker exec -i -e PGPASSWORD=authz \
        "$("${COMPOSE[@]}" ps -q accounting-app-derived-db)" \
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

# The worker. The audit changefeed is lag-gated (1 s stability lag, see
# watch_changes), so give the write a moment, pull the feed, then let
# logical replication deliver the rows.
refresh() {
    sleep 1.2
    run_primary "SELECT authz.refresh_materialized_permissions() AS pairs_rederived;"
    sleep 1
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

step "Derived app DB doesn't know yet (worker not run):"
run_derived "SELECT authz.check_permission('demo','internal_user','grace','can_read','document','doc_acc_001');"

pause

# ─────────────────────────────────────────────────────────────────────

section "3. Run the worker → replicates to derived DB"

step "The derived table is refreshed from the audit changefeed; the worker resumes from a stored cursor:"
run_primary "SELECT store, as_of, feed_drained, last_run_changes, last_run_pairs FROM authz.materialized_permissions_status();"

step "Run the worker (pulls the changes since the cursor, re-derives only the affected subject × object pairs), then wait for replication:"
refresh

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

step "Run the worker and wait for replication:"
refresh

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

step "Run the worker and replicate:"
refresh

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

step "Derived app DB still shows the old permission (worker not run yet):"
run_derived "SELECT authz.check_permission('demo','internal_user','eva','can_read','document','doc_acc_001');"

step "Run the worker and wait for replication:"
refresh

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
refresh

pause

# ─────────────────────────────────────────────────────────────────────

section "7. Wildcards on the derived DB — the '*' contract"

step "nadia_auditor holds 'viewer' on document:* (an object wildcard). Her derived rows:"
run_derived "
SELECT permission, object_id
  FROM authz.materialized_permissions
 WHERE store = 'demo' AND user_id = 'nadia_auditor' AND object_type = 'document'
 ORDER BY permission, object_id;
"
echo "    One concrete row per document the engine knows, plus a literal '*' row."
echo "    The engine cannot expand document:* — it does not know which documents"
echo "    the application has — so the '*' row stands in for every document it"
echo "    has never seen."
echo ""

pause

step "A document that has no tuples at all, e.g. one created a second ago. The primary says:"
run_primary "SELECT authz.check_access('demo','internal_user','nadia_auditor','can_read','document','doc_brand_new');"

step "A naive lookup on the derived DB gets it WRONG (no concrete row):"
run_derived "
SELECT EXISTS (
  SELECT 1 FROM authz.materialized_permissions
   WHERE store = 'demo' AND user_type = 'internal_user' AND user_id = 'nadia_auditor'
     AND permission = 'can_read' AND object_type = 'document' AND object_id = 'doc_brand_new') AS naive_lookup;
"

step "check_permission() gets it right — it applies the contract:"
run_derived "SELECT authz.check_permission('demo','internal_user','nadia_auditor','can_read','document','doc_brand_new');"
echo "    The rule: a '*' row applies ONLY to a subject or object the engine does"
echo "    not know. Known entities have authoritative concrete rows (exclusions"
echo "    already applied); an unknown one has no tuples, so nothing can narrow"
echo "    the wildcard for it. 'Known' is what the side tables say:"
run_derived "
SELECT (SELECT count(*) FROM authz.materialized_objects WHERE store = 'demo' AND object_type = 'document') AS known_documents,
       EXISTS (SELECT 1 FROM authz.materialized_objects
                WHERE store = 'demo' AND object_type = 'document' AND object_id = 'doc_brand_new') AS doc_brand_new_known;
"

pause

step "The mirror case — a subject wildcard (e.g. employee:* may 'delegatable' a document) —"
echo "    yields a row with user_id = '*' that applies to users the engine has never"
echo "    seen; materialized_subjects decides who is 'known'. (The demo model has no"
echo "    subject-wildcard relation; tests/test-replication.sh exercises it with the"
echo "    aia-acme fixture.)"
echo ""

step "So a listing query on the derived DB uses the helper, not a join on user_id/object_id:"
echo "    SELECT d.* FROM documents d"
echo "     WHERE authz.check_permission('demo','internal_user', :me, 'can_read', 'document', d.id);"
echo ""

pause

step "A NEW object-wildcard grant re-derives the whole type. Grant demo_auditor2 viewer on document:*"
run_primary "SELECT authz.write_tuple('demo','internal_user','demo_auditor2','viewer','document','*');"
refresh
run_primary "SELECT last_run_changes AS changes_in_feed, last_run_pairs AS pairs_rederived FROM authz.materialized_permissions_status() WHERE store = 'demo';"
echo "    (one change in the feed; the pairs are demo_auditor2 × every known document"
echo "    plus the '*' pseudo-object — their concrete rows are authoritative and must"
echo "    now say 'allowed'. Nobody else is re-derived.)"

step "On the derived DB: known document, unknown document, and someone else on the unknown document"
run_derived "
SELECT authz.check_permission('demo','internal_user','demo_auditor2','can_read','document','doc_acc_001')   AS known_doc,
       authz.check_permission('demo','internal_user','demo_auditor2','can_read','document','doc_brand_new') AS unknown_doc,
       authz.check_permission('demo','internal_user','alice','can_read','document','doc_brand_new')         AS alice_unknown_doc;
"

step "Revoke it again — the rows disappear and demo_auditor2 becomes unknown (wildcard-covered, by nothing):"
run_primary "SELECT authz.delete_tuple('demo','internal_user','demo_auditor2','viewer','document','*');"
refresh
run_derived "
SELECT (SELECT count(*) FROM authz.materialized_permissions WHERE store = 'demo' AND user_id = 'demo_auditor2') AS rows_left,
       EXISTS (SELECT 1 FROM authz.materialized_subjects WHERE store = 'demo' AND user_id = 'demo_auditor2')    AS still_known,
       authz.check_permission('demo','internal_user','demo_auditor2','can_read','document','doc_brand_new')     AS can_read_unknown_doc;
"

pause

# ─────────────────────────────────────────────────────────────────────

section "8. Summary"

echo "  The demo showed two integration patterns:"
echo ""
echo "  Primary (port 55433):"
echo "    - Full authz engine: check_access() resolves the graph in real-time"
echo "    - Writes tuples, evaluates conditions, traverses TTU chains"
echo ""
echo "  Derived app DB (port 55436):"
echo "    - No authz schema or functions — just a flat permissions table"
echo "    - One lookup via check_permission(), which also applies the '*' contract:"
echo "      a wildcard row counts only for subjects/objects the engine does not know"
echo "    - Updated incrementally: audit changefeed → worker (affected pairs only)"
echo "      → logical replication; permissions_as_of(store) says how stale it may be"
echo ""
echo "  Latency: change on primary → available on derived app DB"
echo "    = changefeed stability lag (1 s) + worker cadence + replication lag"
echo ""

# ── Cleanup demo data ───────────────────────────────────────────────

step "Cleaning up demo data (removing doc_acc_002, demo_auditor2)..."
primary -c "SELECT authz.delete_tuple('demo', 'internal_data_space', 'eng_42_accounting_internal', 'in_internal_space', 'document', 'doc_acc_002');" > /dev/null 2>&1
primary -c "SELECT authz.delete_tuple('demo','internal_user','demo_auditor2','viewer','document','*');" > /dev/null 2>&1
sleep 1.2
primary -c "SELECT authz.refresh_materialized_permissions();" > /dev/null 2>&1

echo ""
echo "  Done."
echo ""
