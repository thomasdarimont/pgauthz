#!/usr/bin/env bash
#
# Integration test for the logical-replication demo (compose-replication.yml +
# db/replication/init-replication.sh). Brings up the primary + two subscriber
# topologies, runs the setup, then INDEPENDENTLY asserts they work:
#
#   - full replica (accounting-app-db): subscriptions reach 'ready', resolves
#     check_access locally on replicated tuples, and reflects a live write made
#     on the primary;
#   - derived replica (accounting-app-derived-db): receives the flat
#     materialized_permissions table.
#
# The assertions are independent of init-replication.sh's own output because
# that script does not use ON_ERROR_STOP — a SQL error leaves a broken setup but
# still exits 0, so only these checks catch a regression.
#
# Leaves the stack running for inspection; the caller tears it down
# (the CI job and a final hint below).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
COMPOSE=(docker compose -f compose-replication.yml)

echo "==> Resetting + bringing up the replication stack..."
"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --wait

echo "==> Running init-replication.sh..."
./db/replication/init-replication.sh

PRIMARY=$("${COMPOSE[@]}" ps -q authz-primary)
ACCT=$("${COMPOSE[@]}" ps -q accounting-app-db)
DERIVED=$("${COMPOSE[@]}" ps -q accounting-app-derived-db)
qp() { docker exec -e PGPASSWORD=authz "$1" psql -U authz -d authz -tA -c "$2"; }

fail=0
assert() {  # description  expected  actual
  if [ "$2" = "$3" ]; then echo "    PASS  $1"; else echo "    FAIL  $1 (expected '$2', got '$3')"; fail=1; fi
}

# Poll until every subscribed table on $1 is 'r' (ready), or time out.
wait_ready() {  # container  label
  for _ in $(seq 1 30); do
    [ "$(qp "$1" "SELECT count(*) FROM pg_subscription_rel WHERE srsubstate <> 'r';")" = "0" ] && return 0
    sleep 2
  done
  return 1
}

echo "==> Asserting subscription health..."
wait_ready "$ACCT"    && assert "accounting-app: all subscriptions ready" "ok" "ok" \
                      || assert "accounting-app: all subscriptions ready" "ok" "timeout"
wait_ready "$DERIVED" && assert "derived: all subscriptions ready"        "ok" "ok" \
                      || assert "derived: all subscriptions ready"        "ok" "timeout"
# Replication is actively streaming (3 subscribers connected to the primary).
assert "primary has 3 streaming replication connections" "3" \
  "$(qp "$PRIMARY" "SELECT count(*) FROM pg_stat_replication WHERE state='streaming';")"

echo "==> Asserting the FULL replica resolves access on replicated data..."
assert "replica: eva can_read accounting doc" "t" \
  "$(qp "$ACCT" "SELECT authz.check_access('demo','internal_user','eva','can_read','document','doc_acc_001');")"
assert "replica: carol cannot read client doc (space not replicated)" "f" \
  "$(qp "$ACCT" "SELECT authz.check_access('demo','client_user','carol','can_read','document','doc_client_001');")"

echo "==> Asserting the DERIVED replica received materialized permissions..."
assert "derived: materialized_permissions populated" "t" \
  "$(qp "$DERIVED" "SELECT count(*) > 0 FROM authz.materialized_permissions;")"

echo "==> Asserting LIVE propagation (write on primary -> full replica)..."
qp "$PRIMARY" "SELECT authz.write_tuple('demo','internal_user','ci_repltest','viewer','document','doc_acc_001');" >/dev/null
live=timeout
for _ in $(seq 1 15); do
  if [ "$(qp "$ACCT" "SELECT authz.check_access('demo','internal_user','ci_repltest','can_read','document','doc_acc_001');")" = "t" ]; then
    live=ok; break
  fi
  sleep 1
done
assert "replica reflects a primary write within 15s" "ok" "$live"

echo ""
if [ "$fail" -ne 0 ]; then
  echo "==> REPLICATION TESTS FAILED"
  exit 1
fi
echo "==> All replication tests passed."
echo "    (stack left running — tear down with: ${COMPOSE[*]} down -v)"
