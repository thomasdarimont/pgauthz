#!/usr/bin/env bash
#
# Integration test for the streaming-replication scaling demo
# (compose-scaling.yml): a read-write primary, a read-only hot-standby replica
# streaming its WAL, and PostgREST + OPA serving access checks off the replica.
#
# Installs the engine on the primary via the documented flow
# (COMPOSE_FILE=compose-scaling.yml ./init.sh), seeds the demo, then asserts the
# standby streams the schema + data and resolves checks — directly and through
# the OPA -> PostgREST -> replica path.
#
# Leaves the stack running for inspection; the caller tears it down.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Drive init.sh/env.sh against the scaling topology, in demo trusted-PEP mode so
# the OPA read path resolves without a JWT.
export COMPOSE_FILE=compose-scaling.yml
export REQUIRE_TOKEN_FOR_READS=false
COMPOSE=(docker compose -f compose-scaling.yml)

echo "==> Reset, then install the engine on the primary (COMPOSE_FILE=compose-scaling.yml ./init.sh)..."
"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
./init.sh                       # env.sh brings the stack up; init installs on the primary

PRIMARY=$("${COMPOSE[@]}" ps -q authz-primary)
REPLICA=$("${COMPOSE[@]}" ps -q authz-replica)

echo "==> Seeding the demo fixture on the primary..."
docker exec -i -e PGPASSWORD=authz "$PRIMARY" psql -U authz -d authz -q -v ON_ERROR_STOP=1 < examples/models/demo/model.sql >/dev/null
docker exec -i -e PGPASSWORD=authz "$PRIMARY" psql -U authz -d authz -q -v ON_ERROR_STOP=1 < examples/models/demo/seed.sql  >/dev/null

qp() { docker exec -e PGPASSWORD=authz "$1" psql -U authz -d authz -tA -c "$2"; }
fail=0
assert() {  # description  expected  actual
  if [ "$2" = "$3" ]; then echo "    PASS  $1"; else echo "    FAIL  $1 (expected '$2', got '$3')"; fail=1; fi
}

echo "==> Asserting streaming replication..."
assert "replica is a hot standby (in recovery)" "t" "$(qp "$REPLICA" "SELECT pg_is_in_recovery();")"
assert "primary has a streaming standby" "1" \
  "$(qp "$PRIMARY" "SELECT count(*) FROM pg_stat_replication WHERE state='streaming';")"

echo "==> Asserting the standby received the schema + data (poll for WAL replay)..."
demo_tuples() { qp "$1" "SELECT count(*) FROM authz.tuples WHERE store_id=(SELECT store_id FROM authz.stores WHERE name='demo');" 2>/dev/null || true; }
# Compare the replica to the PRIMARY rather than a hardcoded count, so this stays
# correct when the demo seed changes.
want=$(demo_tuples "$PRIMARY")
got=""
for _ in $(seq 1 20); do
  got=$(demo_tuples "$REPLICA")
  [ "$got" = "$want" ] && break
  sleep 1
done
assert "replica replicated all $want demo tuples (matches primary)" "$want" "$got"

echo "==> Asserting read checks resolve on the read-only replica..."
assert "replica: eva can_read accounting doc" "t" \
  "$(qp "$REPLICA" "SELECT authz.check_access('demo','internal_user','eva','can_read','document','doc_acc_001');")"
assert "replica: unknown subject denied" "f" \
  "$(qp "$REPLICA" "SELECT authz.check_access('demo','internal_user','ghost_xyz','can_read','document','doc_acc_001');")"

# PostgREST connects to the read-only replica, which cannot receive LISTEN/NOTIFY
# (the engine NOTIFYs the primary on schema changes, but LISTEN/NOTIFY is not
# replicated and a standby rejects LISTEN). So PostgREST holds whatever schema
# cache it loaded at startup — before the schema existed. In this topology a
# schema change therefore requires reloading the replica-facing PostgREST;
# restart it so it re-reads the now-present authz schema.
echo "==> Reloading PostgREST's schema cache (read-only replica can't LISTEN)..."
"${COMPOSE[@]}" restart postgrest >/dev/null 2>&1 || true

echo "==> Asserting the OPA -> PostgREST -> replica path..."
opa() {  # input-json
  curl -s -m 10 http://localhost:8181/v1/data/authz/allow \
    -H "Authorization: Bearer ${OPA_ADMIN_TOKEN:-change-me-in-production}" -d "$1"
}
eva_opa=""
for _ in $(seq 1 20); do   # allow PostgREST to come back + reload its cache
  eva_opa=$(opa '{"input":{"subject":{"type":"internal_user","id":"eva"},"action":"can_read","resource":{"type":"document","id":"doc_acc_001"}}}' || true)
  [ "$eva_opa" = '{"result":true}' ] && break
  sleep 2
done
assert "OPA: eva allowed" '{"result":true}' "$eva_opa"
assert "OPA: unknown subject denied" '{"result":false}' \
  "$(opa '{"input":{"subject":{"type":"internal_user","id":"ghost_xyz"},"action":"can_read","resource":{"type":"document","id":"doc_acc_001"}}}')"

echo ""
if [ "$fail" -ne 0 ]; then
  echo "==> SCALING TESTS FAILED"
  exit 1
fi
echo "==> All scaling tests passed."
echo "    (stack left running — tear down with: ${COMPOSE[*]} down -v)"
