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

# pgauthzd uses pgx and holds no schema cache (unlike PostgREST), so there is
# nothing to reload on a schema change. But the replica-facing pgauthzd-reader
# may have started (and restarted) before the schema+roles existed on the
# primary/replica; bounce it to guarantee it is connected to the now-initialized
# replica before the OPA-path assertions.
echo "==> Ensuring pgauthzd-reader is connected to the initialized replica..."
"${COMPOSE[@]}" restart pgauthzd-reader >/dev/null 2>&1 || true

echo "==> Asserting the OPA -> pgauthzd -> replica path..."
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

# ── Layer B: strict revocation (new-enemy) ──────────────────────────────────
# A revoke acknowledged under synchronous_commit=remote_apply must be DENIED on
# the replica immediately after the ack — no stale-allow window.

# Connection that mimics the OPA-fronted writer (remote_apply, see compose.yml).
qsync() { docker exec -e PGPASSWORD=authz "$1" psql   "postgres://authz:authz@localhost:5432/authz?options=-csynchronous_commit%3Dremote_apply"   -tA -c "$2"; }

echo "==> Demonstrating the stale-allow window WITHOUT synchronous apply..."
# (must run BEFORE sync is enabled: with sync on + replay paused, the revoke
# would block — that blocking is the feature, but it would hang the test)
qp "$PRIMARY" "SELECT authz.write_tuple('demo','internal_user','newenemy','viewer','document','doc_newenemy');" >/dev/null
sleep 1  # let the grant replicate
assert "async: replica sees the grant" "t"   "$(qp "$REPLICA" "SELECT authz.check_access('demo','internal_user','newenemy','can_read','document','doc_newenemy');")"
qp "$REPLICA" "SELECT pg_wal_replay_pause();" >/dev/null
qp "$PRIMARY" "SELECT authz.delete_tuple('demo','internal_user','newenemy','viewer','document','doc_newenemy');" >/dev/null
assert "async + paused replay: replica still ALLOWS after the revoke (the bug Layer B closes)" "t"   "$(qp "$REPLICA" "SELECT authz.check_access('demo','internal_user','newenemy','can_read','document','doc_newenemy');")"
qp "$REPLICA" "SELECT pg_wal_replay_resume();" >/dev/null
for _ in $(seq 1 20); do
  [ "$(qp "$REPLICA" "SELECT authz.check_access('demo','internal_user','newenemy','can_read','document','doc_newenemy');")" = "f" ] && break
  sleep 1
done
assert "replica converges to deny after replay resumes" "f"   "$(qp "$REPLICA" "SELECT authz.check_access('demo','internal_user','newenemy','can_read','document','doc_newenemy');")"

echo "==> Enabling synchronous replication (remote_apply guarantee active)..."
# ALTER SYSTEM refuses to run inside a transaction block — psql -c sends a
# multi-statement string as ONE implicit transaction, so issue them separately.
qp "$PRIMARY" "ALTER SYSTEM SET synchronous_standby_names = '*';" >/dev/null
qp "$PRIMARY" "SELECT pg_reload_conf();" >/dev/null
for _ in $(seq 1 20); do
  [ "$(qp "$PRIMARY" "SELECT count(*) FROM pg_stat_replication WHERE sync_state='sync';")" = "1" ] && break
  sleep 1
done
assert "replica is in the synchronous set" "1"   "$(qp "$PRIMARY" "SELECT count(*) FROM pg_stat_replication WHERE sync_state='sync';")"

echo "==> New-enemy loop: revoke ack (remote_apply) → immediate replica check must DENY..."
ne_fail=0
for i in $(seq 1 10); do
  qsync "$PRIMARY" "SELECT authz.write_tuple('demo','internal_user','newenemy','viewer','document','doc_newenemy');" >/dev/null
  [ "$(qp "$REPLICA" "SELECT authz.check_access('demo','internal_user','newenemy','can_read','document','doc_newenemy');")" = "t" ] || ne_fail=$((ne_fail+1))
  qsync "$PRIMARY" "SELECT authz.delete_tuple('demo','internal_user','newenemy','viewer','document','doc_newenemy');" >/dev/null
  # NO sleep: the ack itself is the guarantee — the replica must already deny
  [ "$(qp "$REPLICA" "SELECT authz.check_access('demo','internal_user','newenemy','can_read','document','doc_newenemy');")" = "f" ] || ne_fail=$((ne_fail+1))
done
assert "10× grant/revoke cycles: replica state matched the ack every time (0 violations)" "0" "$ne_fail"

echo "==> Resetting synchronous replication config..."
qp "$PRIMARY" "ALTER SYSTEM RESET synchronous_standby_names;" >/dev/null
qp "$PRIMARY" "SELECT pg_reload_conf();" >/dev/null

echo ""
if [ "$fail" -ne 0 ]; then
  echo "==> SCALING TESTS FAILED"
  exit 1
fi
echo "==> All scaling tests passed."
echo "    (stack left running — tear down with: ${COMPOSE[*]} down -v)"
