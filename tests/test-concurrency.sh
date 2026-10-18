#!/usr/bin/env bash
#
# Two-session concurrency tests for the engine's locking guarantees (review #17,
# round 2): what a single psql session cannot show — that one transaction
# actually WAITS for another and decides on what it committed.
#
#   A. model_remove_type waits for an in-flight tuple write to commit, then
#      counts that tuple and refuses (without the SHARE lock on authz.tuples
#      the type — and the tuple — would be gone).
#   B. Two write_tuples_checked with the same PARTIAL precondition ("alice owns
#      no doc") on different objects: the second waits on the exclusive store
#      lock and then fails its precondition — exactly one owner tuple.
#   C. Two OBJECT-scoped checked writes on different objects do not wait for
#      each other (the shared store lock keeps them concurrent).
#
# Reports in the shared "==> N passed, M failed (of T ...)" format for
# test-all.sh. Needs python3 for millisecond timing (macOS date has no %N).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$PG_DIR/env.sh"

S=test_conc
pass=0; fail=0
ok()   { echo "    PASS  $1"; pass=$((pass + 1)); }
bad()  { echo "    FAIL  $1: $2"; fail=$((fail + 1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected=$3, got=$2"; fi; }
now_ms(){ python3 -c 'import time; print(int(time.time() * 1000))'; }
q()    { psql_exec "$PG_DB" -Atq -c "$1" 2>&1 | grep -v '^NOTICE'; }
# A session that runs the given SQL in ONE transaction in the background.
session(){ psql_exec "$PG_DB" -q -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<SQL &
BEGIN;
$1
SELECT pg_sleep(2);
COMMIT;
SQL
}

cleanup(){ q "SELECT authz.delete_store('$S', p_purge_audit => true)" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
q "SELECT authz.create_store('$S');
   SELECT authz.model_register_type('$S', t) FROM unnest(ARRAY['user','doc','legacy']) t;
   SELECT authz.model_register_relation('$S', r) FROM unnest(ARRAY['owner','viewer']) r;
   SELECT authz.model_add_rule('$S', 'doc', 'owner', 'direct');
   SELECT authz.model_add_rule('$S', 'doc', 'viewer', 'direct');
   SELECT authz.model_add_rule('$S', 'legacy', 'viewer', 'direct');" >/dev/null

echo "==> A. model_remove_type vs an in-flight tuple write"
session "SELECT authz.write_tuple('$S','user','bob','viewer','legacy','l1');"
sleep 0.7
t0=$(now_ms)
out=$(q "SELECT authz.model_remove_type('$S','legacy')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"referenced by 1 tuple"*) ok "conc_A_remove_refused_after_waiting" ;; *) bad "conc_A_remove_refused_after_waiting" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_A_remover_waited_for_the_writer (${dt} ms)" || bad "conc_A_remover_waited_for_the_writer" "${dt} ms — did not wait"
check "conc_A_type_still_registered" "$(q "SELECT count(*) FROM authz.types WHERE store_id = authz._s('$S') AND name = 'legacy'")" "1"
check "conc_A_tuple_survived" "$(q "SELECT count(*) FROM authz.tuples WHERE store_id = authz._s('$S') AND object_id = 'l1'")" "1"

echo "==> B. two partial-precondition checked writes (cross-object invariant)"
PC='[{"match":"absent","user_type":"user","user_id":"alice","relation":"owner","object_type":"doc"}]'
W1='[{"user_type":"user","user_id":"alice","relation":"owner","object_type":"doc","object_id":"d1"}]'
W2='[{"user_type":"user","user_id":"alice","relation":"owner","object_type":"doc","object_id":"d2"}]'
session "SELECT authz.write_tuples_checked('$S', '$PC', '[]', '$W1');"
sleep 0.7
t0=$(now_ms)
out=$(q "SELECT authz.write_tuples_checked('$S', '$PC', '[]', '$W2')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"precondition failed"*) ok "conc_B_second_writer_precondition_failed" ;; *) bad "conc_B_second_writer_precondition_failed" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_B_second_writer_waited (${dt} ms)" || bad "conc_B_second_writer_waited" "${dt} ms — did not wait"
check "conc_B_exactly_one_owner" "$(q "SELECT count(*) FROM authz.tuples t WHERE t.store_id = authz._s('$S') AND t.user_id = 'alice' AND t.relation = authz._r(authz._s('$S'), 'owner')")" "1"

echo "==> C. two object-scoped checked writes stay concurrent"
P1='[{"match":"absent","user_type":"user","user_id":"zed","relation":"viewer","object_type":"doc","object_id":"d1"}]'
P2='[{"match":"absent","user_type":"user","user_id":"zed","relation":"viewer","object_type":"doc","object_id":"d2"}]'
V1='[{"user_type":"user","user_id":"zed","relation":"viewer","object_type":"doc","object_id":"d1"}]'
V2='[{"user_type":"user","user_id":"zed","relation":"viewer","object_type":"doc","object_id":"d2"}]'
session "SELECT authz.write_tuples_checked('$S', '$P1', '[]', '$V1');"
sleep 0.7
t0=$(now_ms)
out=$(q "SELECT authz.write_tuples_checked('$S', '$P2', '[]', '$V2')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *'"written": 1'*) ok "conc_C_second_writer_succeeded" ;; *) bad "conc_C_second_writer_succeeded" "$out" ;; esac
[ "$dt" -lt 1000 ] && ok "conc_C_second_writer_did_not_wait (${dt} ms)" || bad "conc_C_second_writer_did_not_wait" "${dt} ms — waited for the other object"

echo "==> ${pass} passed, ${fail} failed (of $((pass + fail)) concurrency checks)"
[ "$fail" -eq 0 ]
