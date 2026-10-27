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
#   D. A writer waits for a removal holding the lock — as its first statement,
#      before resolving names to ids (the orphan-after-removal window).
#   E. Two removals serialize instead of deadlocking (SHARE ROW EXCLUSIVE is
#      self-exclusive; a plain SHARE lock would let both in and deadlock on
#      their DELETEs).
#   F. A removal commits while a writer waits: the writer resolves the name
#      only after the lock, fails with "Unknown type", inserts no orphan.
#   G. The removal lock conflicts with itself (measured directly, no partition
#      detach involved), and a second removal of the SAME type waits and then
#      fails with "Unknown type" instead of acting on a stale id.
#   H. Two plain write_tuple calls race for the last slot of a capped relation
#      (max_direct, migration 0025): the second waits on the per-object lock
#      the cap guard takes, counts the first after its commit and is refused —
#      exactly max_direct holders. Another object stays concurrent.
#   I. The same race from a REPEATABLE READ transaction whose snapshot predates
#      the first writer's commit: the count could not see it, so the cap guard
#      refuses the write outright (SQLSTATE 25000) — still exactly max_direct.
#   J. Model edits that contradict each other serialize on the relation's model
#      lock: a cap being declared vs a user:* facet being added (both orders),
#      and a cap vs a wildcard tuple being written (both orders) — the second
#      waits and is then refused, never both committed.
#   K. apply_model (replacing a cap by a wildcard facet) vs a concurrent
#      model_set_relation_constraint on the same relation: apply takes the
#      relation-model locks up front, so the setter waits instead of
#      deadlocking on the constraint row, and is then refused.
#   L. Two revocations race for the last slot above a floor (min_direct 1,
#      two owners): the second waits on the object lock, counts the first's
#      delete and is refused — exactly min_direct holders remain.
#   M. The floor is raised while a revocation waits for the object lock: the
#      revocation re-reads the floor under the lock and is refused by the new
#      value (a cap lowered meanwhile is re-read the same way).
#   N. An issuer binding is moved to another store group while a group
#      admin's write (authorized against the old group) waits on the row
#      lock: the write is refused by the ownership precondition (ZA003),
#      never overwriting the transferred row; a stale delete likewise.
#   O. Two groups create the SAME new issuer at once: the second creator
#      (create only) waits on the unique key and is refused — the first
#      group's row is never overwritten (no row to lock, so the write
#      itself is the check).
#
# Synchronization: the holder session runs its statement and then pg_sleep(2)
# in one transaction; the second session is launched only once pg_stat_activity
# shows the holder inside that pg_sleep (so the lock is held) — not after a
# fixed delay. A "waited" assertion then means the waiter returned only after
# the holder's commit (>= 1 s later, with the 2 s sleep); a "did not wait"
# assertion checks that the holder session was still alive when the second
# call returned. Reports in the shared "==> N passed, M failed (of T ...)"
# format for test-all.sh. Needs python3 for millisecond timing (macOS date
# has no %N).
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
# A session that runs the given SQL in ONE transaction in the background,
# then holds it open for 2 s. await_holder blocks until that hold has begun.
HOLDER_PID=
session(){ psql_exec "$PG_DB" -q -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<SQL &
BEGIN;
$1
SELECT pg_sleep(2.0) /* conc-holder */;
COMMIT;
SQL
HOLDER_PID=$!
await_holder
}
await_holder(){
    local i
    for i in $(seq 1 100); do
        if [ "$(q "SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND query LIKE '%conc-holder%' AND pid <> pg_backend_pid()")" -ge 1 ]; then
            return 0
        fi
        sleep 0.05
    done
    echo "    FAIL  holder session never reached its hold" ; fail=$((fail + 1)); return 1
}
holder_alive(){ kill -0 "$HOLDER_PID" 2>/dev/null; }

cleanup(){ q "SELECT authz.delete_store('$S', p_purge_audit => true)" >/dev/null 2>&1 || true
           q "DELETE FROM authz.issuer_bindings WHERE issuer LIKE 'https://test-conc/%'; SELECT authz.delete_store_group('conc_ga'); SELECT authz.delete_store_group('conc_gb');" >/dev/null 2>&1 || true; }
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
t0=$(now_ms)
out=$(q "SELECT authz.write_tuples_checked('$S', '$P2', '[]', '$V2')")
dt=$(( $(now_ms) - t0 ))
if holder_alive; then alive=yes; else alive=no; fi
wait
case "$out" in *'"written": 1'*) ok "conc_C_second_writer_succeeded" ;; *) bad "conc_C_second_writer_succeeded" "$out" ;; esac
[ "$alive" = yes ] && ok "conc_C_second_writer_did_not_wait (holder still open, ${dt} ms)" || bad "conc_C_second_writer_did_not_wait" "the holder had already committed (${dt} ms)"

echo "==> D. a writer waits for a removal that holds the lock (before it resolves any id)"
session "SELECT authz._lock_tuples_for_removal();"
t0=$(now_ms)
out=$(q "SELECT authz.write_tuple('$S','user','bob','viewer','legacy','l2')")
dt=$(( $(now_ms) - t0 ))
wait
check "conc_D_write_succeeded_after_the_removal_released" "$out" "t"
[ "$dt" -ge 1000 ] && ok "conc_D_writer_waited_for_the_remover (${dt} ms)" || bad "conc_D_writer_waited_for_the_remover" "${dt} ms — did not wait"

echo "==> E. two concurrent removals serialize (no lock-upgrade deadlock)"
q "SELECT authz.model_register_type('$S', t) FROM unnest(ARRAY['gone_a','gone_b']) t;" >/dev/null
session "SELECT authz.model_remove_type('$S','gone_a');"
t0=$(now_ms)
out=$(q "SELECT authz.model_remove_type('$S','gone_b')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *'"type": "gone_b"'*) ok "conc_E_second_removal_succeeded" ;; *) bad "conc_E_second_removal_succeeded" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_E_second_removal_waited (${dt} ms)" || bad "conc_E_second_removal_waited" "${dt} ms — did not wait"
check "conc_E_both_types_gone" "$(q "SELECT count(*) FROM authz.types WHERE store_id = authz._s('$S') AND name IN ('gone_a','gone_b')")" "0"

echo "==> F. a removal commits while a writer waits — the writer fails, no orphan"
q "SELECT authz.model_register_type('$S', 'doomed'); SELECT authz.model_register_relation('$S', 'reads'); SELECT authz.model_add_rule('$S', 'doomed', 'reads', 'direct');" >/dev/null
session "SELECT authz.model_remove_type('$S','doomed');"
t0=$(now_ms)
out=$(q "SELECT authz.write_tuple('$S','user','bob','reads','doomed','x1')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"Unknown type"*) ok "conc_F_writer_failed_on_the_removed_type" ;; *) bad "conc_F_writer_failed_on_the_removed_type" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_F_writer_waited_for_the_removal (${dt} ms)" || bad "conc_F_writer_waited_for_the_removal" "${dt} ms — did not wait"
check "conc_F_no_orphan_tuple" "$(q "SELECT count(*) FROM authz.tuples t WHERE t.store_id = authz._s('$S') AND (NOT EXISTS (SELECT 1 FROM authz.types ty WHERE ty.id = t.object_type) OR NOT EXISTS (SELECT 1 FROM authz.types ty WHERE ty.id = t.user_type))")" "0"

echo "==> G. the removal lock is self-exclusive; two removals of the SAME type"
session "SELECT authz._lock_tuples_for_removal();"
t0=$(now_ms)
q "SELECT authz._lock_tuples_for_removal()" >/dev/null
dt=$(( $(now_ms) - t0 ))
wait
[ "$dt" -ge 1000 ] && ok "conc_G_second_removal_lock_waited (${dt} ms)" || bad "conc_G_second_removal_lock_waited" "${dt} ms — SHARE ROW EXCLUSIVE did not conflict with itself"
q "SELECT authz.model_register_type('$S', 'same');" >/dev/null
session "SELECT authz.model_remove_type('$S','same');"
t0=$(now_ms)
out=$(q "SELECT authz.model_remove_type('$S','same')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"Unknown type"*) ok "conc_G_same_type_second_removal_fails_cleanly" ;; *) bad "conc_G_same_type_second_removal_fails_cleanly" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_G_same_type_second_removal_waited (${dt} ms)" || bad "conc_G_same_type_second_removal_waited" "${dt} ms — did not wait"
check "conc_G_type_gone_once" "$(q "SELECT count(*) FROM authz.types WHERE store_id = authz._s('$S') AND name = 'same'")" "0"
check "conc_G_no_leftover_partition" "$(q "SELECT count(*) FROM pg_class WHERE relname = 'tuples_test_conc_same'")" "0"

echo "==> H. two writers race for the last slot of a capped relation"
q "SELECT authz.model_register_type('$S', 'room');
   SELECT authz.model_add_rule('$S', 'room', 'viewer', 'direct');
   SELECT authz.model_set_relation_constraint('$S', 'room', 'viewer', p_max_direct => 1);" >/dev/null
session "SELECT authz.write_tuple('$S','user','ann','viewer','room','r1');"
t0=$(now_ms)
out=$(q "SELECT authz.write_tuple('$S','user','ben','viewer','room','r1')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"relation viewer on room:r1 is full: 1 of 1 active"*) ok "conc_H_second_writer_refused_after_waiting" ;; *) bad "conc_H_second_writer_refused_after_waiting" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_H_second_writer_waited_for_the_first (${dt} ms)" || bad "conc_H_second_writer_waited_for_the_first" "${dt} ms — did not wait"
check "conc_H_exactly_max_direct_holders" "$(q "SELECT count(*) FROM authz.tuples t WHERE t.store_id = authz._s('$S') AND t.object_id = 'r1'")" "1"
session "SELECT authz.write_tuple('$S','user','ann','viewer','room','r2');"
t0=$(now_ms)
out=$(q "SELECT authz.write_tuple('$S','user','ben','viewer','room','r3')")
dt=$(( $(now_ms) - t0 ))
if holder_alive; then alive=yes; else alive=no; fi
wait
check "conc_H_other_object_written" "$out" "t"
[ "$alive" = yes ] && ok "conc_H_other_object_did_not_wait (holder still open, ${dt} ms)" || bad "conc_H_other_object_did_not_wait" "the holder had already committed (${dt} ms)"

echo "==> I. a REPEATABLE READ writer with an older snapshot cannot slip past the cap"
session "SELECT authz.write_tuple('$S','user','ann','viewer','room','r4');"
# the RR transaction takes its snapshot (the SELECT) while the holder's write is uncommitted
out=$(psql_exec "$PG_DB" -Atq -v ON_ERROR_STOP=0 <<SQL 2>&1 | grep -v '^NOTICE' | tr '\n' ' '
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM authz.tuples WHERE store_id = authz._s('$S') AND object_id = 'r4';
SELECT pg_sleep(2.5);
SELECT authz.write_tuple('$S','user','ben','viewer','room','r4');
COMMIT;
SQL
)
wait
case "$out" in *"requires READ COMMITTED isolation"*) ok "conc_I_repeatable_read_writer_refused" ;; *) bad "conc_I_repeatable_read_writer_refused" "$out" ;; esac
check "conc_I_exactly_max_direct_holders" "$(q "SELECT count(*) FROM authz.tuples t WHERE t.store_id = authz._s('$S') AND t.object_id = 'r4'")" "1"

echo "==> J. a cap and a wildcard declaration race: the second waits, then is refused"
q "SELECT authz.model_register_type('$S', 'shelf');
   SELECT authz.model_add_rule('$S', 'shelf', 'viewer', 'direct');
   SELECT authz.model_add_rule('$S', 'shelf', 'owner', 'direct');" >/dev/null
# J1: the cap holds the lock; the facet waits and is refused
session "SELECT authz.model_set_relation_constraint('$S', 'shelf', 'viewer', 2);"
t0=$(now_ms)
out=$(q "SELECT authz.model_add_type_restriction('$S', 'shelf', 'viewer', 'user', p_allow_wildcard => true)")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"is capped (max_direct)"*) ok "conc_J1_facet_refused_after_waiting" ;; *) bad "conc_J1_facet_refused_after_waiting" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_J1_facet_waited_for_the_cap (${dt} ms)" || bad "conc_J1_facet_waited_for_the_cap" "${dt} ms — did not wait"
check "conc_J1_cap_and_no_facet" "$(q "SELECT (SELECT count(*) FROM authz.list_relation_constraints('$S') WHERE object_type = 'shelf') || '/' || (SELECT count(*) FROM authz.type_restrictions tr WHERE tr.store_id = authz._s('$S') AND tr.allow_wildcard)")" "1/0"
# J2: the facet holds the lock; the cap waits and is refused
q "SELECT authz.model_drop_relation_constraint('$S', 'shelf', 'viewer')" >/dev/null
session "SELECT authz.model_add_type_restriction('$S', 'shelf', 'viewer', 'user', p_allow_wildcard => true);"
t0=$(now_ms)
out=$(q "SELECT authz.model_set_relation_constraint('$S', 'shelf', 'viewer', 2)")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"allows wildcard grants"*) ok "conc_J2_cap_refused_after_waiting" ;; *) bad "conc_J2_cap_refused_after_waiting" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_J2_cap_waited_for_the_facet (${dt} ms)" || bad "conc_J2_cap_waited_for_the_facet" "${dt} ms — did not wait"
check "conc_J2_facet_and_no_cap" "$(q "SELECT (SELECT count(*) FROM authz.list_relation_constraints('$S') WHERE object_type = 'shelf') || '/' || (SELECT count(*) FROM authz.type_restrictions tr WHERE tr.store_id = authz._s('$S') AND tr.allow_wildcard)")" "0/1"
# J3: a wildcard tuple is being written (uncapped, no restrictions on owner); the cap waits and is refused
session "SELECT authz.write_tuple('$S','user','*','owner','shelf','s1');"
t0=$(now_ms)
out=$(q "SELECT authz.model_set_relation_constraint('$S', 'shelf', 'owner', 1)")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"1 active wildcard tuple(s) exist"*) ok "conc_J3_cap_refused_by_in_flight_wildcard" ;; *) bad "conc_J3_cap_refused_by_in_flight_wildcard" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_J3_cap_waited_for_the_wildcard_write (${dt} ms)" || bad "conc_J3_cap_waited_for_the_wildcard_write" "${dt} ms — did not wait"
# J4: the cap is being declared; the wildcard tuple waits and is refused
q "SELECT authz.delete_tuple('$S','user','*','owner','shelf','s1')" >/dev/null
session "SELECT authz.model_set_relation_constraint('$S', 'shelf', 'owner', 1);"
t0=$(now_ms)
out=$(q "SELECT authz.write_tuple('$S','user','*','owner','shelf','s1')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"a wildcard tuple is unbounded"*) ok "conc_J4_wildcard_refused_by_in_flight_cap" ;; *) bad "conc_J4_wildcard_refused_by_in_flight_cap" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_J4_wildcard_waited_for_the_cap (${dt} ms)" || bad "conc_J4_wildcard_waited_for_the_cap" "${dt} ms — did not wait"
check "conc_J4_no_wildcard_tuple" "$(q "SELECT count(*) FROM authz.tuples t WHERE t.store_id = authz._s('$S') AND t.object_id = 's1'")" "0"

echo "==> K. apply_model vs a concurrent cap update: no deadlock, the setter waits"
K=${S}_k; KSRC=${S}_ksrc
cleanup_k(){ q "SELECT authz.delete_store('$K', p_purge_audit => true); SELECT authz.delete_store('$KSRC', p_purge_audit => true); DELETE FROM authz.model_registry WHERE name = 'conc_k_model';" >/dev/null 2>&1 || true; }
cleanup_k
for st in "$K" "$KSRC"; do
  q "SELECT authz.create_store('$st');
     SELECT authz.model_register_type('$st', t) FROM unnest(ARRAY['user','shelf']) t;
     SELECT authz.model_register_relation('$st', 'viewer');
     SELECT authz.model_add_rule('$st', 'shelf', 'viewer', 'direct');" >/dev/null
done
q "SELECT authz.model_set_relation_constraint('$K', 'shelf', 'viewer', 2);
   SELECT authz.model_add_type_restriction('$KSRC', 'shelf', 'viewer', 'user', p_allow_wildcard => true);
   SELECT authz.publish_model('conc_k_model', '$KSRC');" >/dev/null
session "SELECT authz.apply_model('$K', 'conc_k_model');"
t0=$(now_ms)
out=$(q "SELECT authz.model_set_relation_constraint('$K', 'shelf', 'viewer', 3)")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *deadlock*) bad "conc_K_no_deadlock" "$out" ;; *) ok "conc_K_no_deadlock" ;; esac
case "$out" in *"allows wildcard grants"*) ok "conc_K_setter_refused_after_apply" ;; *) bad "conc_K_setter_refused_after_apply" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_K_setter_waited_for_apply (${dt} ms)" || bad "conc_K_setter_waited_for_apply" "${dt} ms — did not wait"
check "conc_K_facet_and_no_cap" "$(q "SELECT (SELECT count(*) FROM authz.list_relation_constraints('$K')) || '/' || (SELECT count(*) FROM authz.type_restrictions tr WHERE tr.store_id = authz._s('$K') AND tr.allow_wildcard)")" "0/1"
cleanup_k

echo "==> L. two revocations race for the last slot above a floor"
q "SELECT authz.model_register_type('$S', 'vault');
   SELECT authz.model_add_rule('$S', 'vault', 'owner', 'direct');
   SELECT authz.model_set_relation_constraint('$S', 'vault', 'owner', p_min_direct => 1);
   SELECT authz.write_tuple('$S','user','ann','owner','vault','v1');
   SELECT authz.write_tuple('$S','user','ben','owner','vault','v1');" >/dev/null
session "SELECT authz.delete_tuple('$S','user','ann','owner','vault','v1');"
t0=$(now_ms)
out=$(q "SELECT authz.delete_tuple('$S','user','ben','owner','vault','v1')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"would drop below its minimum: 1 of 1"*) ok "conc_L_second_revocation_refused_after_waiting" ;; *) bad "conc_L_second_revocation_refused_after_waiting" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_L_second_revocation_waited (${dt} ms)" || bad "conc_L_second_revocation_waited" "${dt} ms — did not wait"
check "conc_L_exactly_min_direct_holders" "$(q "SELECT count(*) FROM authz.tuples t WHERE t.store_id = authz._s('$S') AND t.object_id = 'v1'")" "1"

echo "==> M. a floor raised while a revocation waits is the floor that counts"
q "SELECT authz.write_tuple('$S','user',u,'owner','vault','v2') FROM unnest(ARRAY['ann','ben','cid']) u;" >/dev/null
session "SELECT authz.delete_tuple('$S','user','ann','owner','vault','v2');"
q "SELECT authz.model_set_relation_constraint('$S', 'vault', 'owner', p_min_direct => 2);" >/dev/null
t0=$(now_ms)
out=$(q "SELECT authz.delete_tuple('$S','user','ben','owner','vault','v2')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"would drop below its minimum: 2 of 2"*) ok "conc_M_raised_floor_counts" ;; *) bad "conc_M_raised_floor_counts" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_M_revocation_waited (${dt} ms)" || bad "conc_M_revocation_waited" "${dt} ms — did not wait"
check "conc_M_two_owners_remain" "$(q "SELECT count(*) FROM authz.tuples t WHERE t.store_id = authz._s('$S') AND t.object_id = 'v2'")" "2"

echo "==> N. an issuer binding transferred while a group admin's write waits (ownership precondition)"
# Review P1 (2026-10-27): the write names the group it authorized against;
# the engine re-reads the row under FOR UPDATE. The platform's transfer
# (A → B) holds the row lock; group A's admin, having read the row as A's,
# waits — and is refused once the transfer committed (SQLSTATE ZA003),
# instead of overwriting B's row. A matching delete is refused the same way.
ISS="https://test-conc/idp-$(now_ms)"
q "SELECT authz.create_store_group('conc_ga'); SELECT authz.create_store_group('conc_gb');
   SELECT authz.set_issuer_binding('$ISS', p_store_group => 'conc_ga', p_jwks_url => 'https://test-conc/jwks', p_audience => 'a', p_expect_group => '');" >/dev/null
session "SELECT authz.set_issuer_binding('$ISS', p_store_group => 'conc_gb', p_jwks_url => 'https://test-conc/jwks', p_audience => 'a', p_expect_group => 'conc_ga');"
t0=$(now_ms)
out=$(q "SELECT authz.set_issuer_binding('$ISS', p_store_group => 'conc_ga', p_jwks_url => 'https://test-conc/jwks', p_audience => 'a', p_description => 'group a edit', p_expect_group => 'conc_ga')")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"owned by group conc_gb now (expected group conc_ga)"*) ok "conc_N_stale_owner_refused_after_waiting" ;; *) bad "conc_N_stale_owner_refused_after_waiting" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_N_group_admin_write_waited (${dt} ms)" || bad "conc_N_group_admin_write_waited" "${dt} ms — did not wait"
check "conc_N_row_is_b_untouched" "$(q "SELECT store_group || '|' || coalesce(description, '-') FROM authz.list_issuer_bindings() WHERE issuer = '$ISS'")" "conc_gb|-"
out=$(q "SELECT authz.delete_issuer_binding('$ISS', NULL, 'conc_ga')")
case "$out" in *"owned by group conc_gb now"*) ok "conc_N_stale_delete_refused" ;; *) bad "conc_N_stale_delete_refused" "$out" ;; esac
check "conc_N_owner_delete_ok" "$(q "SELECT authz.delete_issuer_binding('$ISS', NULL, 'conc_gb')")" "t"
q "SELECT authz.delete_store_group('conc_ga'); SELECT authz.delete_store_group('conc_gb');" >/dev/null

echo "==> O. two groups create the same new issuer at once (create-only precondition)"
# Both admins found no row and authorized against their own group. The first
# INSERT holds the unique key; the second (create only: ON CONFLICT DO
# NOTHING) waits for it, then updates nothing and is refused (ZA003) — the
# first group's row is never overwritten.
ISS="https://test-conc/new-$(now_ms)"
q "SELECT authz.create_store_group('conc_ga'); SELECT authz.create_store_group('conc_gb');" >/dev/null
session "SELECT authz.set_issuer_binding('$ISS', p_store_group => 'conc_ga', p_jwks_url => 'https://test-conc/jwks', p_audience => 'a', p_expect_exists => false);"
t0=$(now_ms)
out=$(q "SELECT authz.set_issuer_binding('$ISS', p_store_group => 'conc_gb', p_jwks_url => 'https://test-conc/jwks', p_audience => 'a', p_expect_exists => false)")
dt=$(( $(now_ms) - t0 ))
wait
case "$out" in *"already exists, owned by group conc_ga"*) ok "conc_O_second_creator_refused_after_waiting" ;; *) bad "conc_O_second_creator_refused_after_waiting" "$out" ;; esac
[ "$dt" -ge 1000 ] && ok "conc_O_second_creator_waited (${dt} ms)" || bad "conc_O_second_creator_waited" "${dt} ms — did not wait"
check "conc_O_first_creator_row_kept" "$(q "SELECT store_group FROM authz.list_issuer_bindings() WHERE issuer = '$ISS'")" "conc_ga"
q "SELECT authz.delete_issuer_binding('$ISS'); SELECT authz.delete_store_group('conc_ga'); SELECT authz.delete_store_group('conc_gb');" >/dev/null

echo "==> ${pass} passed, ${fail} failed (of $((pass + fail)) concurrency checks)"
[ "$fail" -eq 0 ]
