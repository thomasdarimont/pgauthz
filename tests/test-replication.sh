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
#     materialized_permissions table and its side tables, and its
#     check_permission() agrees with the primary's live check_access for every
#     (subject, relation, object) of two stores — known subjects and objects
#     plus unknown probes, so the wildcard contract ('*' rows apply only to
#     entities the engine does not know) is proven, not assumed; a write on
#     the primary reaches the derived replica through the changefeed-driven
#     worker; a subject or object that becomes known (or unknown) under a
#     wildcard keeps agreeing with the primary; a forced type removal rebuilds
#     the store; a write inside a transaction held open for seconds is never
#     skipped by the cursor; and after each of three batches of random
#     mutations (tests/sql/derived_permissions_mutate.sql: grants, revokes,
#     usersets, wildcards, short expiries) the differential still holds.
#
# The aia-acme fixture is loaded onto the primary in addition to the demo
# because it has subject wildcards (employee:*), exclusion and intersection;
# the demo contributes object wildcards (document:*).
#
# The assertions are independent of init-replication.sh's own output because
# that script does not use ON_ERROR_STOP — a SQL error leaves a broken setup but
# still exits 0, so only these checks catch a regression.
#
# REPLICATION_COMPOSE_FILES (colon-separated) adds compose override files, e.g.
# to move the host ports so the test can run next to the main stack; set
# COMPOSE_PROJECT_NAME too so the networks stay apart. Both are passed on to
# init-replication.sh.
#
# Leaves the stack running for inspection; the caller tears it down
# (the CI job and a final hint below).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
COMPOSE=(docker compose)
IFS=: read -ra _compose_files <<< "${REPLICATION_COMPOSE_FILES:-compose-replication.yml}"
for _f in "${_compose_files[@]}"; do COMPOSE+=(-f "$_f"); done
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Resetting + bringing up the replication stack..."
"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --wait

echo "==> Running init-replication.sh..."
./db/replication/init-replication.sh

PRIMARY=$("${COMPOSE[@]}" ps -q authz-primary)
ACCT=$("${COMPOSE[@]}" ps -q accounting-app-db)
DERIVED=$("${COMPOSE[@]}" ps -q accounting-app-derived-db)
qp() { docker exec -e PGPASSWORD=authz "$1" psql -U authz -d authz -tA -c "$2"; }
# Run a SQL script from stdin (ON_ERROR_STOP, quiet).
qf() { docker exec -i -e PGPASSWORD=authz "$1" psql -U authz -d authz -v ON_ERROR_STOP=1 -q -tA; }

fail=0
assert() {  # description  expected  actual
  if [ "$2" = "$3" ]; then echo "    PASS  $1"; else echo "    FAIL  $1 (expected '$2', got '$3')"; fail=1; fi
}

# Poll until every subscribed table on $1 is 'r' (ready), or time out.
wait_ready() {  # container
  for _ in $(seq 1 30); do
    [ "$(qp "$1" "SELECT count(*) FROM pg_subscription_rel WHERE srsubstate <> 'r';")" = "0" ] && return 0
    sleep 2
  done
  return 1
}

# Poll until the derived replica holds exactly the primary's derived rows.
derived_counts() {  # container
  qp "$1" "SELECT (SELECT count(*) FROM authz.materialized_permissions) || '/' ||
                  (SELECT count(*) FROM authz.materialized_subjects)    || '/' ||
                  (SELECT count(*) FROM authz.materialized_objects);"
}
wait_derived_parity() {
  local want
  want=$(derived_counts "$PRIMARY")
  for _ in $(seq 1 30); do
    [ "$(derived_counts "$DERIVED")" = "$want" ] && { echo "$want"; return 0; }
    sleep 1
  done
  echo "timeout (primary $want, derived $(derived_counts "$DERIVED"))"; return 1
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

echo "==> Loading the aia-acme fixture (subject wildcards, exclusion) onto the primary and deriving it..."
qf "$PRIMARY" < examples/models/aia-acme/model.sql >/dev/null
qf "$PRIMARY" < examples/models/aia-acme/seed.sql  >/dev/null
qp "$PRIMARY" "SELECT authz.refresh_all_materialized_permissions('aia_acme');" >/dev/null

echo "==> Asserting the DERIVED replica mirrors the primary's derived tables..."
parity=$(wait_derived_parity) || true
case "$parity" in timeout*) assert "derived: permissions/subjects/objects match the primary" "parity" "$parity";;
                  *)        assert "derived: permissions/subjects/objects match the primary ($parity)" "ok" "ok";; esac
assert "derived: materialized_permissions populated" "t" \
  "$(qp "$DERIVED" "SELECT count(*) > 0 FROM authz.materialized_permissions;")"
assert "derived: literal '*' rows present for both wildcard kinds" "t" \
  "$(qp "$DERIVED" "SELECT EXISTS(SELECT 1 FROM authz.materialized_permissions WHERE user_id='*') AND EXISTS(SELECT 1 FROM authz.materialized_permissions WHERE object_id='*');")"

# The universe and the live answers come from the primary; the derived replica
# evaluates the same universe with check_permission(); any disagreement fails.
# Known subjects and objects of both stores, plus unknown probes and the ids the
# random mutations use (rnd_<type>_0..3), for every relation of the type.
differential() {  # label
  qp "$PRIMARY" "COPY (
    WITH stores AS (SELECT id, name FROM authz.stores WHERE name IN ('demo','aia_acme')),
    subj AS (
      SELECT DISTINCT s.name AS store, ut.name AS user_type, t.user_id
        FROM authz.tuples t JOIN stores s ON s.id=t.store_id JOIN authz.types ut ON ut.id=t.user_type
       WHERE t.user_relation IS NULL AND t.user_id <> '*'
      UNION
      SELECT DISTINCT s.name, ut.name, 'zz_unknown_' || ut.name
        FROM authz.tuples t JOIN stores s ON s.id=t.store_id JOIN authz.types ut ON ut.id=t.user_type
       WHERE t.user_relation IS NULL
      UNION
      SELECT DISTINCT s.name, ut.name, 'rnd_' || ut.name || '_' || g
        FROM authz.tuples t JOIN stores s ON s.id=t.store_id JOIN authz.types ut ON ut.id=t.user_type, generate_series(0,3) g
       WHERE t.user_relation IS NULL),
    obj AS (
      SELECT DISTINCT s.name AS store, ot.name AS object_type, t.object_id
        FROM authz.tuples t JOIN stores s ON s.id=t.store_id JOIN authz.types ot ON ot.id=t.object_type
       WHERE t.object_id <> '*'
      UNION
      SELECT DISTINCT s.name, ot.name, 'zz_unknown_object'
        FROM authz.tuples t JOIN stores s ON s.id=t.store_id JOIN authz.types ot ON ot.id=t.object_type
      UNION
      SELECT DISTINCT s.name, ot.name, 'rnd_' || ot.name || '_' || g
        FROM authz.tuples t JOIN stores s ON s.id=t.store_id JOIN authz.types ot ON ot.id=t.object_type, generate_series(0,3) g),
    rel AS (
      SELECT DISTINCT s.name AS store, ot.name AS object_type, r.name AS relation
        FROM authz.models m JOIN stores s ON s.id=m.store_id JOIN authz.types ot ON ot.id=m.object_type JOIN authz.relations r ON r.id=m.relation)
    SELECT u.store, u.user_type, u.user_id, r.relation, o.object_type, o.object_id,
           authz.check_access(u.store, u.user_type, u.user_id, r.relation, o.object_type, o.object_id) AS live
      FROM subj u JOIN obj o ON o.store = u.store JOIN rel r ON r.store = o.store AND r.object_type = o.object_type
  ) TO STDOUT;" > "$WORK/universe.tsv"
  local checks live_allows mismatches
  checks=$(wc -l < "$WORK/universe.tsv" | tr -d ' ')
  live_allows=$(awk -F'\t' '$7=="t"' "$WORK/universe.tsv" | wc -l | tr -d ' ')
  {
    echo "CREATE TEMP TABLE u (store text, user_type text, user_id text, relation text, object_type text, object_id text, live boolean);"
    echo "COPY u FROM STDIN;"
    cat "$WORK/universe.tsv"
    echo '\.'
    echo "SELECT count(*) FILTER (WHERE live <> authz.check_permission(store, user_type, user_id, relation, object_type, object_id)) FROM u;"
    echo "SELECT store || ' ' || user_type || ':' || user_id || ' ' || relation || ' ' || object_type || ':' || object_id || ' live=' || live
            FROM u WHERE live <> authz.check_permission(store, user_type, user_id, relation, object_type, object_id) ORDER BY 1 LIMIT 10;"
  } | qf "$DERIVED" > "$WORK/diff.out"
  mismatches=$(sed -n 1p "$WORK/diff.out")
  echo "    [$1] checks=$checks live_allows=$live_allows mismatches=$mismatches"
  assert "differential ($1): universe is non-trivial (> 5000 checks)" "t" "$([ "${checks:-0}" -gt 5000 ] && echo t || echo f)"
  assert "differential ($1): derived check_permission == live check_access everywhere" "0" "$mismatches"
  if [ "$mismatches" != "0" ]; then sed -n '2,$p' "$WORK/diff.out" | sed 's/^/        /'; fi
}

# Run the worker until every registered store's feed is drained. The feed is
# lag-gated (1 s), so the first pull waits that long.
drain_feed() {
  local i
  for i in $(seq 1 20); do
    sleep 1.1
    qp "$PRIMARY" "SELECT authz.refresh_materialized_permissions();" >/dev/null
    [ "$(qp "$PRIMARY" "SELECT bool_and(feed_drained) FROM authz.materialized_refresh_state;")" = "t" ] && return 0
  done
  return 1
}

# Absorb the snapshot's replay window first (writes from the stability lag
# before the cursor are replayed on purpose, never missed).
drain_feed || assert "feed drained after the snapshot" "ok" "timeout"
echo "==> Differential after the initial snapshot..."
differential "snapshot"

echo "==> Wildcard contract regressions (the cases that were wrong before the side tables)..."
assert "unknown employee may 'delegatable' board-deck (employee:* grant, subject not expanded)" "t" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('aia_acme','employee','zz_nobody','delegatable','document','board-deck');")"
assert "nadia_auditor can_read a document the engine never saw (document:* grant)" "t" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('demo','internal_user','nadia_auditor','can_read','document','doc_never_touched');")"
assert "an unknown user cannot read that unknown document" "f" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('demo','internal_user','zz_nobody','can_read','document','doc_never_touched');")"
assert "alice cannot read doc_acc_001 (no path into the accounting engagement)" "f" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('demo','internal_user','alice','can_read','document','doc_acc_001');")"

echo "==> Known-state transitions under wildcards (the subscriber must keep agreeing with the primary)..."
# An unknown employee inherits employee:* on board-deck. An unrelated grant
# makes her known — the '*' rows stop applying, so concrete rows must appear.
assert "unknown zz_newbie inherits employee:* delegatable on board-deck" "t" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('aia_acme','employee','zz_newbie','delegatable','document','board-deck');")"
qp "$PRIMARY" "SELECT authz.write_tuple('aia_acme','employee','zz_newbie','editor','document','q3-plan');" >/dev/null
drain_feed || assert "transition 1: feed drained" "ok" "timeout"
parity=$(wait_derived_parity) || true
assert "transition 1: zz_newbie is now a known subject on the replica" "t" \
  "$(qp "$DERIVED" "SELECT EXISTS(SELECT 1 FROM authz.materialized_subjects WHERE store='aia_acme' AND user_id='zz_newbie');")"
assert "transition 1: known zz_newbie still may 'delegatable' board-deck (concrete row materialized)" "t" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('aia_acme','employee','zz_newbie','delegatable','document','board-deck');")"
# An unknown document inherits nadia's document:* grant. A grant to someone
# else makes it known — nadia needs a concrete row on it.
assert "unknown doc_fresh_obj: nadia_auditor reads it via document:*" "t" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('demo','internal_user','nadia_auditor','can_read','document','doc_fresh_obj');")"
qp "$PRIMARY" "SELECT authz.write_tuple('demo','internal_user','bob','viewer','document','doc_fresh_obj');" >/dev/null
drain_feed || assert "transition 2: feed drained" "ok" "timeout"
parity=$(wait_derived_parity) || true
assert "transition 2: doc_fresh_obj is now a known object on the replica" "t" \
  "$(qp "$DERIVED" "SELECT EXISTS(SELECT 1 FROM authz.materialized_objects WHERE store='demo' AND object_id='doc_fresh_obj');")"
assert "transition 2: nadia_auditor still reads the now-known document (concrete row)" "t" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('demo','internal_user','nadia_auditor','can_read','document','doc_fresh_obj');")"
assert "transition 2: bob reads it too" "t" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('demo','internal_user','bob','can_read','document','doc_fresh_obj');")"
# Known → unknown again: rows go, the '*' row applies once more.
qp "$PRIMARY" "SELECT authz.delete_tuple('aia_acme','employee','zz_newbie','editor','document','q3-plan');" >/dev/null
drain_feed || assert "transition 3: feed drained" "ok" "timeout"
parity=$(wait_derived_parity) || true
assert "transition 3: zz_newbie is unknown again and still inherits employee:*" "t" \
  "$(qp "$DERIVED" "SELECT NOT EXISTS(SELECT 1 FROM authz.materialized_subjects WHERE store='aia_acme' AND user_id='zz_newbie') AND authz.check_permission('aia_acme','employee','zz_newbie','delegatable','document','board-deck');")"

echo "==> A removed type rebuilds the store (TYPE_REMOVED in the feed)..."
assert "demo has derived rows for upload_request before the removal" "t" \
  "$(qp "$DERIVED" "SELECT count(*) > 0 FROM authz.materialized_permissions WHERE store='demo' AND object_type='upload_request';")"
qp "$PRIMARY" "SELECT authz.model_remove_type('demo','upload_request', p_force => true);" >/dev/null
drain_feed || assert "type removal: feed drained" "ok" "timeout"
parity=$(wait_derived_parity) || true
assert "no derived rows for the removed type remain on the replica" "0" \
  "$(qp "$DERIVED" "SELECT count(*) FROM authz.materialized_permissions WHERE store='demo' AND object_type='upload_request';")"
differential "after type removal"

echo "==> A long-open transaction must never be skipped by the cursor..."
# Session A opens a transaction, writes, and holds it open for 5 s; session B
# writes and commits meanwhile. A's row has the earlier performed_at. The
# worker must widen its gate to A's age and consume neither until A commits.
cat > "$WORK/slow.sql" <<'SQL'
BEGIN;
SELECT authz.write_tuple('demo','internal_user','ci_slow','viewer','document','doc_acc_001');
SELECT pg_sleep(5);
COMMIT;
SQL
docker exec -i -e PGPASSWORD=authz "$PRIMARY" psql -U authz -d authz -q < "$WORK/slow.sql" >/dev/null 2>&1 &
slow_pid=$!
sleep 1
qp "$PRIMARY" "SELECT authz.write_tuple('demo','internal_user','ci_fast','viewer','document','doc_acc_001');" >/dev/null
sleep 1.5
qp "$PRIMARY" "SELECT authz.refresh_materialized_permissions();" >/dev/null
assert "the worker widened its gate to the open transaction (> 2 s)" "t" \
  "$(qp "$PRIMARY" "SELECT last_run_gate > interval '2 seconds' FROM authz.materialized_refresh_state WHERE store='demo';")"
assert "nothing past the open transaction was consumed (ci_fast not derived yet)" "0" \
  "$(qp "$PRIMARY" "SELECT count(*) FROM authz.materialized_permissions WHERE store='demo' AND user_id='ci_fast';")"
wait "$slow_pid" || true
drain_feed || assert "long transaction: feed drained after commit" "ok" "timeout"
parity=$(wait_derived_parity) || true
assert "the slow transaction's write reached the derived replica" "t" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('demo','internal_user','ci_slow','can_read','document','doc_acc_001');")"
assert "the fast write reached it as well" "t" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('demo','internal_user','ci_fast','can_read','document','doc_acc_001');")"

echo "==> The cutoff is absolute and exclusive, and includes the worker's own transaction..."
# watch_changes with p_until ignores the moving clock: a cutoff in the past
# returns nothing even though the lag alone would, a cutoff now returns rows.
qp "$PRIMARY" "SELECT authz.write_tuple('demo','internal_user','ci_cutoff','viewer','document','doc_acc_001');" >/dev/null
sleep 1.2
assert "p_until in the past yields no rows although p_lag would" "0" \
  "$(qp "$PRIMARY" "SELECT count(*) FROM authz.watch_changes('demo', (SELECT cursor_at FROM authz.materialized_refresh_state WHERE store='demo'), (SELECT cursor_seq FROM authz.materialized_refresh_state WHERE store='demo'), 100, '0 seconds', p_until => clock_timestamp() - interval '1 hour');")"
assert "p_until = now yields the committed write" "t" \
  "$(qp "$PRIMARY" "SELECT count(*) >= 1 FROM authz.watch_changes('demo', (SELECT cursor_at FROM authz.materialized_refresh_state WHERE store='demo'), (SELECT cursor_seq FROM authz.materialized_refresh_state WHERE store='demo'), 100, '0 seconds', p_until => clock_timestamp());")"
# A worker run INSIDE an explicit transaction must not advance the cursor past
# that transaction's own start: writes made later in the same transaction have
# the earlier performed_at and would otherwise be skipped forever.
cat > "$WORK/inside.sql" <<'SQL'
BEGIN;
SELECT authz.write_tuple('demo','internal_user','ci_inside1','viewer','document','doc_acc_001');
SELECT pg_sleep(1.5);
SELECT authz.refresh_materialized_permissions();
SELECT authz.write_tuple('demo','internal_user','ci_inside2','viewer','document','doc_acc_001');
COMMIT;
SQL
docker exec -i -e PGPASSWORD=authz "$PRIMARY" psql -U authz -d authz -q < "$WORK/inside.sql" >/dev/null 2>&1
assert "the in-transaction run did not move the cursor past its own transaction" "t" \
  "$(qp "$PRIMARY" "SELECT cursor_at <= (SELECT min(performed_at) FROM authz.tuples_audit WHERE user_id IN ('ci_inside1','ci_inside2')) FROM authz.materialized_refresh_state WHERE store='demo';")"
drain_feed || assert "in-transaction: feed drained" "ok" "timeout"
parity=$(wait_derived_parity) || true
assert "both writes of that transaction reached the derived replica" "t" \
  "$(qp "$DERIVED" "SELECT authz.check_permission('demo','internal_user','ci_inside1','can_read','document','doc_acc_001') AND authz.check_permission('demo','internal_user','ci_inside2','can_read','document','doc_acc_001');")"

echo "==> The refresh entry points refuse any isolation level but READ COMMITTED..."
# Under REPEATABLE READ the snapshot predates the cutoff capture; a change
# committed in between would be invisible yet past the cutoff — skipped forever.
# Assert on SQLSTATE 25000 (invalid_transaction_state), not the message, and
# prove the cursor state (cursor_at, cursor_seq, as_of) is untouched.
# Every registered store, serialized null-safe and ordered, so a rejected run
# that touched any store's cursor shows up.
cursor_state() { qp "$PRIMARY" "SELECT string_agg(format('%s:%s|%s|%s', store, cursor_at, cursor_seq, as_of), ';' ORDER BY store) FROM authz.materialized_refresh_state;"; }
before=$(cursor_state)
rr_worker=$(docker exec -i -e PGPASSWORD=authz "$PRIMARY" psql -U authz -d authz -tA -v VERBOSITY=verbose 2>&1 <<'SQL' | grep -c "^ERROR:  25000:" || true
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT authz.refresh_materialized_permissions();
ROLLBACK;
SQL
)
assert "refresh_materialized_permissions raises SQLSTATE 25000 under REPEATABLE READ" "1" "$rr_worker"
rr_all=$(docker exec -i -e PGPASSWORD=authz "$PRIMARY" psql -U authz -d authz -tA -v VERBOSITY=verbose 2>&1 <<'SQL' | grep -c "^ERROR:  25000:" || true
BEGIN ISOLATION LEVEL SERIALIZABLE;
SELECT authz.refresh_all_materialized_permissions('demo');
ROLLBACK;
SQL
)
assert "refresh_all_materialized_permissions raises SQLSTATE 25000 under SERIALIZABLE" "1" "$rr_all"
assert "cursor_at / cursor_seq / as_of of every store are unchanged by the rejected runs" "$before" "$(cursor_state)"
# The same call inside an explicit READ COMMITTED transaction succeeds.
rc_ok=$(docker exec -i -e PGPASSWORD=authz "$PRIMARY" psql -U authz -d authz -tA -v ON_ERROR_STOP=1 2>&1 <<'SQL' | tail -1
BEGIN ISOLATION LEVEL READ COMMITTED;
SELECT authz.refresh_materialized_permissions();
COMMIT;
SELECT 'rc-ok';
SQL
)
assert "an explicit READ COMMITTED transaction runs the worker" "rc-ok" "$rc_ok"

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

echo "==> Asserting LIVE propagation (write on primary -> changefeed worker -> derived replica)..."
live=timeout; pairs_seen=0
for _ in $(seq 1 15); do
  sleep 1
  p=$(qp "$PRIMARY" "SELECT authz.refresh_materialized_permissions();")
  [ "${p:-0}" -gt 0 ] && pairs_seen=$p
  if [ "$(qp "$DERIVED" "SELECT authz.check_permission('demo','internal_user','ci_repltest','can_read','document','doc_acc_001');")" = "t" ]; then
    live=ok; break
  fi
done
assert "derived replica reflects the write through the worker within 15s" "ok" "$live"
assert "the new subject is now a known subject on the derived replica" "t" \
  "$(qp "$DERIVED" "SELECT EXISTS(SELECT 1 FROM authz.materialized_subjects WHERE store='demo' AND user_id='ci_repltest');")"
assert "the worker re-derived a handful of pairs for that write ($pairs_seen), not the store" "t" \
  "$([ "$pairs_seen" -ge 1 ] && [ "$pairs_seen" -le 5 ] && echo t || echo f)"
assert "derived replica knows how fresh it is (permissions_as_of within the last minute)" "t" \
  "$(qp "$DERIVED" "SELECT authz.permissions_as_of('demo') > now() - interval '1 minute';")"

echo "==> Randomized mutations: 3 batches × 25 draws per store, worker, expiries, differential..."
# tests/sql/derived_permissions_mutate.sql: grants (known / fresh / '*' subjects,
# known / fresh objects), expiring grants (1–3 s), revokes, userset grants,
# object-wildcard grants; writes the model rejects are skipped. Seeds are fixed
# so a failure is reproducible from the same starting state.
mutate() {  # store seed  — psql must succeed, enough draws must apply, no unexpected errors
  local out rc=0 applied unexpected
  out=$({ echo "SELECT set_config('mutate.store', '$1', false), set_config('mutate.n', '25', false), set_config('mutate.seed', '$2', false);"
          cat tests/sql/derived_permissions_mutate.sql
        } | docker exec -i -e PGPASSWORD=authz "$PRIMARY" psql -U authz -d authz -v ON_ERROR_STOP=1 -q 2>&1) || rc=$?
  echo "$out" | grep -i "mutate " | sed 's/^/    /'
  assert "mutate $1 (seed $2): psql exited 0" "0" "$rc"
  applied=$(echo "$out" | sed -n 's/.*: \([0-9]*\) applied.*/\1/p' | head -1)
  unexpected=$(echo "$out" | sed -n 's/.*, \([0-9]*\) unexpected.*/\1/p' | head -1)
  assert "mutate $1 (seed $2): at least 8 of 25 draws applied (${applied:-?})" "t" "$([ "${applied:-0}" -ge 8 ] && echo t || echo f)"
  assert "mutate $1 (seed $2): no unexpected SQL errors" "0" "${unexpected:-?}"
}
for batch in 1 2 3; do
  mutate demo     "0.${batch}1"
  mutate aia_acme "0.${batch}2"
  drain_feed || assert "batch $batch: feed drained" "ok" "timeout"
  sleep 3.5                      # every random expiry (1–3 s) has fallen due
  drain_feed || assert "batch $batch: feed drained after expiries" "ok" "timeout"
  parity=$(wait_derived_parity) || true
  case "$parity" in timeout*) assert "batch $batch: derived tables match the primary" "parity" "$parity";;
                    *)        assert "batch $batch: derived tables match the primary ($parity)" "ok" "ok";; esac
  differential "batch $batch"
done

echo ""
if [ "$fail" -ne 0 ]; then
  echo "==> REPLICATION TESTS FAILED"
  exit 1
fi
echo "==> All replication tests passed."
echo "    (stack left running — tear down with: ${COMPOSE[*]} down -v)"
