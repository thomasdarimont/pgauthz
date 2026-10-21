#!/usr/bin/env bash
#
# The derived-relations refresh worker: a loop around
# authz.refresh_materialized_relations() (db/replication/materialized_relations.sql).
#
# Connection: libpq environment (PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD
# or PGPASSFILE). The login role inherits authz_derived_worker. Knobs:
#
#   DERIVED_STORES      comma-separated stores to REGISTER at start if they are
#                       not registered yet (refresh_all_materialized_relations:
#                       the initial snapshot); an unknown store is logged and
#                       retried on the next start — nothing else is affected
#   WORKER_LAG          stability lag passed as p_lag          (default: 1 second)
#   WORKER_PAGE_LIMIT   changefeed rows per store per run      (default: 1000)
#   WORKER_INTERVAL     seconds to sleep when every feed is drained (default: 2)
#
# One run = one READ COMMITTED transaction (psql autocommit). While a store's
# feed is not drained the next run follows immediately; otherwise the worker
# sleeps WORKER_INTERVAL. Errors are logged and retried after the interval —
# the cursor only moves in a committed run, so nothing is lost. Run ONE
# instance; a second one is harmless (per-store try-locks) but pointless.
set -euo pipefail

LAG="${WORKER_LAG:-1 second}"
LIMIT="${WORKER_PAGE_LIMIT:-1000}"
INTERVAL="${WORKER_INTERVAL:-2}"
PSQL=(psql -X -q -tA -v ON_ERROR_STOP=1)

log() { printf '%s derived-worker %s\n' "$(date -u +%FT%TZ)" "$*"; }

log "starting against ${PGHOST:-localhost}:${PGPORT:-5432}/${PGDATABASE:-authz} as ${PGUSER:-$(id -un)} (lag=$LAG limit=$LIMIT interval=${INTERVAL}s)"
until pg_isready -q; do log "waiting for the database..."; sleep 2; done

register() {
  local store=$1 out
  if out=$("${PSQL[@]}" -c "SELECT EXISTS (SELECT 1 FROM authz.materialized_relations_status() WHERE store = '$store');" 2>&1) \
     && [ "$out" = "t" ]; then
    log "store '$store' already registered"
    return 0
  fi
  if out=$("${PSQL[@]}" -c "SELECT authz.refresh_all_materialized_relations('$store', '$LAG');" 2>&1); then
    log "registered store '$store': $out rows derived"
  else
    log "could not register store '$store' (retried on the next start): $out"
  fi
}

IFS=, read -ra stores <<< "${DERIVED_STORES:-}"
for s in "${stores[@]}"; do
  s="${s// /}"; [ -n "$s" ] && register "$s"
done

while true; do
  # Two statements, two transactions: the worker's effect is only visible to a
  # LATER statement (a read in the worker's own statement sees the old state).
  if out=$("${PSQL[@]}" 2>&1 <<SQL
SELECT authz.refresh_materialized_relations('$LAG', $LIMIT);
SELECT coalesce(bool_and(feed_drained), true) FROM authz.materialized_relations_status();
SQL
  ); then
    pairs=$(sed -n 1p <<< "$out"); drained=$(sed -n 2p <<< "$out")
    [ "$pairs" != "0" ] && log "re-derived $pairs pairs"
    if [ "$drained" = "f" ]; then continue; fi   # more pages waiting
  else
    log "run failed (retrying in ${INTERVAL}s): $out"
  fi
  sleep "$INTERVAL"
done
