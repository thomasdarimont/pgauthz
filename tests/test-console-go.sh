#!/usr/bin/env bash
#
# Runs the management console's Go tests AGAINST THE DATABASE: the race tests
# in console/backend (concurrent last-owner removal, platform-revocation
# ordering, the namespace-rename gate) need a console store and skip without
# one. Here they are mandatory (PGAUTHZ_TEST_REQUIRE_DATABASE=1): the suite
# fails if the database is unreachable instead of passing by skipping
# (review #16, round 3). Loads the console fixture as its own store,
# console_gotest, so a running console's `console` store is never touched,
# and drops it afterwards. Reports in the shared "==> N passed, M failed"
# format for test-all.sh.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$PG_DIR/env.sh"

if ! command -v go >/dev/null 2>&1; then
    echo "    SKIP  go not on PATH — skipping console Go tests"
    echo "==> 0 passed, 0 failed (of 0 go unit checks)"
    exit 0
fi

CS=console_gotest
cleanup() {
    psql_exec "$PG_DB" -q -c "SELECT authz.delete_store('$CS', p_purge_audit => true);" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Loading the console fixture as store $CS..."
psql_file "$PG_DB" "$PG_DIR/examples/models/console/model.sql" -v cs="$CS" >/dev/null || exit 1

cd "$PG_DIR/console/backend"
out=$(PGAUTHZ_TEST_DATABASE_URL="$DATABASE_URL" \
      PGAUTHZ_TEST_CONSOLE_STORE="$CS" \
      PGAUTHZ_TEST_REQUIRE_DATABASE=1 \
      go test -count=1 -v ./... 2>&1)
status=$?
echo "$out"

passed=$(echo "$out" | grep -c '^[[:space:]]*--- PASS:')
failed=$(echo "$out" | grep -c '^[[:space:]]*--- FAIL:')
skipped=$(echo "$out" | grep -c '^[[:space:]]*--- SKIP:')
if [ "$skipped" -gt 0 ]; then
    echo "ERROR: $skipped console Go test(s) skipped — the database-backed tests are mandatory here" >&2
    status=1
fi
echo "==> ${passed} passed, ${failed} failed (of $((passed + failed)) go unit checks)"

[ "$status" -eq 0 ]
