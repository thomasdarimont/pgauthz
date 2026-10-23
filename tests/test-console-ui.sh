#!/usr/bin/env bash
#
# Runs the management console's BROWSER tests (Playwright, Chromium headless)
# against a running console — the console-local stack:
#
#   ./start.sh --console-local      # http://localhost:8095/console/, admin/admin
#   ./tests/test-console-ui.sh
#
# They cover what the Go handler tests cannot reach: the share dialog's
# request/response race, Save's binding to the loaded object, the post-save
# state when the refresh fails, the expiry chip; the Decisions tab's summary,
# pager, filters, detail and hand-over into Test. Loads the fixture store
# console_uitest (console/frontend/tests/ui/fixture.sql) and the decisions
# fixture (decisions.sql, into the console's database) and drops both after.
# Without a reachable console the suite is SKIPPED (it needs the stack this
# script does not start) — unless PGAUTHZ_TEST_REQUIRE_CONSOLE=1, then it
# waits up to a minute for the console and fails if none appears (CI's
# console-ui-test job). CONSOLE_URL overrides the console's address. Reports
# in the shared "==> N passed, M failed" format for test-all.sh.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$PG_DIR/env.sh"

CONSOLE_URL="${CONSOLE_URL:-http://localhost:8095/console/}"
export CONSOLE_URL
STORE=console_uitest
FRONTEND="$PG_DIR/console/frontend"

skip() {
    if [ "${PGAUTHZ_TEST_REQUIRE_CONSOLE:-0}" = "1" ]; then
        echo "ERROR: $1 (PGAUTHZ_TEST_REQUIRE_CONSOLE=1)" >&2
        echo "==> 0 passed, 1 failed (of 1 console browser checks)"
        exit 1
    fi
    echo "    SKIP  $1 — skipping console browser tests"
    echo "==> 0 passed, 0 failed (of 0 console browser checks)"
    exit 0
}

command -v node >/dev/null 2>&1 || skip "node not on PATH"
# The BFF serves only once the engine answers and the console store exists
# (AwaitEngine), so a freshly started stack needs a moment.
console_up() { curl -fsS -o /dev/null --max-time 5 "${CONSOLE_URL%/}/healthz" 2>/dev/null; }
if ! console_up; then
    if [ "${PGAUTHZ_TEST_REQUIRE_CONSOLE:-0}" = "1" ]; then
        echo "==> Waiting for the console at $CONSOLE_URL..."
        for _ in $(seq 1 30); do sleep 2; console_up && break; done
    fi
    console_up || skip "no console at $CONSOLE_URL (./start.sh --console-local)"
fi

# The decisions fixture lives in the CONSOLE's own database (the decision
# log's postgres sink, decisionlog.decisions), reached through the
# console-db service of the console-local stack; a console that is only
# reachable over CONSOLE_URL has no such access, and the Decisions spec then
# skips itself (CONSOLE_UI_DECISIONS unset).
console_psql() {
    docker compose "${COMPOSE_FILES[@]}" exec -T -e PGPASSWORD="${CONSOLE_DB_PASSWORD:-console}" console-db \
        psql -v ON_ERROR_STOP=1 -q -U console -d pgauthz_console "$@"
}
cleanup() {
    psql_exec "$PG_DB" -q -c "SELECT authz.delete_store('$STORE', p_purge_audit => true);" >/dev/null 2>&1 || true
    # the Issuers spec's bindings (one issuer per run under https://uitest.example/)
    psql_exec "$PG_DB" -q -c "DELETE FROM authz.issuer_bindings WHERE issuer LIKE 'https://uitest.example/%';" >/dev/null 2>&1 || true
    if [ "${CONSOLE_UI_DECISIONS:-0}" = "1" ]; then
        console_psql -c "DELETE FROM decisionlog.decisions WHERE store = '$STORE';" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "==> Loading the browser fixture as store $STORE..."
psql_file "$PG_DB" "$FRONTEND/tests/ui/fixture.sql" -v store="$STORE" >/dev/null || exit 1
if console_psql -v store="$STORE" < "$FRONTEND/tests/ui/decisions.sql" >/dev/null 2>&1; then
    echo "==> Loaded the decisions fixture into the console database"
    export CONSOLE_UI_DECISIONS=1
else
    echo "    SKIP  no console-db service reachable — the Decisions tab spec will skip"
fi

cd "$FRONTEND"
if [ ! -d node_modules/@playwright/test ]; then
    echo "==> npm ci (Playwright is a devDependency)..."
    npm ci --silent || exit 1
fi
# A no-op when the pinned Chromium build is already in the browser cache.
npx playwright install chromium-headless-shell >/dev/null 2>&1 || exit 1

echo "==> Running the console browser tests against $CONSOLE_URL..."
out=$(CONSOLE_UI_STORE="$STORE" npx playwright test 2>&1)
status=$?
echo "$out"

passed=$(echo "$out" | grep -Eo '[0-9]+ passed' | tail -1 | grep -Eo '[0-9]+' || echo 0)
failed=$(echo "$out" | grep -Eo '[0-9]+ failed' | tail -1 | grep -Eo '[0-9]+' || echo 0)
passed=${passed:-0}; failed=${failed:-0}
echo "==> ${passed} passed, ${failed} failed (of $((passed + failed)) console browser checks)"

[ "$status" -eq 0 ]
