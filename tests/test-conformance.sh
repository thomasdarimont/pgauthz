#!/usr/bin/env bash
#
# Runs the OpenID conformance suite's AuthZEN PDP test plans against pgauthzd
# (conformance/). Needs Docker (the suite runs in Testcontainers) and the demo
# stack with pgauthzd-decision on :8090 started with ALLOW_SUBJECT_OVERRIDE=true
# (env.sh's default). Loads the authzen_cert fixture first, then runs the plans;
# minutes per plan, the suite images are pulled on first use.
#
#   ./tests/test-conformance.sh                       # all plans
#   ./tests/test-conformance.sh -run TestEvaluationPlan
#   CTS_PGAUTHZD_URL=http://localhost:8099 ./tests/test-conformance.sh   # another instance
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_DIR="$SCRIPT_DIR/.."
source "$PG_DIR/env.sh"

PGAUTHZD_URL="${CTS_PGAUTHZD_URL:-http://localhost:8090}"

if [ "$(psql_exec "$PG_DB" -tA -c "SELECT to_regclass('authz.tuples') IS NOT NULL" 2>/dev/null)" != "t" ]; then
  echo "ERROR: the pgauthz engine is not installed in database '$PG_DB' — run ./init.sh first." >&2
  exit 1
fi

echo "==> Loading the authzen_cert fixture (examples/models/authzen-cert)..."
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_helpers.sql" >/dev/null
psql_file "$PG_DB" "$PG_DIR/examples/models/authzen-cert/model.sql" >/dev/null
psql_file "$PG_DB" "$PG_DIR/examples/models/authzen-cert/seed.sql" >/dev/null
psql_file "$PG_DB" "$PG_DIR/examples/models/authzen-cert/tests.sql" 2>&1 | grep -E "FAIL|==>" || true

if ! curl -sf "$PGAUTHZD_URL/readyz" >/dev/null; then
  echo "ERROR: pgauthzd is not ready at $PGAUTHZD_URL (./start.sh, or set CTS_PGAUTHZD_URL)." >&2
  exit 1
fi

echo "==> Running the conformance suite against $PGAUTHZD_URL (suite UI: https://localhost:${CTS_SUITE_PORT:-18444})..."
cd "$PG_DIR/conformance"
if [ $# -eq 0 ]; then set -- -run Plan; fi
PGAUTHZ_CONFORMANCE_TESTS=true CTS_PGAUTHZD_URL="$PGAUTHZD_URL" go test -timeout 90m -v -count=1 "$@" .
