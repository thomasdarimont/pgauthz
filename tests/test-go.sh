#!/usr/bin/env bash
#
# Runs the AuthZEN Go unit tests and reports in the shared
# "==> N passed, M failed (of T ...)" format so test-all.sh can total them.
# Skips gracefully if Go is not on PATH (the services build in Docker).
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../pgauthzd"

if ! command -v go >/dev/null 2>&1; then
    echo "    SKIP  go not on PATH — skipping AuthZEN Go unit tests"
    echo "==> 0 passed, 0 failed (of 0 go unit checks)"
    exit 0
fi

out=$(go test -v ./... 2>&1)
status=$?
echo "$out"

passed=$(echo "$out" | grep -c '^[[:space:]]*--- PASS:')
failed=$(echo "$out" | grep -c '^[[:space:]]*--- FAIL:')
echo "==> ${passed} passed, ${failed} failed (of $((passed + failed)) go unit checks)"

[ "$status" -eq 0 ]
