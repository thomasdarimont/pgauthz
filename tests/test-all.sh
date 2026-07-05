#!/usr/bin/env bash
#
# Runs all test suites (SQL, OPA, AuthZEN) and prints a grand total.
# Requires init.sh to have been run first.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

total_pass=0
total_fail=0
total_tests=0

# Run a test script, tee output, and accumulate pass/fail/total counts
# from lines matching: ==> X passed, Y failed (of Z checks)
# Run a test script, stream output in real-time via tee, and accumulate
# pass/fail/total counts from lines matching: ==> X passed, Y failed (of Z checks)
run_tests() {
    local tmpfile
    tmpfile=$(mktemp)
    "$@" 2>&1 | tee "$tmpfile" || { rm -f "$tmpfile"; exit 1; }

    while IFS= read -r line; do
        local p f t
        p=$(echo "$line" | sed -n 's/.*==> \([0-9]*\) passed.*/\1/p')
        f=$(echo "$line" | sed -n 's/.*passed, \([0-9]*\) failed.*/\1/p')
        t=$(echo "$line" | sed -n 's/.*(of \([0-9]*\) .*/\1/p')
        if [ -n "$p" ] && [ -n "$f" ] && [ -n "$t" ]; then
            total_pass=$((total_pass + p))
            total_fail=$((total_fail + f))
            total_tests=$((total_tests + t))
        fi
    done < "$tmpfile"
    rm -f "$tmpfile"
}

test_start=$SECONDS

echo ""
echo "==> Running all tests..."
echo ""
run_tests "$SCRIPT_DIR/test.sh"

echo ""
echo "==> Running OPA integration tests..."
echo ""
run_tests "$SCRIPT_DIR/test-opa.sh"

echo ""
echo "==> Running AuthZEN integration tests..."
echo ""
run_tests "$SCRIPT_DIR/test-authzen.sh"

echo ""
echo "==> Running AuthZEN Go unit tests..."
echo ""
run_tests "$SCRIPT_DIR/test-go.sh"

echo ""
echo "==> Running authzctl CLI integration tests..."
echo ""
run_tests "$SCRIPT_DIR/test-authzctl.sh"

test_duration=$((SECONDS - test_start))

echo ""
echo "==========================================================="
echo "  Total: $total_pass passed, $total_fail failed (of $total_tests tests)"
echo "  Duration: ${test_duration}s"
echo "==========================================================="

if [ "$total_fail" -gt 0 ]; then
    exit 1
fi
