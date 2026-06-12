#!/usr/bin/env bash
#
# Runs all authorization test suites against a running database.
# Requires init.sh to have been run first.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_DIR="$SCRIPT_DIR/.."
source "$PG_DIR/env.sh"

# Load shared test helpers (_assert, _assert_true, _test_reset, _test_report)
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_helpers.sql"

echo "==> Running demo model checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/models/demo/tests.sql"

echo ""
echo "==> Running contextual / condition checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_contextual.sql"

echo ""
echo "==> Running search API checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_search.sql"

echo ""
echo "==> Running API function checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_api.sql"

echo ""
echo "==> Running namespace access control checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_namespace.sql"

echo ""
echo "==> Running intersection / exclusion checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_intersection.sql"

echo ""
echo "==> Running wildcard tuple checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_wildcard.sql"

echo ""
echo "==> Running eval_rule unit checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_eval_rule.sql"

echo ""
echo "==> Running type restriction checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_type_restrictions.sql"

echo ""
echo "==> Running partition management checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_partitions.sql"

echo ""
echo "==> Running OpenFGA import checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_openfga.sql"

echo ""
echo "==> Running recursion / cycle checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_recursion.sql"

# Clean up test helpers
psql_file "$PG_DB" "$PG_DIR/db/tests/tests_helpers_cleanup.sql"
