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
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_helpers.sql"

# Test login roles (app_readonly/app_readwrite/app_auditor) used by the
# integration suites. These are test scaffolding, not part of the engine,
# so they live here rather than in init.sh. Idempotent.
psql_file "$PG_DB" "$PG_DIR/tests/sql/test_users.sql"

# The demo model is a fixture for the integration tests below (and for
# the OPA/AuthZEN suites, whose DEFAULT_STORE is 'demo'). init.sh no
# longer loads it, so load it here — idempotent, safe to re-run.
echo "==> Loading demo model fixture..."
echo ""
psql_file "$PG_DB" "$PG_DIR/examples/models/demo/model.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/demo/seed.sql"

echo "==> Running demo model checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/examples/models/demo/tests.sql"

echo ""
echo "==> Running contextual / condition checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_contextual.sql"

echo ""
echo "==> Running search API checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_search.sql"

echo ""
echo "==> Running list_subjects (reverse expansion) checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_list_subjects.sql"

echo ""
echo "==> Running API function checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_api.sql"

echo ""
echo "==> Running write precondition (optimistic concurrency) checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_preconditions.sql"

echo ""
echo "==> Running describe_model (readable rendering) checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_describe.sql"

echo ""
echo "==> Running keyset (cursor) pagination checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_keyset.sql"

echo ""
echo "==> Running namespace access control checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_namespace.sql"

echo ""
echo "==> Running intersection / exclusion checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_intersection.sql"

echo ""
echo "==> Running wildcard tuple checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_wildcard.sql"

echo ""
echo "==> Running eval_rule unit checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_eval_rule.sql"

echo ""
echo "==> Running condition language checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_condition_lang.sql"

echo ""
echo "==> Running SQL/CEL condition equivalence checks (skipped without pg_cel)..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_condition_equivalence.sql"

echo ""
echo "==> Running memoization equivalence checks (memo == no-memo on cyclic graphs)..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_memoization.sql"

echo ""
echo "==> Running type restriction checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_type_restrictions.sql"

echo ""
echo "==> Running partition management checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_partitions.sql"

echo ""
echo "==> Running OpenFGA import checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_openfga.sql"

echo ""
echo "==> Running recursion / cycle checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_recursion.sql"

echo ""
echo "==> Running object wildcard checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_object_wildcard.sql"

echo ""
echo "==> Running model versioning (time-travel) checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_model_versioning.sql"

echo ""
echo "==> Running retire / soft-delete (audit-after-deletion) checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_retire.sql"

echo ""
echo "==> Running watch / changefeed checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_watch.sql"

# Clean up test helpers
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_helpers_cleanup.sql"
