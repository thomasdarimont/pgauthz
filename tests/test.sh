#!/usr/bin/env bash
#
# Runs all authorization test suites against a running database.
# Requires init.sh to have been run first.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_DIR="$SCRIPT_DIR/.."
source "$PG_DIR/env.sh"

# Lint: public decision entry points must go through authz._decide (live) /
# authz._decide_snapshot (time-travel), never the graph walk directly — that
# is the seam temporal gates (ADR 0012) hang on, so a new entry point cannot
# forget them. (maintenance.sql's find_redundant_tuples asks a graph-only
# question and is deliberately exempt.)
echo "==> Lint: decision entry points call _decide..."
if grep -n "authz\._check_access(" "$PG_DIR/db/engine/access.sql" "$PG_DIR/db/engine/explain.sql"; then
  echo "FAIL: access.sql/explain.sql must call authz._decide, not authz._check_access" >&2; exit 1
fi
if grep -n "authz\._check_access_snapshot(" "$PG_DIR/db/engine/audit.sql"; then
  echo "FAIL: audit.sql must call authz._decide_snapshot, not authz._check_access_snapshot" >&2; exit 1
fi
echo "    ok"

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
echo "==> Loading todo model (AuthZEN interop) + checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/examples/models/todo/model.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/todo/seed.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/todo/tests.sql"

echo ""
echo "==> Loading gdrive model (temporal gates example) + checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/examples/models/gdrive/model.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/gdrive/seed.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/gdrive/tests.sql"

echo ""
echo "==> Loading aia-acme model (Authorization in Action, Cedar example) + checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/examples/models/aia-acme/model.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/aia-acme/seed.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/aia-acme/tests.sql"

echo ""
echo "==> Loading agents model (AI agents: planning, sequencing, delegation) + checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/examples/models/agents/model.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/agents/seed.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/agents/tests.sql"

echo ""
echo "==> Loading fourquestions model (the pitch example: team, exclusion, expiry, three gates) + checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/examples/models/fourquestions/model.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/fourquestions/seed.sql"
psql_file "$PG_DB" "$PG_DIR/examples/models/fourquestions/tests.sql"

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

# NOTE: per-write consistency mode mapping (applied/durable/eventual + fail-closed
# on unknown) and the per-app reader-role validation formerly lived in the SQL
# _pre_request/_pre_request_reader hooks and were tested here. Those hooks are
# gone; pgauthzd now performs both in Go — covered by
# pgauthzd's TestSyncCommit unit test and the end-to-end namespace-isolation
# checks in tests/test-opa.sh.

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
echo "==> Running memoization property/differential checks (random graphs, both backends)..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_memo_property.sql"

echo ""
echo "==> Running resolver regression shapes (OpenFGA v2-resolver bug classes)..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_resolver_shapes.sql"

echo ""
echo "==> Running read-only (replica) check resolution checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_readonly.sql"

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
echo "==> Running native expiry (expires_at) checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_expiry.sql"

echo ""
echo "==> Running compositional tri-state decision checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_decision_tristate.sql"

echo ""
echo "==> Running decision detail (rich results) checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_decision_detail.sql"

echo ""
echo "==> Running model registry (publish/apply/drift) checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_model_registry.sql"

echo ""
echo "==> Running retire / soft-delete (audit-after-deletion) checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_retire.sql"

echo ""
echo "==> Running watch / changefeed checks..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_watch.sql"

echo ""
echo "==> Running freshness-token checks (ADR 0009)..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_freshness.sql"

echo ""
echo "==> Running action log (events) checks (ADR 0012)..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_events.sql"

echo ""
echo "==> Running temporal gate checks (ADR 0012 phase 2)..."
echo ""
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_gates.sql"

# reserve_event concurrency (ADR 0012 phase 3): N parallel sessions reserving
# against a cap of K must yield EXACTLY K allows — the per-(store, subject)
# advisory lock is the whole point of the strict tier. Separate psql
# processes so the transactions genuinely race.
echo ""
echo "==> Running reserve_event concurrency check (8 parallel reserves, cap 3)..."
echo ""
psql_exec "$PG_DB" -q -v ON_ERROR_STOP=1 -c "
  DO \$\$ BEGIN PERFORM authz.delete_store('test_reserve', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END \$\$;
  SELECT authz.create_store('test_reserve');
  SELECT authz.model_register_type('test_reserve', 'user');
  SELECT authz.model_register_type('test_reserve', 'account');
  SELECT authz.model_register_relation('test_reserve', 'transfer');
  SELECT authz.model_add_rule('test_reserve', 'account', 'transfer', 'direct');
  SELECT authz.write_tuple('test_reserve', 'user', 'alice', 'transfer', 'account', 'acc-1');
  SELECT authz.add_gate('test_reserve', 'account', 'transfer', 'cap', '{\"all_of\": [{\"count_within\": {\"window\": \"1h\", \"max\": 3, \"plus\": 1}}]}');
" >/dev/null
RESERVE_OUT="$(mktemp)"
for i in $(seq 1 8); do
  psql_exec "$PG_DB" -qtA -c "SELECT authz.reserve_event('test_reserve','user','alice','transfer','account','acc-1') ->> 'allowed';" >> "$RESERVE_OUT" 2>&1 &
done
wait
ALLOWED=$(grep -c '^true$' "$RESERVE_OUT" || true)
DENIED=$(grep -c '^false$' "$RESERVE_OUT" || true)
rm -f "$RESERVE_OUT"
psql_exec "$PG_DB" -q -c "SELECT authz.delete_store('test_reserve', p_purge_audit => true);" >/dev/null
if [ "$ALLOWED" = "3" ] && [ "$DENIED" = "5" ]; then
  echo "    PASS  reserve_concurrency: 3 allowed, 5 denied of 8 parallel reserves"
else
  echo "    FAIL  reserve_concurrency: expected 3 allowed / 5 denied, got $ALLOWED / $DENIED" >&2
  exit 1
fi

# Clean up test helpers
psql_file "$PG_DB" "$PG_DIR/tests/sql/tests_helpers_cleanup.sql"
