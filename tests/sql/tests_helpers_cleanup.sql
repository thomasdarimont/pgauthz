-- Clean up shared test helpers created by tests_helpers.sql.
DROP FUNCTION IF EXISTS _test_report(text);
DROP FUNCTION IF EXISTS _test_assert_true(text, boolean, text);
DROP FUNCTION IF EXISTS _test_assert(text, text, text);
DROP FUNCTION IF EXISTS _test_reset();
DROP TABLE IF EXISTS _test_results;
