-- Shared test helpers for assertion-based test files.
--
-- Loaded once per test run by test.sh. Test files use:
--   SELECT _test_reset();              -- at the top (clears previous results)
--   PERFORM _test_assert(...);         -- for each check
--   SELECT * FROM _test_teardown_*();  -- after DO block (shows results in IDE, clears)
--   SELECT _test_report('label');      -- at the bottom (prints summary, raises on failure)
--
-- Cleaned up by tests_helpers_cleanup.sql at the end of the test run.

CREATE TABLE IF NOT EXISTS _test_results (
    name   text    NOT NULL,
    passed boolean NOT NULL,
    detail text
);

-- Reset results and counters between test files.
CREATE OR REPLACE FUNCTION _test_reset()
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    TRUNCATE _test_results;
    PERFORM set_config('test.pass', '0', false);
    PERFORM set_config('test.fail', '0', false);
END;
$$;

-- Assert exact text equality (handles NULLs via IS NOT DISTINCT FROM).
-- Returns a result row so SELECT _test_assert(...) shows output in IDEs.
DROP FUNCTION IF EXISTS _test_assert(text, text, text);
CREATE OR REPLACE FUNCTION _test_assert(p_name text, p_actual text, p_expected text)
RETURNS _test_results LANGUAGE plpgsql AS $$
DECLARE
    v_row _test_results;
BEGIN
    IF p_actual IS NOT DISTINCT FROM p_expected THEN
        v_row := (p_name, true, NULL);
        INSERT INTO _test_results VALUES (p_name, true);
        PERFORM set_config('test.pass',
            (coalesce(current_setting('test.pass', true), '0')::int + 1)::text, false);
        RAISE NOTICE '    PASS  %', p_name;
    ELSE
        v_row := (p_name, false, format('expected=%s, got=%s', p_expected, p_actual));
        INSERT INTO _test_results VALUES (p_name, false, v_row.detail);
        PERFORM set_config('test.fail',
            (coalesce(current_setting('test.fail', true), '0')::int + 1)::text, false);
        RAISE NOTICE '    FAIL  %: expected=%, got=%', p_name, p_expected, p_actual;
    END IF;
    RETURN v_row;
END;
$$;

-- Assert a boolean condition with optional detail for diagnostics.
-- Returns a result row so SELECT _test_assert_true(...) shows output in IDEs.
DROP FUNCTION IF EXISTS _test_assert_true(text, boolean, text);
CREATE OR REPLACE FUNCTION _test_assert_true(p_name text, p_condition boolean, p_detail text DEFAULT NULL)
RETURNS _test_results LANGUAGE plpgsql AS $$
DECLARE
    v_row _test_results;
BEGIN
    IF p_condition THEN
        v_row := (p_name, true, p_detail);
        INSERT INTO _test_results VALUES (p_name, true);
        PERFORM set_config('test.pass',
            (coalesce(current_setting('test.pass', true), '0')::int + 1)::text, false);
        IF p_detail IS NOT NULL THEN
            RAISE NOTICE '    PASS  %: %', p_name, p_detail;
        ELSE
            RAISE NOTICE '    PASS  %', p_name;
        END IF;
    ELSE
        v_row := (p_name, false, p_detail);
        INSERT INTO _test_results VALUES (p_name, false, p_detail);
        PERFORM set_config('test.fail',
            (coalesce(current_setting('test.fail', true), '0')::int + 1)::text, false);
        IF p_detail IS NOT NULL THEN
            RAISE NOTICE '    FAIL  %: %', p_name, p_detail;
        ELSE
            RAISE NOTICE '    FAIL  %', p_name;
        END IF;
    END IF;
    RETURN v_row;
END;
$$;

-- Print summary and raise exception if any tests failed.
-- Reads from GUC counters so it works even after teardown clears _test_results.
CREATE OR REPLACE FUNCTION _test_report(p_label text DEFAULT 'checks')
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_pass  int;
    v_fail  int;
    v_total int;
BEGIN
    v_pass  := coalesce(current_setting('test.pass', true), '0')::int;
    v_fail  := coalesce(current_setting('test.fail', true), '0')::int;
    v_total := v_pass + v_fail;

    RAISE NOTICE '';
    RAISE NOTICE '==> % passed, % failed (of % %)', v_pass, v_fail, v_total, p_label;

    IF v_fail > 0 THEN
        RAISE EXCEPTION '% % failed', v_fail, p_label;
    END IF;
END;
$$;
