-- Tests for per-write consistency modes (X-Authz-Consistency → _pre_request()
-- → SET LOCAL synchronous_commit). The header arrives via PostgREST's
-- request.headers GUC; we simulate that and assert the transaction-local
-- synchronous_commit each mode produces.

\echo '==> Running write-consistency checks...'

-- Helper: simulate a request carrying the given consistency header, run the
-- hook, and report the resulting transaction-local synchronous_commit.
CREATE FUNCTION pg_temp._wc_apply(p_header text) RETURNS text
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('request.headers',
        CASE WHEN p_header IS NULL THEN ''
             ELSE json_build_object('x-authz-consistency', p_header)::text END,
        true);
    PERFORM authz._pre_request();
    RETURN current_setting('synchronous_commit');
END;
$$;

DO $$
DECLARE
    pass_count int := 0;
    fail_count int := 0;
    v_got      text;
BEGIN
    -- (cases share this transaction; each sets the GUC explicitly, and the
    -- absent-header case documents that it keeps the preceding value)

    v_got := pg_temp._wc_apply('applied');
    IF v_got = 'remote_apply' THEN pass_count := pass_count + 1; RAISE NOTICE '    PASS  applied → remote_apply';
    ELSE fail_count := fail_count + 1; RAISE NOTICE '    FAIL  applied → remote_apply (got %)', v_got; END IF;

    v_got := pg_temp._wc_apply('durable');
    IF v_got = 'on' THEN pass_count := pass_count + 1; RAISE NOTICE '    PASS  durable → on';
    ELSE fail_count := fail_count + 1; RAISE NOTICE '    FAIL  durable → on (got %)', v_got; END IF;

    v_got := pg_temp._wc_apply('eventual');
    IF v_got = 'local' THEN pass_count := pass_count + 1; RAISE NOTICE '    PASS  eventual → local';
    ELSE fail_count := fail_count + 1; RAISE NOTICE '    FAIL  eventual → local (got %)', v_got; END IF;

    -- absent header → hook leaves the setting untouched (still local from above)
    v_got := pg_temp._wc_apply(NULL);
    IF v_got = 'local' THEN pass_count := pass_count + 1; RAISE NOTICE '    PASS  absent header keeps current setting';
    ELSE fail_count := fail_count + 1; RAISE NOTICE '    FAIL  absent header keeps current setting (got %)', v_got; END IF;

    -- unknown mode fails closed
    BEGIN
        PERFORM pg_temp._wc_apply('fast');
        fail_count := fail_count + 1; RAISE NOTICE '    FAIL  unknown mode should raise';
    EXCEPTION WHEN invalid_parameter_value THEN
        pass_count := pass_count + 1; RAISE NOTICE '    PASS  unknown mode "fast" fails closed (invalid_parameter_value)';
    END;

    RAISE NOTICE '';
    RAISE NOTICE '==> % passed, % failed (of % write-consistency checks)',
        pass_count, fail_count, pass_count + fail_count;
    IF fail_count > 0 THEN
        RAISE EXCEPTION '% write-consistency checks failed', fail_count;
    END IF;
END;
$$;
