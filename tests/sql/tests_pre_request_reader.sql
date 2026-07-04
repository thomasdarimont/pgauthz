-- Tests for authz._pre_request_reader() — the reader-side PostgREST
-- db-pre-request hook (per-app namespace isolation on READS).
--
-- The hook validates the X-Authz-Role header (member of authz_reader, NOT
-- admin-capable, fail closed) and SET LOCAL ROLEs to it. We simulate the
-- PostgREST request.headers GUC and observe the effective role.

\echo '==> Running reader pre-request hook checks...'

-- Simulate a request carrying the given role header, run the hook, report the
-- resulting current_user, and restore the original role for the next case.
CREATE FUNCTION pg_temp._prr_apply(p_role text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v_user text;
BEGIN
    PERFORM set_config('request.headers',
        CASE WHEN p_role IS NULL THEN ''
             ELSE json_build_object('x-authz-role', p_role)::text END,
        true);
    PERFORM authz._pre_request_reader();
    v_user := current_user;
    RESET ROLE;
    RETURN v_user;
END;
$$;

-- Assert helper: role header → expected effective user ('' = expect rejection).
CREATE FUNCTION pg_temp._prr_case(p_name text, p_role text, p_expected text)
RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_got text;
BEGIN
    IF p_expected = '<reject>' THEN
        BEGIN
            PERFORM pg_temp._prr_apply(p_role);
            RAISE NOTICE '    FAIL  % (should have raised)', p_name;
            RETURN false;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE '    PASS  %', p_name;
            RETURN true;
        END;
    END IF;
    v_got := pg_temp._prr_apply(p_role);
    IF v_got = p_expected THEN
        RAISE NOTICE '    PASS  %', p_name;
        RETURN true;
    END IF;
    RAISE NOTICE '    FAIL  % (expected %, got %)', p_name, p_expected, v_got;
    RETURN false;
END;
$$;

DO $$
BEGIN
    -- Scratch roles for each membership case (superuser context).
    DROP ROLE IF EXISTS test_prr_app;
    DROP ROLE IF EXISTS test_prr_writer;
    DROP ROLE IF EXISTS test_prr_admin;
    DROP ROLE IF EXISTS test_prr_plain;
    CREATE ROLE test_prr_app    NOLOGIN;  GRANT authz_reader TO test_prr_app;
    CREATE ROLE test_prr_writer NOLOGIN;  GRANT authz_writer TO test_prr_writer;
    CREATE ROLE test_prr_admin  NOLOGIN;  GRANT authz_admin  TO test_prr_admin;
    CREATE ROLE test_prr_plain  NOLOGIN;  -- no authz memberships
END;
$$;

DO $$
DECLARE
    fail_count int := 0;
    v_me       text := current_user;
BEGIN
    -- Reader-member app role → assumed.
    IF NOT pg_temp._prr_case('prr_1_reader_role_assumed', 'test_prr_app', 'test_prr_app') THEN fail_count := fail_count + 1; END IF;
    -- Writer role → assumed too (authz_writer inherits authz_reader; a role
    -- allowed to write tuples may read them).
    IF NOT pg_temp._prr_case('prr_2_writer_role_assumed', 'test_prr_writer', 'test_prr_writer') THEN fail_count := fail_count + 1; END IF;
    -- Absent / empty header → no switch (stays the session role).
    IF NOT pg_temp._prr_case('prr_3_absent_header_no_switch', NULL, v_me) THEN fail_count := fail_count + 1; END IF;
    IF NOT pg_temp._prr_case('prr_4_empty_header_no_switch', '', v_me) THEN fail_count := fail_count + 1; END IF;
    -- Admin-capable role → rejected (a forged header cannot escalate).
    IF NOT pg_temp._prr_case('prr_5_admin_role_rejected', 'test_prr_admin', '<reject>') THEN fail_count := fail_count + 1; END IF;
    -- Role without authz_reader membership → rejected.
    IF NOT pg_temp._prr_case('prr_6_non_member_rejected', 'test_prr_plain', '<reject>') THEN fail_count := fail_count + 1; END IF;
    -- Nonexistent role → rejected.
    IF NOT pg_temp._prr_case('prr_7_unknown_role_rejected', 'test_prr_nonexistent', '<reject>') THEN fail_count := fail_count + 1; END IF;

    RAISE NOTICE '';
    IF fail_count > 0 THEN
        RAISE EXCEPTION '% reader pre-request checks failed', fail_count;
    END IF;
    RAISE NOTICE '==> 7 passed, 0 failed (of 7 reader pre-request checks)';
END;
$$;

DO $$
BEGIN
    DROP ROLE IF EXISTS test_prr_app;
    DROP ROLE IF EXISTS test_prr_writer;
    DROP ROLE IF EXISTS test_prr_admin;
    DROP ROLE IF EXISTS test_prr_plain;
END;
$$;
