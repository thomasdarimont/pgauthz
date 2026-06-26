-- Unit tests for the condition language discriminator (authz.conditions.lang).
--
-- 'sql' is built in; 'cel' is allowed when the optional evaluator extension
-- (authz.cel_eval_bool, e.g. extensions/pg-cel) is installed. These checks
-- lock in:
--   - the 'sql' default and explicit acceptance
--   - audit fidelity (conditions_audit records lang)
--   - that lang='cel' is gated on the evaluator being present (rejected
--     without it, accepted with it) and that an unsupported lang is rejected
--   - that the dispatcher (_eval_condition_expr) routes both 'sql' and 'cel'
--     conditions correctly at check time, via the validator, and in snapshots
--
-- The CEL end-to-end checks (cl_09/cl_10) run only when the evaluator is
-- installed; otherwise they are skipped so the default stack stays green.

SELECT _test_reset();

DO $$
DECLARE
    s        smallint;
    v_lang   text;
    v_ok     boolean;
    v_threw  boolean;
    v_id     smallint;
    v_id2    smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_condlang'); EXCEPTION WHEN OTHERS THEN NULL; END;
    s := authz.create_store('test_condlang');

    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer'), (s, 'can_read');
    PERFORM authz._ensure_tuple_partition(s, 'doc');

    --   doc#viewer   = direct
    --   doc#can_read = computed(viewer)
    INSERT INTO authz.models
        (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed)
    VALUES
        (s, authz._t(s,'doc'), authz._r(s,'viewer'),   authz._rel_direct(),   NULL, NULL, NULL),
        (s, authz._t(s,'doc'), authz._r(s,'can_read'), authz._rel_computed(), authz._r(s,'viewer'), NULL, NULL);

    -- cl_01: lang defaults to 'sql' when omitted
    INSERT INTO authz.conditions (store_id, name, expression, required_context) VALUES
        (s, 'not_expired',
         $cond$($1->>'current_time')::timestamptz < ($2->>'expires')::timestamptz$cond$,
         '{"request": ["current_time"], "stored": ["expires"]}'::jsonb);
    SELECT lang INTO v_lang FROM authz.conditions WHERE store_id = s AND name = 'not_expired';
    PERFORM _test_assert_true('cl_01_default_lang_is_sql', v_lang = authz._cond_lang_sql(), 'lang=' || v_lang);

    -- cl_02: explicit lang='sql' is accepted
    INSERT INTO authz.conditions (store_id, name, expression, lang) VALUES
        (s, 'always_true', $cond$ true $cond$, authz._cond_lang_sql());
    SELECT lang INTO v_lang FROM authz.conditions WHERE store_id = s AND name = 'always_true';
    PERFORM _test_assert_true('cl_02_explicit_sql_accepted', v_lang = authz._cond_lang_sql(), 'lang=' || v_lang);

    -- cl_03: the audit log records the condition's lang
    SELECT lang INTO v_lang FROM authz.conditions_audit
     WHERE store_id = s AND name = 'not_expired' AND action = 'INSERT'
     ORDER BY seq DESC LIMIT 1;
    PERFORM _test_assert_true('cl_03_audit_records_lang', v_lang = authz._cond_lang_sql(),
        'audit lang=' || coalesce(v_lang, '<null>'));

    -- cl_04: lang='cel' acceptance is gated on a CEL evaluator being present.
    -- Without the optional extension a write must be rejected (fail-closed);
    -- with it, the expression compiles and is stored. Either way the engine
    -- never silently stores a condition it cannot evaluate.
    v_threw := false;
    BEGIN
        INSERT INTO authz.conditions (store_id, name, expression, lang) VALUES
            (s, 'c_cel', $cond$ request.ok $cond$, authz._cond_lang_cel());
    EXCEPTION WHEN OTHERS THEN v_threw := true; END;
    IF to_regprocedure('authz.cel_eval_bool(text, text)') IS NULL THEN
        PERFORM _test_assert_true('cl_04_cel_rejected_without_evaluator', v_threw,
            'no evaluator installed');
    ELSE
        PERFORM _test_assert_true('cl_04_cel_accepted_with_evaluator', NOT v_threw,
            'evaluator installed');
    END IF;

    -- cl_05: lang='cedar' is always rejected (not in the CHECK set, no executor)
    v_threw := false;
    BEGIN
        INSERT INTO authz.conditions (store_id, name, expression, lang) VALUES
            (s, 'c_cedar', $cond$ true $cond$, 'cedar');
    EXCEPTION WHEN OTHERS THEN v_threw := true; END;
    PERFORM _test_assert_true('cl_05_cedar_rejected', v_threw);

    -- Conditional grant: alice is viewer on doc:d1 only until 'expires'.
    PERFORM authz.write_tuple('test_condlang',
        'user', 'alice', 'viewer', 'doc', 'd1',
        p_condition => 'not_expired',
        p_condition_context => '{"expires": "2099-01-01T00:00:00Z"}'::jsonb);

    -- cl_06: dispatcher evaluates the 'sql' condition true within the window
    v_ok := authz.check_access_with_context('test_condlang',
        'user', 'alice', 'can_read', 'doc', 'd1',
        '{"current_time": "2026-01-01T00:00:00Z"}'::jsonb);
    PERFORM _test_assert_true('cl_06_sql_condition_allows_in_window', v_ok);

    -- cl_07: dispatcher evaluates the 'sql' condition false after expiry
    v_ok := authz.check_access_with_context('test_condlang',
        'user', 'alice', 'can_read', 'doc', 'd1',
        '{"current_time": "2100-01-01T00:00:00Z"}'::jsonb);
    PERFORM _test_assert_true('cl_07_sql_condition_denies_after_expiry', NOT v_ok);

    -- cl_08: public validate_condition routes through the dispatcher too
    v_ok := authz.validate_condition('test_condlang', 'not_expired',
        '{"expires": "2099-01-01T00:00:00Z"}'::jsonb,
        '{"current_time": "2026-01-01T00:00:00Z"}'::jsonb);
    PERFORM _test_assert_true('cl_08_validate_condition_ok', v_ok);

    -- cl_09/cl_10: CEL end-to-end, only when a CEL evaluator is installed
    -- (e.g. the extensions/pg-cel build). Skipped — not failed — otherwise, so
    -- the default dependency-free stack stays green.
    IF to_regprocedure('authz.cel_eval_bool(text, text)') IS NOT NULL THEN
        INSERT INTO authz.conditions (store_id, name, expression, lang, required_context) VALUES
            (s, 'cel_not_expired',
             $cel$timestamp(request.current_time) < timestamp(stored.expires)$cel$,
             authz._cond_lang_cel(),
             '{"request": ["current_time"], "stored": ["expires"]}'::jsonb);

        PERFORM authz.write_tuple('test_condlang',
            'user', 'bob', 'viewer', 'doc', 'd2',
            p_condition => 'cel_not_expired',
            p_condition_context => '{"expires": "2099-01-01T00:00:00Z"}'::jsonb);

        v_ok := authz.check_access_with_context('test_condlang',
            'user', 'bob', 'can_read', 'doc', 'd2',
            '{"current_time": "2026-01-01T00:00:00Z"}'::jsonb);
        PERFORM _test_assert_true('cl_09_cel_condition_allows_in_window', v_ok);

        v_ok := authz.check_access_with_context('test_condlang',
            'user', 'bob', 'can_read', 'doc', 'd2',
            '{"current_time": "2100-01-01T00:00:00Z"}'::jsonb);
        PERFORM _test_assert_true('cl_10_cel_condition_denies_after_expiry', NOT v_ok);

        -- cl_15..cl_17: CEL duration() wants a Go-style unit ("2h"); a Postgres
        -- interval ("2 hours") is NOT caught at write (parse-only) — it fails at
        -- evaluation. validate_condition surfaces it; the real check path
        -- swallows it to a deny (fail closed).
        PERFORM authz.create_condition_cel('test_condlang', 'cel_window',
            'timestamp(request.now) < timestamp(stored.start) + duration(stored.dur)',
            '{"request": ["now"], "stored": ["start", "dur"]}'::jsonb);

        -- cl_15: a valid CEL duration unit validates fine
        PERFORM _test_assert_true('cl_15_cel_duration_valid_unit',
            authz.validate_condition('test_condlang', 'cel_window',
                '{"start": "2026-01-01T00:00:00Z", "dur": "2h"}'::jsonb,
                '{"now": "2026-01-01T00:30:00Z"}'::jsonb));

        -- cl_16: validate_condition raises on the Postgres-style "2 hours"
        v_threw := false;
        BEGIN
            PERFORM authz.validate_condition('test_condlang', 'cel_window',
                '{"start": "2026-01-01T00:00:00Z", "dur": "2 hours"}'::jsonb,
                '{"now": "2026-01-01T00:30:00Z"}'::jsonb);
        EXCEPTION WHEN OTHERS THEN v_threw := true; END;
        PERFORM _test_assert_true('cl_16_cel_duration_invalid_unit_raises', v_threw);

        -- cl_17: the same bad value on a real tuple denies (fail closed), it does
        -- not error the check_access call
        PERFORM authz.write_tuple('test_condlang',
            'user', 'carol', 'viewer', 'doc', 'd3',
            p_condition => 'cel_window',
            p_condition_context => '{"start": "2026-01-01T00:00:00Z", "dur": "2 hours"}'::jsonb);
        v_ok := authz.check_access_with_context('test_condlang',
            'user', 'carol', 'can_read', 'doc', 'd3',
            '{"now": "2026-01-01T00:30:00Z"}'::jsonb);
        PERFORM _test_assert_true('cl_17_cel_bad_duration_denies_fail_closed', NOT v_ok);
    ELSE
        RAISE NOTICE '    SKIP  cl_09/cl_10/cl_15-17 CEL e2e (no cel_eval_bool evaluator installed)';
    END IF;

    -- cl_11: create_condition / create_condition_sql create a sql condition
    -- and return its id (no direct table INSERT needed).
    v_id := authz.create_condition_sql('test_condlang', 'api_cond',
        $cond$($1->>'n')::int > 0$cond$, '{"request": ["n"]}'::jsonb);
    SELECT lang INTO v_lang FROM authz.conditions WHERE store_id = s AND name = 'api_cond';
    PERFORM _test_assert_true('cl_11_create_condition_sql', v_id IS NOT NULL AND v_lang = authz._cond_lang_sql(),
        'id=' || coalesce(v_id::text, '<null>') || ' lang=' || v_lang);

    -- cl_12: create_condition upserts — same name returns the same id, and the
    -- expression is updated in place.
    v_id2 := authz.create_condition('test_condlang', 'api_cond',
        $cond$($1->>'n')::int > 10$cond$, authz._cond_lang_sql(), '{"request": ["n"]}'::jsonb);
    SELECT expression INTO v_lang FROM authz.conditions WHERE id = v_id2;  -- reuse v_lang as scratch
    PERFORM _test_assert_true('cl_12_create_condition_upsert',
        v_id2 = v_id AND v_lang LIKE '%> 10%', 'id=' || v_id2::text);

    -- cl_13: delete_condition returns true the first time, false the second.
    PERFORM _test_assert_true('cl_13_delete_condition_true',
        authz.delete_condition('test_condlang', 'api_cond'));
    PERFORM _test_assert_true('cl_13b_delete_condition_absent_false',
        NOT authz.delete_condition('test_condlang', 'api_cond'));

    -- cl_14: create_condition_cel is gated on the evaluator, like a raw write.
    v_threw := false;
    BEGIN
        v_id := authz.create_condition_cel('test_condlang', 'api_cel',
            'request.n > 0', '{"request": ["n"]}'::jsonb);
    EXCEPTION WHEN OTHERS THEN v_threw := true; END;
    IF to_regprocedure('authz.cel_eval_bool(text, text)') IS NULL THEN
        PERFORM _test_assert_true('cl_14_create_condition_cel_rejected_without_evaluator', v_threw);
    ELSE
        SELECT lang INTO v_lang FROM authz.conditions WHERE store_id = s AND name = 'api_cel';
        PERFORM _test_assert_true('cl_14_create_condition_cel_accepted_with_evaluator',
            NOT v_threw AND v_lang = authz._cond_lang_cel());
    END IF;

    PERFORM authz.delete_store('test_condlang');
END;
$$;

SELECT _test_report('condition lang checks');
