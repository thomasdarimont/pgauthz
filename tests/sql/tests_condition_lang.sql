-- Unit tests for the condition language discriminator (authz.conditions.lang).
--
-- Today only 'sql' is permitted. These checks lock in:
--   - the 'sql' default and explicit acceptance
--   - audit fidelity (conditions_audit records lang)
--   - rejection of other languages (cel/cedar/…) at write time
--   - that the dispatcher (_eval_condition_expr) routes 'sql' conditions
--     correctly at check time, via the public validator, and in time-travel
--     snapshots
--
-- When a real executor is added later (cel, cedar, rego, …) widen the CHECK
-- on authz.conditions.lang and add a branch to authz._eval_condition_expr;
-- cl_04/cl_05 then become positive tests for that language.

SELECT _test_reset();

DO $$
DECLARE
    s        smallint;
    v_lang   text;
    v_ok     boolean;
    v_threw  boolean;
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
    PERFORM _test_assert_true('cl_01_default_lang_is_sql', v_lang = 'sql', 'lang=' || v_lang);

    -- cl_02: explicit lang='sql' is accepted
    INSERT INTO authz.conditions (store_id, name, expression, lang) VALUES
        (s, 'always_true', $cond$ true $cond$, 'sql');
    SELECT lang INTO v_lang FROM authz.conditions WHERE store_id = s AND name = 'always_true';
    PERFORM _test_assert_true('cl_02_explicit_sql_accepted', v_lang = 'sql', 'lang=' || v_lang);

    -- cl_03: the audit log records the condition's lang
    SELECT lang INTO v_lang FROM authz.conditions_audit
     WHERE store_id = s AND name = 'not_expired' AND action = 'INSERT'
     ORDER BY seq DESC LIMIT 1;
    PERFORM _test_assert_true('cl_03_audit_records_lang', v_lang = 'sql',
        'audit lang=' || coalesce(v_lang, '<null>'));

    -- cl_04: lang='cel' is rejected (no executor yet)
    v_threw := false;
    BEGIN
        INSERT INTO authz.conditions (store_id, name, expression, lang) VALUES
            (s, 'c_cel', $cond$ true $cond$, 'cel');
    EXCEPTION WHEN OTHERS THEN v_threw := true; END;
    PERFORM _test_assert_true('cl_04_cel_rejected', v_threw);

    -- cl_05: lang='cedar' is rejected (no executor yet)
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

    PERFORM authz.delete_store('test_condlang');
END;
$$;

SELECT _test_report('condition lang checks');
