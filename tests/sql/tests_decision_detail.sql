-- Tests for authz.check_access_detailed — the opt-in rich decision result.
--
-- The boolean API collapses "condition lacked required context" into deny
-- (fail closed); the detailed variant distinguishes state=conditional and
-- names the missing keys, so callers can supply them and re-check.

SELECT _test_reset();

DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_dd');     EXCEPTION WHEN OTHERS THEN NULL; END;
    BEGIN PERFORM authz.delete_store('test_dd_mgd'); EXCEPTION WHEN OTHERS THEN NULL; END;
    DELETE FROM authz.model_registry WHERE name = 'test_dd_model';

    PERFORM authz.create_store('test_dd');
    PERFORM authz.model_register_type('test_dd', 'user');
    PERFORM authz.model_register_type('test_dd', 'doc');
    PERFORM authz.model_register_relation('test_dd', 'viewer');
    PERFORM authz.model_add_rule('test_dd', 'doc', 'viewer', 'direct');
    PERFORM authz.create_condition_sql('test_dd', 'needs_clearance',
        $expr$ ($1->>'clearance') = 'high' $expr$,
        '{"request": ["clearance"]}');

    -- alice: conditional grant; bob: unconditional grant; carol: nothing.
    PERFORM authz.write_tuple('test_dd', 'user', 'alice', 'viewer', 'doc', 'd1',
                              p_condition := 'needs_clearance');
    PERFORM authz.write_tuple('test_dd', 'user', 'bob', 'viewer', 'doc', 'd1');
END;
$$;

DO $$
DECLARE
    d jsonb;
BEGIN
    -- Unconditional allow.
    d := authz.check_access_detailed('test_dd', 'user', 'bob', 'viewer', 'doc', 'd1');
    PERFORM _test_assert('dd_1_allow_state',
        (d->>'decision') || '/' || (d->>'state'), 'true/allow');

    -- No grant at all → plain deny, nothing missing.
    d := authz.check_access_detailed('test_dd', 'user', 'carol', 'viewer', 'doc', 'd1');
    PERFORM _test_assert('dd_2_deny_state',
        (d->>'decision') || '/' || (d->>'state') || '/' || (d->'missing_context')::text,
        'false/deny/[]');

    -- Conditional grant without the required context → CONDITIONAL, with the
    -- missing key and the condition named.
    d := authz.check_access_detailed('test_dd', 'user', 'alice', 'viewer', 'doc', 'd1');
    PERFORM _test_assert('dd_3_conditional_state',
        (d->>'decision') || '/' || (d->>'state'), 'false/conditional');
    -- Keys are namespaced by SOURCE: request.* (caller must supply) vs
    -- stored.* (the tuple's stored context is incomplete).
    PERFORM _test_assert('dd_4_missing_keys',
        (d->'missing_context')::text, '["request.clearance"]');
    PERFORM _test_assert('dd_5_condition_named',
        (d->'conditions')::text, '["needs_clearance"]');

    -- Supplying the context flips it to allow — and the boolean API agrees.
    d := authz.check_access_detailed('test_dd', 'user', 'alice', 'viewer', 'doc', 'd1',
                                     '{"clearance": "high"}');
    PERFORM _test_assert('dd_6_context_allows',
        (d->>'decision') || '/' || (d->>'state'), 'true/allow');
    PERFORM _test_assert('dd_7_boolean_agrees',
        authz.check_access_with_context('test_dd', 'user', 'alice', 'viewer', 'doc', 'd1',
                                        '{"clearance": "high"}')::text, 'true');

    -- Wrong context value → the condition evaluated (nothing missing) and
    -- denied: state=deny, not conditional.
    d := authz.check_access_detailed('test_dd', 'user', 'alice', 'viewer', 'doc', 'd1',
                                     '{"clearance": "low"}');
    PERFORM _test_assert('dd_8_failed_condition_is_deny',
        (d->>'decision') || '/' || (d->>'state') || '/' || (d->'missing_context')::text,
        'false/deny/[]');

    -- Unmanaged store → model is null.
    d := authz.check_access_detailed('test_dd', 'user', 'bob', 'viewer', 'doc', 'd1');
    PERFORM _test_assert('dd_9_unmanaged_model_null',
        (d->'model')::text, 'null');
END;
$$;

-- Registry-managed store → model name/version reported.
DO $$
DECLARE
    d jsonb;
BEGIN
    PERFORM authz.publish_model('test_dd_model', 'test_dd');
    PERFORM authz.create_store('test_dd_mgd');
    PERFORM authz.apply_model('test_dd_mgd', 'test_dd_model');
    PERFORM authz.write_tuple('test_dd_mgd', 'user', 'eve', 'viewer', 'doc', 'd9');

    d := authz.check_access_detailed('test_dd_mgd', 'user', 'eve', 'viewer', 'doc', 'd9');
    PERFORM _test_assert('dd_10_managed_model_reported',
        (d->'model'->>'name') || '@' || (d->'model'->>'version') || '/' || (d->>'state'),
        'test_dd_model@1/allow');
END;
$$;

DO $$
BEGIN
    PERFORM authz.delete_store('test_dd');
    PERFORM authz.delete_store('test_dd_mgd');
    DELETE FROM authz.model_registry WHERE name = 'test_dd_model';
END;
$$;

SELECT _test_report('decision detail');
