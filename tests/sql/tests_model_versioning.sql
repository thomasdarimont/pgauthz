-- Tests for model versioning in time-travel queries.
--
-- audit_check_access / audit_list_actions must resolve rules against the
-- MODEL as it was at p_at, not the current model. The audit log versions
-- tuples AND model rules (authz.models_audit), so a historical check
-- reconstructs both the tuple state and the rule set of that moment.
--
-- Uses its own 'test_mv' store. clock_timestamp() (not now()) marks
-- points in time, because audit rows are stamped with clock_timestamp(),
-- which advances within the transaction.

SELECT _test_reset();

-- mv_1: a rule REMOVED after T must still grant at T — the rule existed then.
DO $$
DECLARE
    v_rule_id smallint;
    v_t1      timestamptz;
BEGIN
    BEGIN PERFORM authz.delete_store('test_mv'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_mv');
    PERFORM authz.model_register_type('test_mv', 'user');
    PERFORM authz.model_register_type('test_mv', 'doc');
    PERFORM authz.model_register_relation('test_mv', 'viewer');
    v_rule_id := authz.model_add_rule('test_mv', 'doc', 'viewer', 'direct');
    PERFORM authz.write_tuple('test_mv', 'user', 'alice', 'viewer', 'doc', 'doc1');

    -- Marker while the viewer rule AND the tuple both exist.
    v_t1 := clock_timestamp();

    PERFORM _test_assert('mv_1a_live_allowed_before_removal',
        authz.check_access('test_mv', 'user', 'alice', 'viewer', 'doc', 'doc1')::text, 'true');

    -- Remove the viewer rule.
    PERFORM authz.model_remove_rule('test_mv', v_rule_id);

    PERFORM _test_assert('mv_1b_live_denied_after_removal',
        authz.check_access('test_mv', 'user', 'alice', 'viewer', 'doc', 'doc1')::text, 'false');

    -- Time-travel to t1: the rule existed then, so access is granted.
    PERFORM _test_assert('mv_1c_historical_allowed_at_t1',
        authz.audit_check_access('test_mv', 'user', 'alice', 'viewer', 'doc', 'doc1', v_t1)::text, 'true');

    -- Time-travel to now: the rule is gone, access denied.
    PERFORM _test_assert('mv_1d_historical_denied_now',
        authz.audit_check_access('test_mv', 'user', 'alice', 'viewer', 'doc', 'doc1', clock_timestamp())::text, 'false');

    PERFORM authz.delete_store('test_mv');
END;
$$;

-- mv_2: a rule ADDED after T must NOT grant at T — the rule did not exist
-- then, even though the tuple already did. This is the core leak: a current
-- rule must not be back-applied to a historical check.
DO $$
DECLARE
    v_t0 timestamptz;
BEGIN
    BEGIN PERFORM authz.delete_store('test_mv'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_mv');
    PERFORM authz.model_register_type('test_mv', 'user');
    PERFORM authz.model_register_type('test_mv', 'doc');
    PERFORM authz.model_register_relation('test_mv', 'editor');

    -- The tuple exists from the start; the editor RULE does not yet.
    PERFORM authz.write_tuple('test_mv', 'user', 'bob', 'editor', 'doc', 'doc1');
    v_t0 := clock_timestamp();

    PERFORM _test_assert('mv_2a_live_denied_before_rule',
        authz.check_access('test_mv', 'user', 'bob', 'editor', 'doc', 'doc1')::text, 'false');

    -- Add the editor rule now (after t0).
    PERFORM authz.model_add_rule('test_mv', 'doc', 'editor', 'direct');

    PERFORM _test_assert('mv_2b_live_allowed_after_rule',
        authz.check_access('test_mv', 'user', 'bob', 'editor', 'doc', 'doc1')::text, 'true');

    -- Time-travel to t0: the rule did not exist then -> denied.
    PERFORM _test_assert('mv_2c_historical_denied_at_t0',
        authz.audit_check_access('test_mv', 'user', 'bob', 'editor', 'doc', 'doc1', v_t0)::text, 'false');

    PERFORM authz.delete_store('test_mv');
END;
$$;

-- mv_3: audit_list_actions enumerates candidate relations from the historical
-- model, so a relation whose rule was added after T is not listed at T.
DO $$
DECLARE
    v_t0      timestamptz;
    v_actions text[];
BEGIN
    BEGIN PERFORM authz.delete_store('test_mv'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_mv');
    PERFORM authz.model_register_type('test_mv', 'user');
    PERFORM authz.model_register_type('test_mv', 'doc');
    PERFORM authz.model_register_relation('test_mv', 'viewer');
    PERFORM authz.model_register_relation('test_mv', 'editor');
    PERFORM authz.model_add_rule('test_mv', 'doc', 'viewer', 'direct');
    -- Both tuples exist from the start; only the viewer rule does.
    PERFORM authz.write_tuple('test_mv', 'user', 'alice', 'viewer', 'doc', 'doc1');
    PERFORM authz.write_tuple('test_mv', 'user', 'alice', 'editor', 'doc', 'doc1');
    v_t0 := clock_timestamp();

    -- Add the editor rule AFTER t0.
    PERFORM authz.model_add_rule('test_mv', 'doc', 'editor', 'direct');

    SELECT array_agg(action ORDER BY action) INTO v_actions
      FROM authz.audit_list_actions('test_mv', 'user', 'alice', 'doc', 'doc1', v_t0);

    -- At t0 only 'viewer' had a rule; 'editor' must not appear.
    PERFORM _test_assert('mv_3a_historical_actions_has_viewer',
        (v_actions @> ARRAY['viewer'])::text, 'true');
    PERFORM _test_assert('mv_3b_historical_actions_excludes_editor',
        (v_actions @> ARRAY['editor'])::text, 'false');

    PERFORM authz.delete_store('test_mv');
END;
$$;

SELECT _test_report('model versioning checks');
