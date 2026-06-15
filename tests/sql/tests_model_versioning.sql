-- Tests for model versioning in time-travel queries.
--
-- audit_check_access / audit_list_actions must resolve rules against the
-- MODEL as it was at p_at, not the current model. The audit log versions
-- tuples AND model rules (authz.models_audit), so a historical check
-- reconstructs both the tuple state and the rule set of that moment.
--
-- Versioning is TRANSACTIONAL: audit rows are stamped with
-- transaction_timestamp(), so every change in one transaction shares one
-- version timestamp and time-travel sees a transaction's effect atomically
-- (never a partial, mid-transaction state). These tests therefore put the
-- "before" and "after" states in SEPARATE transactions (separate DO blocks,
-- since each top-level statement autocommits), capturing the point-in-time
-- marker between them in a session GUC. A create-then-mutate within a single
-- transaction would be atomic and the intermediate state unobservable — see
-- mv_4.

SELECT _test_reset();

-- mv_1: a rule REMOVED in a later transaction must still grant at a marker
-- taken before that transaction — the rule existed then.
--   tx1: store + viewer rule + tuple (the "before" state)
DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_mv'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_mv');
    PERFORM authz.model_register_type('test_mv', 'user');
    PERFORM authz.model_register_type('test_mv', 'doc');
    PERFORM authz.model_register_relation('test_mv', 'viewer');
    PERFORM authz.model_add_rule('test_mv', 'doc', 'viewer', 'direct');
    PERFORM authz.write_tuple('test_mv', 'user', 'alice', 'viewer', 'doc', 'doc1');

    PERFORM _test_assert('mv_1a_live_allowed_before_removal',
        authz.check_access('test_mv', 'user', 'alice', 'viewer', 'doc', 'doc1')::text, 'true');
END;
$$;
--   marker: a moment after tx1 committed, before the removal transaction
SELECT set_config('test.mv1_t1', clock_timestamp()::text, false);
--   tx2: remove the rule (the "after" state)
DO $$
DECLARE
    v_t1      timestamptz := current_setting('test.mv1_t1')::timestamptz;
    v_rule_id smallint;
BEGIN
    SELECT id INTO v_rule_id FROM authz.models
     WHERE store_id    = authz._s('test_mv')
       AND object_type = authz._t('test_mv', 'doc')
       AND relation    = authz._r('test_mv', 'viewer')
       AND rule_type   = authz._rel_direct();
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

-- mv_2: a rule ADDED in a later transaction must NOT grant at a marker taken
-- before it — the rule did not exist then, even though the tuple already did.
--   tx1: store + tuple, but NO editor rule yet
DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_mv'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_mv');
    PERFORM authz.model_register_type('test_mv', 'user');
    PERFORM authz.model_register_type('test_mv', 'doc');
    PERFORM authz.model_register_relation('test_mv', 'editor');
    PERFORM authz.write_tuple('test_mv', 'user', 'bob', 'editor', 'doc', 'doc1');

    PERFORM _test_assert('mv_2a_live_denied_before_rule',
        authz.check_access('test_mv', 'user', 'bob', 'editor', 'doc', 'doc1')::text, 'false');
END;
$$;
SELECT set_config('test.mv2_t0', clock_timestamp()::text, false);
--   tx2: add the editor rule
DO $$
DECLARE v_t0 timestamptz := current_setting('test.mv2_t0')::timestamptz;
BEGIN
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
--   tx1: viewer rule + both tuples
DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_mv'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_mv');
    PERFORM authz.model_register_type('test_mv', 'user');
    PERFORM authz.model_register_type('test_mv', 'doc');
    PERFORM authz.model_register_relation('test_mv', 'viewer');
    PERFORM authz.model_register_relation('test_mv', 'editor');
    PERFORM authz.model_add_rule('test_mv', 'doc', 'viewer', 'direct');
    PERFORM authz.write_tuple('test_mv', 'user', 'alice', 'viewer', 'doc', 'doc1');
    PERFORM authz.write_tuple('test_mv', 'user', 'alice', 'editor', 'doc', 'doc1');
END;
$$;
SELECT set_config('test.mv3_t0', clock_timestamp()::text, false);
--   tx2: add the editor rule
DO $$
DECLARE
    v_t0      timestamptz := current_setting('test.mv3_t0')::timestamptz;
    v_actions text[];
BEGIN
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

-- mv_4: changes made in ONE transaction share a single version timestamp, so
-- time-travel sees a transaction's effect atomically (never a partial,
-- mid-transaction model). performed_at is the transaction time, not the
-- per-statement wall clock.
DO $$
DECLARE v_distinct int;
BEGIN
    BEGIN PERFORM authz.delete_store('test_mv'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_mv');
    PERFORM authz.model_register_type('test_mv', 'user');
    PERFORM authz.model_register_type('test_mv', 'doc');
    PERFORM authz.model_register_relation('test_mv', 'viewer');
    PERFORM authz.model_register_relation('test_mv', 'editor');
    -- Two model-rule changes and two tuple writes, all in this transaction.
    PERFORM authz.model_add_rule('test_mv', 'doc', 'viewer', 'direct');
    PERFORM authz.model_add_rule('test_mv', 'doc', 'editor', 'direct');
    PERFORM authz.write_tuple('test_mv', 'user', 'alice', 'viewer', 'doc', 'doc1');
    PERFORM authz.write_tuple('test_mv', 'user', 'bob',   'editor', 'doc', 'doc1');

    SELECT count(DISTINCT performed_at) INTO v_distinct
      FROM authz.models_audit WHERE store_id = authz._s('test_mv');
    PERFORM _test_assert('mv_4a_model_changes_share_one_timestamp', v_distinct::text, '1');

    SELECT count(DISTINCT performed_at) INTO v_distinct
      FROM authz.tuples_audit WHERE store_id = authz._s('test_mv');
    PERFORM _test_assert('mv_4b_tuple_changes_share_one_timestamp', v_distinct::text, '1');

    PERFORM authz.delete_store('test_mv');
END;
$$;

SELECT _test_report('model versioning checks');
