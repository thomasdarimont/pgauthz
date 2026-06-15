-- Tests for contextual tuples and conditions (ABAC / time-based authorization).
--
-- Uses its own 'test_contextual' store with a simple model:
--   type user
--   type folder
--     relations
--       define viewer: [user]
--   type doc
--     relations
--       define viewer: [user] or viewer from parent
--       define editor: [user]
--       define parent: [folder]

SELECT _test_reset();

-- Setup: create test store with model and seed data (idempotent).
DROP FUNCTION IF EXISTS _test_setup_contextual();
CREATE OR REPLACE FUNCTION _test_setup_contextual() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_contextual'); EXCEPTION WHEN OTHERS THEN NULL; END;

    s := authz.create_store('test_contextual');

    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc'), (s, 'folder');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer'), (s, 'editor'), (s, 'parent');
    PERFORM authz._ensure_tuple_partition(s, 'doc');

    INSERT INTO authz.models
        (store_id, object_type, relation, rule_type,
         computed_relation, tupleset_relation, tupleset_computed)
    VALUES
        (s, authz._t(s, 'doc'),    authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL),
        (s, authz._t(s, 'doc'),    authz._r(s, 'editor'), authz._rel_direct(), NULL, NULL, NULL),
        (s, authz._t(s, 'folder'), authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL),
        -- TTU: doc viewer ← viewer on the folder linked via parent
        (s, authz._t(s, 'doc'),    authz._r(s, 'viewer'), authz._rel_ttu(),
            NULL, authz._r(s, 'parent'), authz._r(s, 'viewer'));

    INSERT INTO authz.conditions (store_id, name, expression, required_context) VALUES
    (s,
     'non_expired_grant',
     $cond$
        ($1->>'current_time')::timestamptz < ($2->>'grant_time')::timestamptz + ($2->>'grant_duration')::interval
     $cond$,
     '{"request": ["current_time"], "stored": ["grant_time", "grant_duration"]}'::jsonb
    ),
    (s,
     'from_allowed_network',
     $cond$
        ($1->>'client_ip')::inet <<= ($2->>'allowed_cidr')::cidr
     $cond$,
     '{"request": ["client_ip"], "stored": ["allowed_cidr"]}'::jsonb
    );

    PERFORM authz.write_tuple('test_contextual',
        'user', 'alice', 'viewer', 'doc', 'doc1',
        p_condition => 'non_expired_grant',
        p_condition_context => '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb
    );

    PERFORM authz.write_tuple('test_contextual', 'user', 'bob', 'viewer', 'doc', 'doc1');

    -- Conditional TTU link: doc2's parent folder link is itself time-limited.
    -- Carol is an unconditional viewer on the folder — her access to doc2
    -- must only be granted while the link's condition holds.
    PERFORM authz.write_tuple('test_contextual',
        'folder', 'f1', 'parent', 'doc', 'doc2',
        p_condition => 'non_expired_grant',
        p_condition_context => '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb
    );
    PERFORM authz.write_tuple('test_contextual', 'user', 'carol', 'viewer', 'folder', 'f1');

    RETURN true;
END;
$$;

-- Teardown: remove test store and return accumulated results.
DROP FUNCTION IF EXISTS _test_teardown_contextual();
CREATE OR REPLACE FUNCTION _test_teardown_contextual()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_contextual');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ================================================================
-- Condition tests (time-based / ABAC)
-- ================================================================

-- ctx_01: alice can view within the grant window
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM _test_assert('ctx_01_alice_view_within_grant_window',
        authz.check_access_with_context('test_contextual',
            'user', 'alice', 'viewer', 'doc', 'doc1',
            '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb
        )::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_02: alice cannot view after the grant expires
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM _test_assert('ctx_02_alice_view_after_grant_expires',
        authz.check_access_with_context('test_contextual',
            'user', 'alice', 'viewer', 'doc', 'doc1',
            '{"current_time": "2026-03-11T12:00:00Z"}'::jsonb
        )::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_03: alice cannot view without providing context (condition fails safely)
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM _test_assert('ctx_03_alice_view_without_context_denied',
        authz.check_access('test_contextual',
            'user', 'alice', 'viewer', 'doc', 'doc1'
        )::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_04: bob can view unconditionally (no condition on his tuple)
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM _test_assert('ctx_04_bob_view_unconditional',
        authz.check_access('test_contextual',
            'user', 'bob', 'viewer', 'doc', 'doc1'
        )::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ================================================================
-- Contextual tuple tests
-- ================================================================

-- ctx_05: frank cannot view doc1 normally
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM _test_assert('ctx_05_frank_view_without_contextual_tuple',
        authz.check_access('test_contextual',
            'user', 'frank', 'viewer', 'doc', 'doc1'
        )::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_06: frank CAN view doc1 with a contextual tuple granting viewer (e.g. as Vacation Substitute)
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM _test_assert('ctx_06_frank_view_with_contextual_tuple',
        authz.check_access_with_contextual_tuples('test_contextual',
            'user', 'frank', 'viewer', 'doc', 'doc1',
            contextual_tuples => ARRAY[
                ROW('user', 'frank', NULL, 'viewer', 'doc', 'doc1')
            ]::authz.tuple_input[]
        )::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_07: the contextual tuple does NOT persist
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM authz.check_access_with_contextual_tuples('test_contextual',
        'user', 'frank', 'viewer', 'doc', 'doc1',
        contextual_tuples => ARRAY[
            ROW('user', 'frank', NULL, 'viewer', 'doc', 'doc1')
        ]::authz.tuple_input[]
    );
    PERFORM _test_assert('ctx_07_contextual_tuple_not_persisted',
        authz.check_access('test_contextual',
            'user', 'frank', 'viewer', 'doc', 'doc1'
        )::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ================================================================
-- Condition validation tests
-- ================================================================

-- ctx_08: validate_condition succeeds with correct context
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM authz.validate_condition('test_contextual',
        'non_expired_grant',
        '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb,
        '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb
    );
    PERFORM _test_assert_true('ctx_08_validate_condition_correct_context', true);
EXCEPTION
    WHEN OTHERS THEN
        PERFORM _test_assert_true('ctx_08_validate_condition_correct_context', false, SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_09: validate_condition rejects missing stored context keys
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_contextual();
DO $$
BEGIN
    PERFORM authz.validate_condition('test_contextual',
        'non_expired_grant',
        '{"grant_time": "2026-03-11T09:00:00Z"}'::jsonb,
        '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb
    );
    PERFORM _test_assert_true('ctx_09_validate_condition_missing_stored_key', false, 'expected error, got success');
EXCEPTION
    WHEN OTHERS THEN
        PERFORM _test_assert_true('ctx_09_validate_condition_missing_stored_key', true);
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_10: validate_condition rejects missing request context keys
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_contextual();
DO $$
BEGIN
    PERFORM authz.validate_condition('test_contextual',
        'non_expired_grant',
        '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb,
        '{}'::jsonb
    );
    PERFORM _test_assert_true('ctx_10_validate_condition_missing_request_key', false, 'expected error, got success');
EXCEPTION
    WHEN OTHERS THEN
        PERFORM _test_assert_true('ctx_10_validate_condition_missing_request_key', true);
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_11: write_tuple rejects missing stored context keys
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_contextual();
DO $$
BEGIN
    PERFORM authz.write_tuple('test_contextual',
        'user', 'alice', 'viewer', 'doc', 'doc2',
        p_condition => 'non_expired_grant',
        p_condition_context => '{"grant_time": "2026-03-11T09:00:00Z"}'::jsonb
    );
    PERFORM _test_assert_true('ctx_11_write_tuple_missing_stored_key', false, 'expected error, got success');
EXCEPTION
    WHEN OTHERS THEN
        PERFORM _test_assert_true('ctx_11_write_tuple_missing_stored_key', true);
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ================================================================
-- Conditions on TTU (tupleset) link tuples
-- ================================================================

-- ctx_12: carol can view doc2 via the parent link within the grant window
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM _test_assert('ctx_12_ttu_conditional_link_within_window',
        authz.check_access_with_context('test_contextual',
            'user', 'carol', 'viewer', 'doc', 'doc2',
            '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb
        )::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_13: carol cannot view doc2 after the link's grant expires
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM _test_assert('ctx_13_ttu_conditional_link_after_expiry',
        authz.check_access_with_context('test_contextual',
            'user', 'carol', 'viewer', 'doc', 'doc2',
            '{"current_time": "2026-03-11T12:00:00Z"}'::jsonb
        )::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_14: carol cannot view doc2 without context (link condition fails safely)
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM _test_assert('ctx_14_ttu_conditional_link_without_context',
        authz.check_access('test_contextual',
            'user', 'carol', 'viewer', 'doc', 'doc2'
        )::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_15/16: time-travel (audit_check_access) honors conditions on TTU links.
-- Uses a grant window relative to now() so the snapshot's reconstructed
-- current_time falls inside / outside the window deterministically.
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM authz.write_tuple('test_contextual',
        'folder', 'f2', 'parent', 'doc', 'doc3',
        p_condition => 'non_expired_grant',
        p_condition_context => jsonb_build_object(
            'grant_time', now(), 'grant_duration', '2 hours')
    );
    PERFORM authz.write_tuple('test_contextual', 'user', 'carol', 'viewer', 'folder', 'f2');

    -- clock_timestamp(), not now(): audit rows are stamped with
    -- clock_timestamp(), which is later than this transaction's now().
    PERFORM _test_assert('ctx_15_audit_ttu_conditional_link_within_window',
        authz.audit_check_access('test_contextual',
            'user', 'carol', 'viewer', 'doc', 'doc3',
            clock_timestamp()
        )::text, 'true');

    PERFORM _test_assert('ctx_16_audit_ttu_conditional_link_after_expiry',
        authz.audit_check_access('test_contextual',
            'user', 'carol', 'viewer', 'doc', 'doc3',
            clock_timestamp() + interval '3 hours'
        )::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_17/18: audit_check_access accepts request context for conditions
-- that need more than the reconstructed current_time (e.g. client IP).
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM authz.write_tuple('test_contextual',
        'user', 'dana', 'viewer', 'doc', 'doc4',
        p_condition => 'from_allowed_network',
        p_condition_context => '{"allowed_cidr": "10.0.0.0/8"}'::jsonb
    );

    -- Without request context the condition cannot pass: fail-safe deny
    PERFORM _test_assert('ctx_17_audit_condition_without_request_context_denied',
        authz.audit_check_access('test_contextual',
            'user', 'dana', 'viewer', 'doc', 'doc4',
            clock_timestamp()
        )::text, 'false');

    -- With request context the past grant is reconstructible
    PERFORM _test_assert('ctx_18_audit_condition_with_request_context_allowed',
        authz.audit_check_access('test_contextual',
            'user', 'dana', 'viewer', 'doc', 'doc4',
            clock_timestamp(),
            p_request_context => '{"client_ip": "10.1.2.3"}'::jsonb
        )::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_19: explain_access annotates a condition_denied step with the
-- condition name and the required context keys that were missing.
-- alice's viewer tuple on doc1 is conditional (non_expired_grant); a
-- check with NO request context is denied because current_time is absent.
DO $$
DECLARE e jsonb; v_step jsonb;
BEGIN
    PERFORM _test_setup_contextual();
    e := authz.explain_access('test_contextual', 'user', 'alice', 'viewer', 'doc', 'doc1');

    SELECT s INTO v_step
      FROM jsonb_array_elements(e->'trace') s
     WHERE s->>'condition_name' IS NOT NULL
     LIMIT 1;

    PERFORM _test_assert('ctx_19a_condition_name_surfaced',
        v_step->>'condition_name', 'non_expired_grant');
    PERFORM _test_assert('ctx_19b_missing_request_key_reported',
        (v_step->'condition_missing_keys' @> '["request.current_time"]'::jsonb)::text, 'true');
    -- stored keys WERE provided on the tuple, so they are not reported missing
    PERFORM _test_assert('ctx_19c_present_stored_keys_not_reported',
        (v_step->'condition_missing_keys' @> '["stored.grant_time"]'::jsonb)::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_contextual();
DROP FUNCTION IF EXISTS _test_setup_contextual();

SELECT _test_report('checks');
