-- Tests for contextual tuples and conditions (ABAC / time-based authorization).
--
-- Uses its own 'test_contextual' store with a simple model:
--   type user
--   type doc
--     relations
--       define viewer: [user]
--       define editor: [user]

SELECT _test_reset();

-- Setup: create test store with model and seed data (idempotent).
DROP FUNCTION IF EXISTS _test_setup_contextual();
CREATE OR REPLACE FUNCTION _test_setup_contextual() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_contextual'); EXCEPTION WHEN OTHERS THEN NULL; END;

    s := authz.create_store('test_contextual');

    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer'), (s, 'editor');
    PERFORM authz._ensure_tuple_partition(s, 'doc');

    INSERT INTO authz.models
        (store_id, object_type, relation, rule_type,
         computed_relation, tupleset_relation, tupleset_computed)
    VALUES
        (s, authz._t(s, 'doc'), authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL),
        (s, authz._t(s, 'doc'), authz._r(s, 'editor'), authz._rel_direct(), NULL, NULL, NULL);

    INSERT INTO authz.conditions (store_id, name, expression, required_context) VALUES
    (s,
     'non_expired_grant',
     $cond$
        ($1->>'current_time')::timestamptz < ($2->>'grant_time')::timestamptz + ($2->>'grant_duration')::interval
     $cond$,
     '{"request": ["current_time"], "stored": ["grant_time", "grant_duration"]}'::jsonb
    );

    PERFORM authz.write_tuple('test_contextual',
        'user', 'alice', 'viewer', 'doc', 'doc1',
        p_condition => 'non_expired_grant',
        p_condition_context => '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb
    );

    PERFORM authz.write_tuple('test_contextual', 'user', 'bob', 'viewer', 'doc', 'doc1');

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

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_contextual();
DROP FUNCTION IF EXISTS _test_setup_contextual();

SELECT _test_report('checks');
