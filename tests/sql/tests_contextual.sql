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
    -- the suite pins the clock from the request context for this condition
    UPDATE authz.conditions SET time_source = 'caller' WHERE store_id = s AND name = 'non_expired_grant';

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

-- ctx_20: write_tuple with an unknown condition raises a clear, named error
-- naming the condition and store — not the opaque "query returned no rows"
-- that a bare INTO STRICT miss would produce.
DO $$
DECLARE v_msg text; v_raised boolean := false;
BEGIN
    PERFORM _test_setup_contextual();
    BEGIN
        PERFORM authz.write_tuple('test_contextual',
            'user', 'bob', 'viewer', 'doc', 'doc1',
            p_condition => 'no_such_condition',
            p_condition_context => '{}'::jsonb);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
        v_msg := SQLERRM;
    END;
    PERFORM _test_assert('ctx_20a_unknown_condition_raises', v_raised::text, 'true');
    PERFORM _test_assert('ctx_20b_message_names_condition',
        (v_msg LIKE '%Unknown condition%no_such_condition%')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_21: condition expression versioning — editing a condition's expression
-- in a LATER transaction must NOT rewrite historical answers. Time-travel
-- evaluates the expression in effect at p_at, reconstructed from
-- conditions_audit. Versioning is transactional, so the original grant and
-- the edit are in separate transactions with the marker captured between
-- (an in-place edit in the SAME transaction would be atomic — unobservable).
--   tx1: permissive condition + a grant that uses it
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    INSERT INTO authz.conditions (store_id, name, expression, required_context)
    VALUES (authz._s('test_contextual'), 'always', 'true', NULL);
    PERFORM authz.write_tuple('test_contextual',
        'user', 'zoe', 'viewer', 'doc', 'doc1', p_condition => 'always');

    PERFORM _test_assert('ctx_21a_live_allowed_before_edit',
        authz.check_access('test_contextual','user','zoe','viewer','doc','doc1')::text, 'true');
END;
$$;
SELECT set_config('test.ctx21_t1', clock_timestamp()::text, false);
--   tx2: tighten the condition in place to always-false
DO $$
DECLARE v_t1 timestamptz := current_setting('test.ctx21_t1')::timestamptz;
BEGIN
    UPDATE authz.conditions SET expression = 'false'
     WHERE store_id = authz._s('test_contextual') AND name = 'always';

    PERFORM _test_assert('ctx_21b_live_denied_after_edit',
        authz.check_access('test_contextual','user','zoe','viewer','doc','doc1')::text, 'false');

    -- Time-travel to t1: the old expression ('true') was in effect -> allowed.
    PERFORM _test_assert('ctx_21c_historical_uses_old_expression',
        authz.audit_check_access('test_contextual','user','zoe','viewer','doc','doc1', v_t1)::text, 'true');

    -- Time-travel to now: the new expression ('false') is in effect -> denied.
    PERFORM _test_assert('ctx_21d_historical_uses_new_expression',
        authz.audit_check_access('test_contextual','user','zoe','viewer','doc','doc1', clock_timestamp())::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_22: a condition whose expression cannot compile (a syntax/resolution
-- error) is rejected at write time, rather than stored and silently failing
-- closed at every check. Valid expressions still insert; data-dependent
-- runtime errors are NOT rejected (they remain deny-at-check).
DO $$
DECLARE v_raised boolean; v_msg text; v_ok boolean;
BEGIN
    PERFORM _test_setup_contextual();

    -- Syntactically invalid expression -> rejected, message names the condition.
    v_raised := false;
    BEGIN
        INSERT INTO authz.conditions (store_id, name, expression, required_context)
        VALUES (authz._s('test_contextual'), 'bad', '1 +', NULL);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true; v_msg := SQLERRM;
    END;
    PERFORM _test_assert('ctx_22a_invalid_expression_rejected', v_raised::text, 'true');
    PERFORM _test_assert('ctx_22b_error_names_condition',
        (v_msg LIKE '%bad%')::text, 'true');

    -- A valid expression still inserts fine.
    v_ok := false;
    BEGIN
        INSERT INTO authz.conditions (store_id, name, expression, required_context)
        VALUES (authz._s('test_contextual'), 'good', '($1->>''level'')::int >= 5', '{"request":["level"]}'::jsonb);
        v_ok := true;
    EXCEPTION WHEN OTHERS THEN v_ok := false;
    END;
    PERFORM _test_assert('ctx_22c_valid_expression_accepted', v_ok::text, 'true');

    -- Editing a valid condition to garbage is rejected too.
    v_raised := false;
    BEGIN
        UPDATE authz.conditions SET expression = '1 +'
         WHERE store_id = authz._s('test_contextual') AND name = 'good';
    EXCEPTION WHEN OTHERS THEN v_raised := true;
    END;
    PERFORM _test_assert('ctx_22d_invalid_update_rejected', v_raised::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_23: a condition whose evaluation exceeds statement_timeout aborts the
-- check (the cancel propagates) rather than being swallowed into a silent
-- deny — so an operator-configured statement_timeout actually bounds (and
-- fail-closes) condition evaluation. The slow expression uses heavy compute
-- (not pg_sleep, which the sandbox can no longer call) and only triggers when
-- the request context asks for it, so write-time validation stays fast.
SELECT _test_setup_contextual();
DO $$
BEGIN
    INSERT INTO authz.conditions (store_id, name, expression, required_context)
    VALUES (authz._s('test_contextual'), 'slow',
            'CASE WHEN ($1->>''go'') = ''yes'' THEN (SELECT count(*) FROM generate_series(1, 2000000000)) >= 0 ELSE true END',
            NULL);
    PERFORM authz.write_tuple('test_contextual', 'user', 'zoe', 'viewer', 'doc', 'doc1', p_condition => 'slow');
END;
$$;
SET statement_timeout = '300ms';   -- armed for the next top-level statement
DO $$
BEGIN
    BEGIN
        PERFORM authz.check_access_with_context('test_contextual', 'user', 'zoe', 'viewer', 'doc', 'doc1',
            '{"go": "yes"}'::jsonb);
        PERFORM _test_assert_true('ctx_23_condition_timeout_aborts', false,
            'expected query_canceled, got completion');
    EXCEPTION WHEN query_canceled THEN
        PERFORM _test_assert_true('ctx_23_condition_timeout_aborts', true);
    END;
END;
$$;
RESET statement_timeout;
SELECT * FROM _test_teardown_contextual();

-- ctx_24: the condition sandbox role (authz_eval) cannot call pg_sleep — it is
-- revoked from PUBLIC, so a hang-via-pg_sleep expression is blocked outright
-- (defense in depth alongside statement_timeout).
DO $$
DECLARE v_state text;
BEGIN
    BEGIN
        SET ROLE authz_eval;
        PERFORM pg_sleep(0);
        RESET ROLE;
        PERFORM _test_assert_true('ctx_24_sandbox_cannot_pg_sleep', false,
            'expected permission denied');
    EXCEPTION WHEN OTHERS THEN
        v_state := SQLSTATE;
        PERFORM _test_assert_true('ctx_24_sandbox_cannot_pg_sleep',
            v_state = '42501', 'sqlstate=' || v_state);
    END;
    RESET ROLE;
END;
$$;

-- ctx_25: write_tuples_jsonb carries conditions per element — conditional
-- elements (with a "condition" key) are routed to write_tuple, which validates
-- the condition name + its stored-context keys; unconditional elements take the
-- set-based path. Regression guard for batch conditional writes (the jsonb API
-- used by HTTP/Go callers); the composite-array write_tuples() has no condition
-- fields, so this is the supported way to batch conditional grants.
DO $$
BEGIN
    PERFORM _test_setup_contextual();

    PERFORM authz.write_tuples_jsonb('test_contextual', $j$[
      {"user_type":"user","user_id":"erin","relation":"viewer","object_type":"doc","object_id":"batch_doc"},
      {"user_type":"user","user_id":"dave","relation":"viewer","object_type":"doc","object_id":"batch_doc",
       "condition":"non_expired_grant",
       "condition_context":{"grant_time":"2026-03-11T09:00:00Z","grant_duration":"2 hours"}}
    ]$j$::jsonb);

    -- unconditional element granted
    PERFORM _test_assert('ctx_25a_batch_unconditional_granted',
        authz.check_access('test_contextual','user','erin','viewer','doc','batch_doc')::text, 'true');

    -- conditional element carried its condition: allowed within the grant window
    PERFORM _test_assert('ctx_25b_batch_conditional_within_window',
        authz.check_access_with_context('test_contextual','user','dave','viewer','doc','batch_doc',
            '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb)::text, 'true');

    -- ...and denied after it — proves the condition was actually attached, not
    -- written as a plain (unconditional) grant
    PERFORM _test_assert('ctx_25c_batch_conditional_after_window',
        authz.check_access_with_context('test_contextual','user','dave','viewer','doc','batch_doc',
            '{"current_time": "2026-03-11T12:00:00Z"}'::jsonb)::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- Cleanup file-level functions
-- ctx_26: condition time source (migration 0016) — `server` conditions read the
-- engine's clock for current_time, ignoring (or not needing) the caller's value;
-- `caller` conditions keep today's behaviour. The choice is versioned, replayed
-- by time travel, exported by the registry and rendered by describe/explain.
DO $$
DECLARE v_msg text; v_n0 int; v_n1 int; d jsonb; e text;
BEGIN
    PERFORM _test_setup_contextual();
    -- same expression, two clocks
    PERFORM authz.create_condition_sql('test_contextual', 'after_2000_caller',
        $c$ ($1->>'current_time')::timestamptz > '2000-01-01' $c$, '{"request": ["current_time"]}', p_time_source => 'caller');
    PERFORM authz.create_condition_sql('test_contextual', 'after_2000_server',
        $c$ ($1->>'current_time')::timestamptz > '2000-01-01' $c$, '{"request": ["current_time"]}',
        p_time_source => 'server');
    PERFORM authz.create_condition_sql('test_contextual', 'before_2000_server',
        $c$ ($1->>'current_time')::timestamptz < '2000-01-01' $c$, '{"request": ["current_time"]}',
        p_time_source => 'server');
    PERFORM authz.write_tuple('test_contextual', 'user', 'tc1', 'viewer', 'doc', 'doc1', p_condition => 'after_2000_caller');
    PERFORM authz.write_tuple('test_contextual', 'user', 'tc2', 'viewer', 'doc', 'doc1', p_condition => 'after_2000_server');
    PERFORM authz.write_tuple('test_contextual', 'user', 'tc3', 'viewer', 'doc', 'doc1', p_condition => 'before_2000_server');

    -- a) the caller's clock is honoured for a caller condition …
    PERFORM _test_assert('ctx_26a_caller_time_honoured',
        authz.check_access_with_context('test_contextual','user','tc1','viewer','doc','doc1','{"current_time": "1999-06-01T00:00:00Z"}')::text, 'false');
    -- b) … and ignored for a server condition (the server is past 2000)
    PERFORM _test_assert('ctx_26b_server_time_ignores_caller_claim',
        authz.check_access_with_context('test_contextual','user','tc2','viewer','doc','doc1','{"current_time": "1999-06-01T00:00:00Z"}')::text, 'true');
    PERFORM _test_assert('ctx_26c_server_time_cannot_be_backdated',
        authz.check_access_with_context('test_contextual','user','tc3','viewer','doc','doc1','{"current_time": "1999-06-01T00:00:00Z"}')::text, 'false');
    -- d) a server condition needs no current_time from the caller: not missing, not conditional
    PERFORM _test_assert('ctx_26d_server_time_needs_no_caller_key',
        authz.check_access('test_contextual','user','tc2','viewer','doc','doc1')::text, 'true');
    d := authz.check_access_detailed('test_contextual','user','tc3','viewer','doc','doc1');
    PERFORM _test_assert('ctx_26e_server_time_never_conditional', (d->>'state') || ' ' || (d->'missing_context')::text, 'deny []');
    -- the caller condition without the key stays conditional (unchanged behaviour)
    PERFORM _test_assert('ctx_26f_caller_time_still_conditional',
        authz.check_access_detailed('test_contextual','user','tc1','viewer','doc','doc1')->>'state', 'conditional');
    -- g) explain names the clock on the denied step
    SELECT x->>'detail' INTO e FROM jsonb_array_elements(
        authz.explain_access('test_contextual','user','tc3','viewer','doc','doc1')->'trace') x
     WHERE x->>'condition_name' = 'before_2000_server' LIMIT 1;
    PERFORM _test_assert_true('ctx_26g_explain_names_server_time', e LIKE '%before_2000_server (server time)%denied', e);
    -- h) invalid source rejected
    BEGIN
        PERFORM authz.create_condition_sql('test_contextual', 'bad_src', 'true', NULL, p_time_source => 'moon');
        v_msg := 'no error';
    EXCEPTION WHEN OTHERS THEN v_msg := SQLERRM; END;
    PERFORM _test_assert_true('ctx_26h_invalid_source_rejected', v_msg LIKE '%time_source must be caller or server%', v_msg);
    -- i) changing the clock is a versioned change (DELETE + INSERT in the audit)
    SELECT count(*) INTO v_n0 FROM authz.conditions_audit a JOIN authz.conditions c ON c.id = a.condition_id
     WHERE c.store_id = authz._s('test_contextual') AND c.name = 'after_2000_caller';
    PERFORM authz.create_condition_sql('test_contextual', 'after_2000_caller',
        $c$ ($1->>'current_time')::timestamptz > '2000-01-01' $c$, '{"request": ["current_time"]}', p_time_source => 'server');
    SELECT count(*) INTO v_n1 FROM authz.conditions_audit a JOIN authz.conditions c ON c.id = a.condition_id
     WHERE c.store_id = authz._s('test_contextual') AND c.name = 'after_2000_caller';
    PERFORM _test_assert('ctx_26i_clock_change_is_versioned', (v_n1 - v_n0)::text, '2');
    PERFORM _test_assert('ctx_26j_switched_condition_now_server',
        authz.check_access_with_context('test_contextual','user','tc1','viewer','doc','doc1','{"current_time": "1999-06-01T00:00:00Z"}')::text, 'true');
    -- k) export carries time_source only for server conditions; describe renders both clocks
    PERFORM _test_assert('ctx_26k_export_marks_server_only',
        (SELECT string_agg(c->>'name' || ':' || COALESCE(c->>'time_source', '-'), ' ' ORDER BY c->>'name')
           FROM jsonb_array_elements(authz.export_model('test_contextual')->'conditions') c
          WHERE c->>'name' LIKE '%2000%'),
        'after_2000_caller:server after_2000_server:server before_2000_server:server');
    PERFORM _test_assert_true('ctx_26l_describe_renders_clock',
        position('# condition before_2000_server (sql, server time)' in authz.describe_model('test_contextual')) > 0,
        authz.describe_model('test_contextual'));
    -- m) the default is the server's clock — for the function API and for a raw INSERT
    PERFORM authz.create_condition_sql('test_contextual', 'dflt_fn', 'true');
    INSERT INTO authz.conditions (store_id, name, expression) VALUES (authz._s('test_contextual'), 'dflt_ins', 'true');
    PERFORM _test_assert('ctx_26m_default_is_server',
        (SELECT string_agg(name || '=' || time_source, ' ' ORDER BY name) FROM authz.conditions
          WHERE store_id = authz._s('test_contextual') AND name LIKE 'dflt_%'), 'dflt_fn=server dflt_ins=server');
END;
$$;
SELECT * FROM _test_teardown_contextual();

-- ctx_27: time travel — every condition's current_time is p_at there (as
-- before); a server condition's clock is therefore p_at too, whatever the
-- caller sends, and a live check after a time-travel call still uses now.
DO $$
BEGIN
    PERFORM _test_setup_contextual();
    PERFORM authz.create_condition_sql('test_contextual', 'from_2030',
        $c$ ($1->>'current_time')::timestamptz >= '2030-01-01' $c$, '{"request": ["current_time"]}', p_time_source => 'caller');   -- caller clock, for now
    PERFORM authz.write_tuple('test_contextual', 'user', 'tt1', 'viewer', 'doc', 'doc1', p_condition => 'from_2030');
    PERFORM _test_assert('ctx_27a_caller_clock_live',
        authz.check_access_with_context('test_contextual','user','tt1','viewer','doc','doc1','{"current_time": "2031-01-01T00:00:00Z"}')::text, 'true');
END;
$$;
SELECT set_config('test.ctx27_t1', clock_timestamp()::text, false);
DO $$
DECLARE v_t1 timestamptz := current_setting('test.ctx27_t1')::timestamptz;
BEGIN
    -- switch the clock to the server (a later transaction)
    PERFORM authz.create_condition_sql('test_contextual', 'from_2030',
        $c$ ($1->>'current_time')::timestamptz >= '2030-01-01' $c$, '{"request": ["current_time"]}', p_time_source => 'server');
    -- live: the server is before 2030, the caller's 2031 is ignored
    PERFORM _test_assert('ctx_27b_server_clock_live_denies',
        authz.check_access_with_context('test_contextual','user','tt1','viewer','doc','doc1','{"current_time": "2031-01-01T00:00:00Z"}')::text, 'false');
    -- time travel always evaluates current_time = p_at, for BOTH clock kinds (as
    -- before this feature): as of t1 (2026) the caller's 2031 does not count
    PERFORM _test_assert('ctx_27c_as_of_t1_is_p_at_for_every_condition',
        authz.audit_check_access('test_contextual','user','tt1','viewer','doc','doc1', v_t1, '{"current_time": "2031-01-01T00:00:00Z"}')::text, 'false');
    -- time travel to 2030-06-01 (after the switch): the clock IS p_at → allowed, whatever the caller says
    PERFORM _test_assert('ctx_27d_server_clock_is_p_at',
        authz.audit_check_access('test_contextual','user','tt1','viewer','doc','doc1', '2030-06-01T00:00:00Z', '{"current_time": "1999-01-01T00:00:00Z"}')::text, 'true');
    -- … and a live check right after a time-travel call in the same transaction is NOT answered as of 2030
    PERFORM _test_assert('ctx_27e_live_after_time_travel_uses_now',
        authz.check_access_with_context('test_contextual','user','tt1','viewer','doc','doc1','{"current_time": "2031-01-01T00:00:00Z"}')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_contextual();

DROP FUNCTION IF EXISTS _test_teardown_contextual();
DROP FUNCTION IF EXISTS _test_setup_contextual();

SELECT _test_report('checks');
