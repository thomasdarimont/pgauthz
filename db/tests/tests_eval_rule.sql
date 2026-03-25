-- Unit tests for extracted rule evaluation functions:
--   _eval_direct, _eval_ttu, _eval_direct_snapshot, _eval_ttu_snapshot
--
-- Uses its own 'test_eval' store with a minimal model covering:
--   - direct tuples (exact + wildcard)
--   - computed relations
--   - tuple-to-userset (TTU)
--   - userset expansion
--   - conditions (time-based)

SELECT _test_reset();

-- Setup: create test store with model and seed data (idempotent).
DROP FUNCTION IF EXISTS _test_setup_eval();
CREATE OR REPLACE FUNCTION _test_setup_eval() RETURNS boolean LANGUAGE plpgsql AS $fn$
DECLARE
    s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_eval'); EXCEPTION WHEN OTHERS THEN NULL; END;

    s := authz.create_store('test_eval');

    INSERT INTO authz.types (store_id, name) VALUES
        (s, 'user'), (s, 'group'), (s, 'doc'), (s, 'folder');
    INSERT INTO authz.relations (store_id, name) VALUES
        (s, 'viewer'), (s, 'editor'), (s, 'can_read'),
        (s, 'member'), (s, 'in_folder'), (s, 'can_view');
    PERFORM authz._ensure_tuple_partition(s, 'doc');
    PERFORM authz._ensure_tuple_partition(s, 'folder');
    PERFORM authz._ensure_tuple_partition(s, 'group');

    -- Model rules:
    --   doc#viewer  = direct [user, group#member]
    --   doc#editor  = direct [user]
    --   doc#can_read = computed(viewer) | ttu(in_folder, can_view)
    --   folder#can_view = direct [user]
    --   group#member = direct [user]
    INSERT INTO authz.models
        (store_id, object_type, relation, rule_type,
         computed_relation, tupleset_relation, tupleset_computed)
    VALUES
        -- doc#viewer: direct
        (s, authz._t(s,'doc'), authz._r(s,'viewer'), authz._rel_direct(), NULL, NULL, NULL),
        -- doc#editor: direct
        (s, authz._t(s,'doc'), authz._r(s,'editor'), authz._rel_direct(), NULL, NULL, NULL),
        -- doc#can_read: computed from viewer
        (s, authz._t(s,'doc'), authz._r(s,'can_read'), authz._rel_computed(), authz._r(s,'viewer'), NULL, NULL),
        -- doc#can_read: ttu via in_folder -> can_view
        (s, authz._t(s,'doc'), authz._r(s,'can_read'), authz._rel_ttu(), NULL, authz._r(s,'in_folder'), authz._r(s,'can_view')),
        -- folder#can_view: direct
        (s, authz._t(s,'folder'), authz._r(s,'can_view'), authz._rel_direct(), NULL, NULL, NULL),
        -- group#member: direct
        (s, authz._t(s,'group'), authz._r(s,'member'), authz._rel_direct(), NULL, NULL, NULL);

    -- Seed tuples:
    --   user:alice  --viewer-->  doc:d1
    --   user:*      --viewer-->  doc:d_public  (wildcard)
    --   group:eng#member --viewer--> doc:d2    (userset)
    --   user:alice  --member-->  group:eng
    --   doc:d3 --in_folder--> folder:f1
    --   user:bob --can_view--> folder:f1
    PERFORM authz.write_tuple('test_eval', 'user', 'alice', 'viewer', 'doc', 'd1');
    PERFORM authz.write_tuple('test_eval', 'user', '*', 'viewer', 'doc', 'd_public');
    PERFORM authz.write_tuple('test_eval', 'group', 'eng', 'viewer', 'doc', 'd2', 'member');
    PERFORM authz.write_tuple('test_eval', 'user', 'alice', 'member', 'group', 'eng');
    PERFORM authz.write_tuple('test_eval', 'folder', 'f1', 'in_folder', 'doc', 'd3');
    PERFORM authz.write_tuple('test_eval', 'user', 'bob', 'can_view', 'folder', 'f1');

    -- Condition for time-based tests
    INSERT INTO authz.conditions (store_id, name, expression, required_context) VALUES
    (s, 'not_expired',
     $cond$($1->>'current_time')::timestamptz < ($2->>'expires')::timestamptz$cond$,
     '{"request": ["current_time"], "stored": ["expires"]}'::jsonb);

    -- Conditional tuple: user:carol --viewer--> doc:d_cond (expires)
    PERFORM authz.write_tuple('test_eval',
        'user', 'carol', 'viewer', 'doc', 'd_cond',
        p_condition => 'not_expired',
        p_condition_context => '{"expires": "2099-01-01T00:00:00Z"}'::jsonb);

    RETURN true;
END;
$fn$;

-- Teardown: remove test store and return accumulated results.
DROP FUNCTION IF EXISTS _test_teardown_eval();
CREATE OR REPLACE FUNCTION _test_teardown_eval()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_eval');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ================================================================
-- _eval_direct tests
-- ================================================================

-- ev_01: exact direct tuple found
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_direct(
        s, authz._t(s,'user'), 'alice', authz._r(s,'viewer'),
        authz._t(s,'doc'), 'd1',
        NULL, false, 0, false,
        NULL, NULL, NULL, NULL
    );
    PERFORM _test_assert_true('ev_01_direct_exact_tuple', v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_02: direct tuple not found
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_direct(
        s, authz._t(s,'user'), 'nobody', authz._r(s,'viewer'),
        authz._t(s,'doc'), 'd1',
        NULL, false, 0, false,
        NULL, NULL, NULL, NULL
    );
    PERFORM _test_assert_true('ev_02_direct_no_tuple', NOT v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_03: wildcard tuple match
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_direct(
        s, authz._t(s,'user'), 'anyone', authz._r(s,'viewer'),
        authz._t(s,'doc'), 'd_public',
        NULL, false, 0, false,
        NULL, NULL, NULL, NULL
    );
    PERFORM _test_assert_true('ev_03_direct_wildcard', v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_04: userset expansion (alice is member of group:eng, group:eng#member is viewer of doc:d2)
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_direct(
        s, authz._t(s,'user'), 'alice', authz._r(s,'viewer'),
        authz._t(s,'doc'), 'd2',
        NULL, false, 0, false,
        NULL, NULL, NULL, NULL
    );
    PERFORM _test_assert_true('ev_04_direct_userset_expansion', v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_05: conditional tuple — condition passes
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_direct(
        s, authz._t(s,'user'), 'carol', authz._r(s,'viewer'),
        authz._t(s,'doc'), 'd_cond',
        '{"current_time": "2026-06-01T00:00:00Z"}'::jsonb,
        false, 0, false,
        NULL, NULL, NULL, NULL
    );
    PERFORM _test_assert_true('ev_05_direct_condition_pass', v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_06: conditional tuple — condition denied
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_direct(
        s, authz._t(s,'user'), 'carol', authz._r(s,'viewer'),
        authz._t(s,'doc'), 'd_cond',
        '{"current_time": "2100-01-01T00:00:00Z"}'::jsonb,
        false, 0, false,
        NULL, NULL, NULL, NULL
    );
    PERFORM _test_assert_true('ev_06_direct_condition_denied', NOT v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ================================================================
-- _eval_ttu tests
-- ================================================================

-- ev_07: TTU — bob can_view folder:f1, doc:d3 is in_folder folder:f1
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_ttu(
        s, authz._t(s,'user'), 'bob', authz._r(s,'can_read'),
        authz._t(s,'doc'), 'd3',
        authz._r(s,'in_folder'), authz._r(s,'can_view'),
        NULL, false, 0, false,
        NULL, NULL, NULL, NULL
    );
    PERFORM _test_assert_true('ev_07_ttu_linked_access', v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_08: TTU — alice has no can_view on folder:f1
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_ttu(
        s, authz._t(s,'user'), 'alice', authz._r(s,'can_read'),
        authz._t(s,'doc'), 'd3',
        authz._r(s,'in_folder'), authz._r(s,'can_view'),
        NULL, false, 0, false,
        NULL, NULL, NULL, NULL
    );
    PERFORM _test_assert_true('ev_08_ttu_no_access_on_linked', NOT v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_09: TTU — no link exists (doc:d1 has no in_folder)
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_ttu(
        s, authz._t(s,'user'), 'bob', authz._r(s,'can_read'),
        authz._t(s,'doc'), 'd1',
        authz._r(s,'in_folder'), authz._r(s,'can_view'),
        NULL, false, 0, false,
        NULL, NULL, NULL, NULL
    );
    PERFORM _test_assert_true('ev_09_ttu_no_link', NOT v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ================================================================
-- _eval_direct with tracing
-- ================================================================

-- ev_10: tracing produces trace rows
DO $$
DECLARE s smallint; v boolean; v_count int;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');

    CREATE TEMP TABLE IF NOT EXISTS _access_trace (
        step        serial,
        depth       int,
        rule_type   text,
        subject     text,
        relation    text,
        object      text,
        result      boolean,
        detail      text,
        duration_ms double precision
    ) ON COMMIT DROP;

    v := authz._eval_direct(
        s, authz._t(s,'user'), 'alice', authz._r(s,'viewer'),
        authz._t(s,'doc'), 'd1',
        NULL, false, 0, true,
        'user', 'viewer', 'doc', clock_timestamp()
    );

    SELECT count(*) INTO v_count FROM _access_trace;

    PERFORM _test_assert_true('ev_10_direct_tracing', v AND v_count > 0,
        'result=' || v::text || ', trace_rows=' || v_count::text);

    DROP TABLE IF EXISTS _access_trace;
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ================================================================
-- _eval_direct_snapshot / _eval_ttu_snapshot tests
-- ================================================================

-- ev_11: snapshot direct — tuple found
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');

    CREATE TEMP TABLE _snapshot_tuples ON COMMIT DROP AS
        SELECT * FROM authz.tuples WHERE store_id = s;

    v := authz._eval_direct_snapshot(
        s, authz._t(s,'user'), 'alice', authz._r(s,'viewer'),
        authz._t(s,'doc'), 'd1',
        NULL, 0
    );
    PERFORM _test_assert_true('ev_11_snapshot_direct_found', v);

    DROP TABLE IF EXISTS _snapshot_tuples;
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_12: snapshot direct — no tuple
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');

    CREATE TEMP TABLE _snapshot_tuples ON COMMIT DROP AS
        SELECT * FROM authz.tuples WHERE store_id = s;

    v := authz._eval_direct_snapshot(
        s, authz._t(s,'user'), 'nobody', authz._r(s,'viewer'),
        authz._t(s,'doc'), 'd1',
        NULL, 0
    );
    PERFORM _test_assert_true('ev_12_snapshot_direct_not_found', NOT v);

    DROP TABLE IF EXISTS _snapshot_tuples;
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_13: snapshot TTU — bob can read d3 via folder
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');

    CREATE TEMP TABLE _snapshot_tuples ON COMMIT DROP AS
        SELECT * FROM authz.tuples WHERE store_id = s;

    v := authz._eval_ttu_snapshot(
        s, authz._t(s,'user'), 'bob', authz._r(s,'can_read'),
        authz._t(s,'doc'), 'd3',
        authz._r(s,'in_folder'), authz._r(s,'can_view'),
        NULL, 0
    );
    PERFORM _test_assert_true('ev_13_snapshot_ttu_access', v);

    DROP TABLE IF EXISTS _snapshot_tuples;
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_14: snapshot TTU — no link
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');

    CREATE TEMP TABLE _snapshot_tuples ON COMMIT DROP AS
        SELECT * FROM authz.tuples WHERE store_id = s;

    v := authz._eval_ttu_snapshot(
        s, authz._t(s,'user'), 'bob', authz._r(s,'can_read'),
        authz._t(s,'doc'), 'd1',
        authz._r(s,'in_folder'), authz._r(s,'can_view'),
        NULL, 0
    );
    PERFORM _test_assert_true('ev_14_snapshot_ttu_no_link', NOT v);

    DROP TABLE IF EXISTS _snapshot_tuples;
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ================================================================
-- End-to-end: _eval_rule dispatcher still works correctly
-- ================================================================

-- ev_15: _eval_rule dispatches direct correctly
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_rule(
        s, authz._t(s,'user'), 'alice', authz._r(s,'viewer'),
        authz._t(s,'doc'), 'd1',
        authz._rel_direct(), NULL, NULL, NULL,
        NULL, false, 0, false
    );
    PERFORM _test_assert_true('ev_15_eval_rule_direct', v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_16: _eval_rule dispatches TTU correctly
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_rule(
        s, authz._t(s,'user'), 'bob', authz._r(s,'can_read'),
        authz._t(s,'doc'), 'd3',
        authz._rel_ttu(), NULL, authz._r(s,'in_folder'), authz._r(s,'can_view'),
        NULL, false, 0, false
    );
    PERFORM _test_assert_true('ev_16_eval_rule_ttu', v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_17: _eval_rule dispatches computed correctly (can_read via viewer)
DO $$
DECLARE s smallint; v boolean;
BEGIN
    PERFORM _test_setup_eval();
    s := authz._s('test_eval');
    v := authz._eval_rule(
        s, authz._t(s,'user'), 'alice', authz._r(s,'can_read'),
        authz._t(s,'doc'), 'd1',
        authz._rel_computed(), authz._r(s,'viewer'), NULL, NULL,
        NULL, false, 0, false
    );
    PERFORM _test_assert_true('ev_17_eval_rule_computed', v);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_18: full check_access still works end-to-end (can_read via computed+direct)
DO $$
BEGIN
    PERFORM _test_setup_eval();
    PERFORM _test_assert_true('ev_18_check_access_e2e_computed',
        authz.check_access('test_eval', 'user', 'alice', 'can_read', 'doc', 'd1'));
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_19: full check_access still works end-to-end (can_read via TTU)
DO $$
BEGIN
    PERFORM _test_setup_eval();
    PERFORM _test_assert_true('ev_19_check_access_e2e_ttu',
        authz.check_access('test_eval', 'user', 'bob', 'can_read', 'doc', 'd3'));
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ================================================================
-- find_redundant_tuples tests
-- ================================================================

-- ev_20: bob has direct can_view on folder:f1, plus viewer on doc:d3 is
-- resolved via TTU (in_folder → can_view). If we also give bob a direct
-- viewer tuple on doc:d3, it should be flagged as redundant because
-- can_read → computed(viewer) already grants via the TTU path AND the
-- direct viewer tuple on d3 itself is covered by the userset path.
-- But viewer on d3 is NOT covered by another path (only TTU covers can_read,
-- not viewer). So we need a clearer case:
-- Give bob direct can_view on folder:f1 (already exists) AND a direct
-- can_view tuple on folder:f1 from a second path. Actually the simplest
-- case: alice already has viewer on d1, and can_read is computed from viewer.
-- If we give alice a SECOND path to viewer on d1 it won't help because the
-- original is the only path.
-- Clearest test: bob has can_view on folder:f1. doc:d3 is in folder:f1.
-- So bob gets can_read on d3 via TTU. Now add a DIRECT viewer tuple for
-- bob on d3. Since can_read = computed(viewer) | ttu(in_folder, can_view),
-- bob's viewer on d3 is not redundant for the "viewer" relation itself
-- (no other path grants viewer), but let's test with a truly redundant one.
--
-- Best approach: alice is member of group:eng, group:eng#member is viewer
-- of doc:d2 (userset). So alice already has viewer on d2 via userset.
-- If we add a direct viewer tuple for alice on d2, that's redundant.

DO $$
DECLARE
    v_count int;
BEGIN
    PERFORM _test_setup_eval();

    -- alice already has viewer on d2 via group:eng#member userset
    -- Add a redundant direct tuple
    PERFORM authz.write_tuple('test_eval', 'user', 'alice', 'viewer', 'doc', 'd2');

    SELECT count(*) INTO v_count
      FROM authz.find_redundant_tuples('test_eval', 'doc', 'viewer');

    PERFORM _test_assert_true('ev_20_redundant_found',
        v_count >= 1, 'redundant_count=' || v_count::text);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_21: non-redundant tuples should NOT be flagged
DO $$
DECLARE
    v_count int;
BEGIN
    PERFORM _test_setup_eval();

    -- alice's viewer on d1 is the only path — not redundant
    SELECT count(*) INTO v_count
      FROM authz.find_redundant_tuples('test_eval', 'doc', 'viewer')
     WHERE user_id = 'alice' AND object_id = 'd1';

    PERFORM _test_assert_true('ev_21_non_redundant_not_flagged',
        v_count = 0, 'count=' || v_count::text);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_22: after removing a redundant tuple, the user still has access
DO $$
DECLARE
    v_still_has_access boolean;
BEGIN
    PERFORM _test_setup_eval();

    -- Add redundant direct tuple
    PERFORM authz.write_tuple('test_eval', 'user', 'alice', 'viewer', 'doc', 'd2');

    -- Verify it shows as redundant
    PERFORM _test_assert_true('ev_22a_is_redundant',
        EXISTS (SELECT 1 FROM authz.find_redundant_tuples('test_eval', 'doc', 'viewer')
                 WHERE user_id = 'alice' AND object_id = 'd2'));

    -- Remove the redundant tuple
    PERFORM authz.delete_tuple('test_eval', 'user', 'alice', 'viewer', 'doc', 'd2');

    -- Alice should still have viewer on d2 via group userset
    v_still_has_access := authz.check_access('test_eval', 'user', 'alice', 'viewer', 'doc', 'd2');
    PERFORM _test_assert_true('ev_22b_still_has_access', v_still_has_access);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_23: wildcard tuples are never flagged as redundant
DO $$
DECLARE
    v_count int;
BEGIN
    PERFORM _test_setup_eval();

    SELECT count(*) INTO v_count
      FROM authz.find_redundant_tuples('test_eval')
     WHERE user_id = '*';

    PERFORM _test_assert_true('ev_23_wildcards_not_flagged',
        v_count = 0, 'wildcard_count=' || v_count::text);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_24: find_redundant_tuples does not pollute audit log
DO $$
DECLARE
    v_before int;
    v_after  int;
BEGIN
    PERFORM _test_setup_eval();
    PERFORM authz.write_tuple('test_eval', 'user', 'alice', 'viewer', 'doc', 'd2');

    SELECT count(*) INTO v_before FROM authz.tuples_audit
     WHERE store_id = authz._s('test_eval');

    PERFORM authz.find_redundant_tuples('test_eval');

    SELECT count(*) INTO v_after FROM authz.tuples_audit
     WHERE store_id = authz._s('test_eval');

    PERFORM _test_assert_true('ev_24_no_audit_pollution',
        v_before = v_after,
        'before=' || v_before || ', after=' || v_after);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ev_25: scan with no filters (all object types, all relations)
DO $$
DECLARE
    v_count int;
BEGIN
    PERFORM _test_setup_eval();
    PERFORM authz.write_tuple('test_eval', 'user', 'alice', 'viewer', 'doc', 'd2');

    SELECT count(*) INTO v_count
      FROM authz.find_redundant_tuples('test_eval');

    PERFORM _test_assert_true('ev_25_unfiltered_scan',
        v_count >= 1, 'redundant_count=' || v_count::text);
END;
$$;
SELECT * FROM _test_teardown_eval();

-- ================================================================

DROP FUNCTION IF EXISTS _test_teardown_eval();
DROP FUNCTION IF EXISTS _test_setup_eval();

SELECT _test_report('eval_rule checks');
