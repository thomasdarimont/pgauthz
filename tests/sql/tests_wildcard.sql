-- Tests for wildcard tuples (user:*).
-- Uses a dedicated 'test_wildcard' store to avoid polluting the demo model.

SELECT _test_reset();

-- Setup: create test store with wildcard model and seed data (idempotent).
DROP FUNCTION IF EXISTS _test_setup_wildcard();
CREATE OR REPLACE FUNCTION _test_setup_wildcard() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s          smallint;
    t_resource smallint;
    r_viewer   smallint;
    r_editor   smallint;
    r_can_view smallint;
    r_can_edit smallint;
    r_parent   smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_wildcard'); EXCEPTION WHEN OTHERS THEN NULL; END;

    s := authz.create_store('test_wildcard');

    INSERT INTO authz.types (store_id, name) VALUES
        (s, 'user'), (s, 'resource'), (s, 'folder');
    INSERT INTO authz.relations (store_id, name) VALUES
        (s, 'viewer'), (s, 'editor'), (s, 'can_view'), (s, 'can_edit'), (s, 'parent');

    t_resource := authz._t(s, 'resource');
    r_viewer   := authz._r(s, 'viewer');
    r_editor   := authz._r(s, 'editor');
    r_can_view := authz._r(s, 'can_view');
    r_can_edit := authz._r(s, 'can_edit');
    r_parent   := authz._r(s, 'parent');

    INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed) VALUES
        (s, t_resource, r_viewer,   authz._rel_direct(),   NULL, NULL, NULL),
        (s, t_resource, r_editor,   authz._rel_direct(),   NULL, NULL, NULL),
        (s, t_resource, r_can_view, authz._rel_computed(), r_viewer, NULL, NULL),
        (s, t_resource, r_can_view, authz._rel_computed(), r_editor, NULL, NULL),
        (s, t_resource, r_can_edit, authz._rel_computed(), r_editor, NULL, NULL),
        (s, t_resource, r_parent,   authz._rel_direct(),   NULL, NULL, NULL);

    PERFORM authz.write_tuple('test_wildcard', 'user', 'alice', 'editor', 'resource', 'r1');
    PERFORM authz.write_tuple('test_wildcard', 'user', '*', 'viewer', 'resource', 'r2');
    PERFORM authz.write_tuple('test_wildcard', 'user', '*', 'viewer', 'resource', 'r3');
    PERFORM authz.write_tuple('test_wildcard', 'user', 'bob', 'editor', 'resource', 'r3');

    RETURN true;
END;
$$;

-- Teardown: remove test store and return accumulated results.
DROP FUNCTION IF EXISTS _test_teardown_wildcard();
CREATE OR REPLACE FUNCTION _test_teardown_wildcard()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_wildcard');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ----------------------------------------------------------------
-- Data-driven test cases (kept in one block for the FOR loop)
-- ----------------------------------------------------------------
DO $$
DECLARE
    result boolean;
    rec    record;
BEGIN
    PERFORM _test_setup_wildcard();

    CREATE TEMP TABLE test_wildcard_checks (
        id          serial,
        description text,
        user_id     text,
        relation    text,
        resource_id text,
        expected    boolean
    );

    INSERT INTO test_wildcard_checks (description, user_id, relation, resource_id, expected) VALUES
    ('wc_01_alice_can_edit_r1',             'alice',   'can_edit', 'r1', true),
    ('wc_02_alice_can_view_r1',             'alice',   'can_view', 'r1', true),
    ('wc_03_bob_cannot_can_edit_r1',        'bob',     'can_edit', 'r1', false),
    ('wc_04_bob_cannot_can_view_r1',        'bob',     'can_view', 'r1', false),
    ('wc_05_unknown_cannot_can_view_r1',    'unknown', 'can_view', 'r1', false),
    ('wc_06_alice_can_view_r2_wildcard',    'alice',   'can_view', 'r2', true),
    ('wc_07_bob_can_view_r2_wildcard',      'bob',     'can_view', 'r2', true),
    ('wc_08_unknown_can_view_r2_wildcard',  'unknown', 'can_view', 'r2', true),
    ('wc_09_alice_cannot_can_edit_r2',      'alice',   'can_edit', 'r2', false),
    ('wc_10_alice_can_view_r3_wildcard',    'alice',   'can_view', 'r3', true),
    ('wc_11_bob_can_view_r3_wildcard',      'bob',     'can_view', 'r3', true),
    ('wc_12_bob_can_edit_r3',               'bob',     'can_edit', 'r3', true),
    ('wc_13_alice_cannot_can_edit_r3',      'alice',   'can_edit', 'r3', false),
    ('wc_14_alice_cannot_can_view_r4',      'alice',   'can_view', 'r4', false);

    FOR rec IN SELECT * FROM test_wildcard_checks ORDER BY id LOOP
        result := authz.check_access(
            'test_wildcard', 'user', rec.user_id,
            rec.relation, 'resource', rec.resource_id
        );
        PERFORM _test_assert(rec.description, result::text, rec.expected::text);
    END LOOP;

    DROP TABLE test_wildcard_checks;
END;
$$;
SELECT * FROM _test_teardown_wildcard();

-- wc_15: explain_access shows wildcard trace detail
DO $$
DECLARE
    v_result boolean;
    v_detail text;
BEGIN
    PERFORM _test_setup_wildcard();
    SELECT (e->>'result')::boolean = true AND e->>'summary' LIKE '%wildcard%',
           e->>'summary'
      INTO v_result, v_detail
      FROM authz.explain_access('test_wildcard', 'user', 'unknown', 'can_view', 'resource', 'r2') e;
    PERFORM _test_assert_true('wc_15_explain_access_wildcard', v_result, v_detail);
END;
$$;
SELECT * FROM _test_teardown_wildcard();

-- wc_16: wildcard + user_relation is rejected
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_wildcard();
DO $$
DECLARE v_err text;
BEGIN
    PERFORM authz.write_tuple('test_wildcard', 'user', '*', 'viewer', 'resource', 'r_bad', 'editor');
    PERFORM _test_assert_true('wc_16_wildcard_user_relation_rejected', false,
        'expected error, got success');
EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_err = MESSAGE_TEXT;
    PERFORM _test_assert_true('wc_16_wildcard_user_relation_rejected',
        v_err LIKE '%Wildcard%user_relation%', v_err);
END;
$$;
SELECT * FROM _test_teardown_wildcard();

-- wc_17: list_objects includes wildcard-granted objects
DO $$
DECLARE v_exists boolean;
BEGIN
    PERFORM _test_setup_wildcard();
    SELECT EXISTS (
        SELECT 1 FROM authz.list_objects('test_wildcard', 'user', 'unknown', 'can_view', 'resource')
         WHERE object_id = 'r2'
    ) INTO v_exists;
    PERFORM _test_assert_true('wc_17_list_objects_includes_wildcard', v_exists);
END;
$$;
SELECT * FROM _test_teardown_wildcard();

-- wc_18: list_subjects reports wildcard grants as a typed row:
-- subject_id '*' with is_wildcard = true ("every user of this type
-- has access"). '*' is a reserved ID (write_tuple treats it as the
-- wildcard), so no real user can collide with it.
DO $$
DECLARE v_exists boolean;
BEGIN
    PERFORM _test_setup_wildcard();
    SELECT EXISTS (
        SELECT 1 FROM authz.list_subjects('test_wildcard', 'user', 'can_view', 'resource', 'r2')
         WHERE subject_id = '*' AND is_wildcard
    ) INTO v_exists;
    PERFORM _test_assert_true('wc_18_list_subjects_flags_wildcard', v_exists);
END;
$$;
SELECT * FROM _test_teardown_wildcard();

-- wc_19: no wildcard grant on the object -> no wildcard row
DO $$
DECLARE v_exists boolean;
BEGIN
    PERFORM _test_setup_wildcard();
    SELECT EXISTS (
        SELECT 1 FROM authz.list_subjects('test_wildcard', 'user', 'can_view', 'resource', 'r1')
         WHERE subject_id = '*' OR is_wildcard
    ) INTO v_exists;
    PERFORM _test_assert_true('wc_19_no_wildcard_row_without_wildcard_grant', NOT v_exists);
END;
$$;
SELECT * FROM _test_teardown_wildcard();

-- wc_20: concrete subjects are not flagged as wildcard
DO $$
DECLARE v_ok boolean;
BEGIN
    PERFORM _test_setup_wildcard();
    SELECT bool_and(NOT is_wildcard) AND count(*) > 0
      INTO v_ok
      FROM authz.list_subjects('test_wildcard', 'user', 'can_view', 'resource', 'r3')
     WHERE subject_id <> '*';
    PERFORM _test_assert_true('wc_20_concrete_subjects_not_flagged', v_ok);
END;
$$;
SELECT * FROM _test_teardown_wildcard();

-- wc_21: wildcard user_id + user_relation is rejected in the NATIVE batch
-- path (write_tuples), not only single write_tuple. (setup outside the DO
-- block: the exception handler would otherwise roll back the setup.)
SELECT _test_setup_wildcard();
DO $$
DECLARE v_err text;
BEGIN
    PERFORM authz.write_tuples('test_wildcard', ARRAY[
        ROW('user', '*', 'editor', 'viewer', 'resource', 'r_bad')::authz.tuple_input
    ]);
    PERFORM _test_assert_true('wc_21_batch_wildcard_user_relation_rejected', false,
        'expected error, got success');
EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_err = MESSAGE_TEXT;
    PERFORM _test_assert_true('wc_21_batch_wildcard_user_relation_rejected',
        v_err LIKE '%Wildcard%user_relation%', v_err);
END;
$$;
SELECT * FROM _test_teardown_wildcard();

-- wc_22: same guard via the JSONB batch path (write_tuples_jsonb), for an
-- unconditional element (which is routed through write_tuples).
SELECT _test_setup_wildcard();
DO $$
DECLARE v_err text;
BEGIN
    PERFORM authz.write_tuples_jsonb('test_wildcard', '[
        {"user_type":"user","user_id":"*","user_relation":"editor","relation":"viewer","object_type":"resource","object_id":"r_bad"}
    ]'::jsonb);
    PERFORM _test_assert_true('wc_22_jsonb_batch_wildcard_user_relation_rejected', false,
        'expected error, got success');
EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_err = MESSAGE_TEXT;
    PERFORM _test_assert_true('wc_22_jsonb_batch_wildcard_user_relation_rejected',
        v_err LIKE '%Wildcard%user_relation%', v_err);
END;
$$;
SELECT * FROM _test_teardown_wildcard();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_wildcard();
DROP FUNCTION IF EXISTS _test_setup_wildcard();

SELECT _test_report('wildcard checks');
