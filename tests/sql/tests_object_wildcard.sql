-- Tests for object-side wildcard tuples ("privileged" grants):
--   (user, relation, type, '*') = the subject holds the relation on
--   EVERY object of the type. Writes are default-deny — the direct
--   model rule must be marked allow_object_wildcard.
--
-- Model:
--   type doc { viewer: [user, group#member] (object wildcard allowed)
--              editor: [user]               (object wildcard NOT allowed)
--              blocked: [user]
--              can_comment: viewer BUT NOT blocked }
--   type group { member: [user] }

SELECT _test_reset();

DROP FUNCTION IF EXISTS _test_setup_ow();
CREATE OR REPLACE FUNCTION _test_setup_ow() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_ow'); EXCEPTION WHEN OTHERS THEN NULL; END;

    s := authz.create_store('test_ow');
    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc'), (s, 'group');
    INSERT INTO authz.relations (store_id, name) VALUES
        (s, 'viewer'), (s, 'editor'), (s, 'blocked'), (s, 'can_comment'), (s, 'member');
    PERFORM authz._ensure_tuple_partition(s, 'doc');

    PERFORM authz.model_add_rule('test_ow', 'group', 'member', 'direct');
    PERFORM authz.model_add_rule('test_ow', 'doc', 'viewer', 'direct',
        p_allow_object_wildcard => true);
    PERFORM authz.model_add_rule('test_ow', 'doc', 'editor', 'direct');
    PERFORM authz.model_add_rule('test_ow', 'doc', 'blocked', 'direct');
    PERFORM authz.model_add_rule('test_ow', 'doc', 'can_comment', 'computed',
        p_computed_relation => 'viewer',
        p_group_id => 1::smallint, p_group_op => 'exclusion');
    PERFORM authz.model_add_rule('test_ow', 'doc', 'can_comment', 'computed',
        p_computed_relation => 'blocked',
        p_group_id => 1::smallint, p_group_op => 'exclusion', p_negated => true);

    -- ordinary data
    PERFORM authz.write_tuple('test_ow', 'user', 'bob', 'viewer', 'doc', 'd1');
    PERFORM authz.write_tuple('test_ow', 'user', 'carol', 'member', 'group', 'g1');
    RETURN true;
END;
$$;

DROP FUNCTION IF EXISTS _test_teardown_ow();
CREATE OR REPLACE FUNCTION _test_teardown_ow()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_ow');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ow_01: object-wildcard writes are rejected for unmarked relations
SELECT _test_setup_ow();
DO $$
BEGIN
    PERFORM authz.write_tuple('test_ow', 'user', 'eve', 'editor', 'doc', '*');
    PERFORM _test_assert_true('ow_01_unmarked_relation_rejects_object_wildcard', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ow_01_unmarked_relation_rejects_object_wildcard',
        SQLERRM LIKE '%object wildcard%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_02..04: marked relation accepts and grants across the type
DO $$
BEGIN
    PERFORM _test_setup_ow();
    PERFORM _test_assert('ow_02_marked_relation_accepts_object_wildcard',
        authz.write_tuple('test_ow', 'user', 'adm', 'viewer', 'doc', '*')::text, 'true');

    -- adm can view any doc, including ones with no tuples at all
    PERFORM _test_assert('ow_03a_wildcard_grants_existing_doc',
        authz.check_access('test_ow', 'user', 'adm', 'viewer', 'doc', 'd1')::text, 'true');
    PERFORM _test_assert('ow_03b_wildcard_grants_unknown_doc',
        authz.check_access('test_ow', 'user', 'adm', 'viewer', 'doc', 'd_never_seen')::text, 'true');
    -- but not other relations or other users
    PERFORM _test_assert('ow_04a_other_relation_unaffected',
        authz.check_access('test_ow', 'user', 'adm', 'editor', 'doc', 'd1')::text, 'false');
    PERFORM _test_assert('ow_04b_other_user_unaffected',
        authz.check_access('test_ow', 'user', 'mallory', 'viewer', 'doc', 'd1')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_05: userset subject + object wildcard: all group members, all docs
DO $$
BEGIN
    PERFORM _test_setup_ow();
    PERFORM authz.write_tuple('test_ow', 'group', 'g1', 'viewer', 'doc', '*',
        p_user_relation => 'member');
    PERFORM _test_assert('ow_05a_userset_object_wildcard_grants_member',
        authz.check_access('test_ow', 'user', 'carol', 'viewer', 'doc', 'd_any')::text, 'true');
    PERFORM _test_assert('ow_05b_userset_object_wildcard_denies_nonmember',
        authz.check_access('test_ow', 'user', 'mallory', 'viewer', 'doc', 'd_any')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_06: list_objects reports the typed wildcard row ('*', true)
DO $$
DECLARE v_ok boolean;
BEGIN
    PERFORM _test_setup_ow();
    PERFORM authz.write_tuple('test_ow', 'user', 'adm', 'viewer', 'doc', '*');
    SELECT EXISTS (
        SELECT 1 FROM authz.list_objects('test_ow', 'user', 'adm', 'viewer', 'doc')
         WHERE object_id = '*' AND is_wildcard
    ) INTO v_ok;
    PERFORM _test_assert_true('ow_06_list_objects_flags_wildcard', v_ok);
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_07: without an object wildcard, no wildcard row; concrete rows unflagged
DO $$
DECLARE v_ok boolean;
BEGIN
    PERFORM _test_setup_ow();
    SELECT bool_and(NOT is_wildcard) AND count(*) = 1
      INTO v_ok
      FROM authz.list_objects('test_ow', 'user', 'bob', 'viewer', 'doc');
    PERFORM _test_assert_true('ow_07_no_wildcard_row_without_grant', v_ok);
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_08: list_subjects sees the privileged user on any object of the type
DO $$
DECLARE v_ok boolean;
BEGIN
    PERFORM _test_setup_ow();
    PERFORM authz.write_tuple('test_ow', 'user', 'adm', 'viewer', 'doc', '*');
    SELECT EXISTS (
        SELECT 1 FROM authz.list_subjects('test_ow', 'user', 'viewer', 'doc', 'd1')
         WHERE subject_id = 'adm' AND NOT is_wildcard
    ) INTO v_ok;
    PERFORM _test_assert_true('ow_08_list_subjects_includes_privileged_user', v_ok);
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_09: exclusion still subtracts from a wildcard grant
DO $$
BEGIN
    PERFORM _test_setup_ow();
    PERFORM authz.write_tuple('test_ow', 'user', 'adm', 'viewer', 'doc', '*');
    PERFORM authz.write_tuple('test_ow', 'user', 'adm', 'blocked', 'doc', 'd9');
    PERFORM _test_assert('ow_09a_wildcard_with_exclusion_denied_where_blocked',
        authz.check_access('test_ow', 'user', 'adm', 'can_comment', 'doc', 'd9')::text, 'false');
    PERFORM _test_assert('ow_09b_wildcard_with_exclusion_allowed_elsewhere',
        authz.check_access('test_ow', 'user', 'adm', 'can_comment', 'doc', 'd1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_10: conditions on object-wildcard tuples are enforced
DO $$
BEGIN
    PERFORM _test_setup_ow();
    INSERT INTO authz.conditions (store_id, name, expression)
    VALUES (authz._s('test_ow'), 'flag_set', $cond$($1->>'ok')::boolean$cond$);
    PERFORM authz.write_tuple('test_ow', 'user', 'adm', 'viewer', 'doc', '*',
        p_condition => 'flag_set');
    PERFORM _test_assert('ow_10a_conditional_wildcard_denied_without_context',
        authz.check_access('test_ow', 'user', 'adm', 'viewer', 'doc', 'd1')::text, 'false');
    PERFORM _test_assert('ow_10b_conditional_wildcard_allowed_with_context',
        authz.check_access_with_context('test_ow', 'user', 'adm', 'viewer', 'doc', 'd1',
            '{"ok": true}'::jsonb)::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_11: time travel honors object wildcards
DO $$
BEGIN
    PERFORM _test_setup_ow();
    PERFORM authz.write_tuple('test_ow', 'user', 'adm', 'viewer', 'doc', '*');
    PERFORM _test_assert('ow_11_audit_check_honors_object_wildcard',
        authz.audit_check_access('test_ow', 'user', 'adm', 'viewer', 'doc', 'd1',
            clock_timestamp())::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_12: batch writes are gated the same way
SELECT _test_setup_ow();
DO $$
BEGIN
    PERFORM authz.write_tuples('test_ow', ARRAY[
        ROW('user', 'eve', NULL, 'editor', 'doc', '*')
    ]::authz.tuple_input[]);
    PERFORM _test_assert_true('ow_12_batch_write_gated', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ow_12_batch_write_gated',
        SQLERRM LIKE '%object wildcard%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_13: a specific tuple shadowed by an object wildcard is redundant;
-- the wildcard tuple itself is never flagged
DO $$
DECLARE v_cnt int;
BEGIN
    PERFORM _test_setup_ow();
    PERFORM authz.write_tuple('test_ow', 'user', 'adm', 'viewer', 'doc', '*');
    PERFORM authz.write_tuple('test_ow', 'user', 'adm', 'viewer', 'doc', 'd1');

    SELECT count(*) INTO v_cnt
      FROM authz.find_redundant_tuples('test_ow', 'doc', 'viewer')
     WHERE user_id = 'adm' AND object_id = 'd1';
    PERFORM _test_assert('ow_13a_shadowed_tuple_redundant', v_cnt::text, '1');

    SELECT count(*) INTO v_cnt
      FROM authz.find_redundant_tuples('test_ow', 'doc', 'viewer')
     WHERE object_id = '*';
    PERFORM _test_assert('ow_13b_wildcard_tuple_not_flagged', v_cnt::text, '0');
END;
$$;
SELECT * FROM _test_teardown_ow();

-- ow_14: allow_object_wildcard is rejected on non-direct rules
SELECT _test_setup_ow();
DO $$
BEGIN
    PERFORM authz.model_add_rule('test_ow', 'doc', 'can_comment', 'computed',
        p_computed_relation => 'viewer', p_allow_object_wildcard => true);
    PERFORM _test_assert_true('ow_14_flag_rejected_on_non_direct_rule', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ow_14_flag_rejected_on_non_direct_rule',
        SQLERRM LIKE '%allow_object_wildcard%direct%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ow();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_ow();
DROP FUNCTION IF EXISTS _test_setup_ow();

SELECT _test_report('object wildcard checks');
