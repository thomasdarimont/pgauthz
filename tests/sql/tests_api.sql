-- Tests for core API functions.
-- Covers: write_tuple, delete_tuple, write_tuples, delete_tuples,
--         write_tuples_jsonb, delete_tuples_jsonb,
--         check_access_with_contextual_tuples_jsonb,
--         delete_user_tuples, check_access_batch, audit_check_access,
--         audit_list_actions, audit_list_user, audit_list_object,
--         performed_by tracking, JSONB validation, delete_store.
--
-- Uses its own 'test_api' store with a minimal model:
--   type user
--   type doc
--     relations
--       define reader:  [user]
--       define editor:  [user]

SELECT _test_reset();

-- Setup: create test store with model (idempotent).
CREATE OR REPLACE FUNCTION _test_setup_api() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_api'); EXCEPTION WHEN OTHERS THEN NULL; END;

    s := authz.create_store('test_api');

    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'reader'), (s, 'editor');
    PERFORM authz._ensure_tuple_partition(s, 'doc');

    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, tupleset_relation, tupleset_computed)
    VALUES
        (s, authz._t(s, 'doc'), authz._r(s, 'reader'), authz._rel_direct(), NULL, NULL, NULL),
        (s, authz._t(s, 'doc'), authz._r(s, 'editor'), authz._rel_direct(), NULL, NULL, NULL);
    RETURN true;
END;
$$;

-- Teardown: remove test store and return accumulated results.
DROP FUNCTION IF EXISTS _test_teardown_api();
CREATE OR REPLACE FUNCTION _test_teardown_api()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_api');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ================================================================
-- write_tuple / delete_tuple tests
-- ================================================================

-- api_01: write_tuple returns true for new tuple
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM _test_assert('api_01_write_tuple_new',
        authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();


-- api_02: write_tuple returns false for duplicate
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM _test_assert('api_02_write_tuple_duplicate',
        authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_03: written tuple grants access
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM _test_assert('api_03_written_tuple_grants_access',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_04: delete_tuple returns true for existing tuple
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM _test_assert('api_04_delete_tuple_existing',
        authz.delete_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_05: delete_tuple returns false for nonexistent tuple
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM _test_assert('api_05_delete_tuple_nonexistent',
        authz.delete_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_06: deleted tuple revokes access
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM authz.delete_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM _test_assert('api_06_deleted_tuple_revokes_access',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc1')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- write_tuples / delete_tuples (batch) tests
-- ================================================================

-- api_07: write_tuples returns count of new tuples
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM _test_assert('api_07_write_tuples_batch_new',
        authz.write_tuples('test_api', ARRAY[
            ROW('user', 'alice', NULL, 'reader', 'doc', 'doc2'),
            ROW('user', 'bob',   NULL, 'reader', 'doc', 'doc2'),
            ROW('user', 'frank', NULL, 'reader', 'doc', 'doc2')
        ]::authz.tuple_input[])::text, '3');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_08: write_tuples skips duplicates
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc2');
    PERFORM _test_assert('api_08_write_tuples_skip_duplicates',
        authz.write_tuples('test_api', ARRAY[
            ROW('user', 'alice', NULL, 'reader', 'doc', 'doc2'),
            ROW('user', 'zara',  NULL, 'reader', 'doc', 'doc2')
        ]::authz.tuple_input[])::text, '1');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_09: batch-written tuple grants access
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuples('test_api', ARRAY[
        ROW('user', 'zara', NULL, 'reader', 'doc', 'doc2')
    ]::authz.tuple_input[]);
    PERFORM _test_assert('api_09_batch_written_grants_access',
        authz.check_access('test_api', 'user', 'zara', 'reader', 'doc', 'doc2')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_10: delete_tuples returns count of deleted tuples
DO $$
DECLARE v_int integer;
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc2');
    PERFORM authz.write_tuple('test_api', 'user', 'bob',   'reader', 'doc', 'doc2');
    v_int := authz.delete_tuples('test_api', ARRAY[
        ROW('user', 'alice', NULL, 'reader', 'doc', 'doc2'),
        ROW('user', 'bob',   NULL, 'reader', 'doc', 'doc2')
    ]::authz.tuple_input[]);
    PERFORM _test_assert('api_10_delete_tuples_batch', v_int::text, '2');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_11: delete_tuples returns 0 for nonexistent tuples
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM _test_assert('api_11_delete_tuples_nonexistent',
        authz.delete_tuples('test_api', ARRAY[
            ROW('user', 'alice', NULL, 'reader', 'doc', 'doc2')
        ]::authz.tuple_input[])::text, '0');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_12: batch-deleted tuple revokes access
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuples('test_api', ARRAY[
        ROW('user', 'alice', NULL, 'reader', 'doc', 'doc2')
    ]::authz.tuple_input[]);
    PERFORM authz.delete_tuples('test_api', ARRAY[
        ROW('user', 'alice', NULL, 'reader', 'doc', 'doc2')
    ]::authz.tuple_input[]);
    PERFORM _test_assert('api_12_batch_deleted_revokes_access',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc2')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- delete_user_tuples tests
-- ================================================================

-- api_13: delete_user_tuples removes all tuples for a user
DO $$
DECLARE v_int integer;
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'zara', 'reader', 'doc', 'doc2');
    PERFORM authz.write_tuple('test_api', 'user', 'zara', 'reader', 'doc', 'doc3');
    v_int := authz.delete_user_tuples('test_api', 'user', 'zara');
    PERFORM _test_assert('api_13_delete_user_tuples', v_int::text, '2');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_14: delete_user_tuples revokes access
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'zara', 'reader', 'doc', 'doc2');
    PERFORM authz.delete_user_tuples('test_api', 'user', 'zara');
    PERFORM _test_assert('api_14_delete_user_tuples_revokes',
        authz.check_access('test_api', 'user', 'zara', 'reader', 'doc', 'doc2')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_15: delete_user_tuples returns 0 when user has no tuples
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM _test_assert('api_15_delete_user_tuples_empty',
        authz.delete_user_tuples('test_api', 'user', 'zara')::text, '0');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- performed_by audit tracking tests
-- ================================================================

-- api_16: performed_by tracked on write_tuple
DO $$
DECLARE
    s smallint;
    v_text text;
BEGIN
    PERFORM _test_setup_api();
    s := authz._s('test_api');
    PERFORM authz.write_tuple('test_api',
        'user', 'alice', 'reader', 'doc', 'doc_audit',
        p_performed_by => 'admin');
    SELECT a.performed_by INTO v_text
      FROM authz.tuples_audit a
     WHERE a.store_id = s AND a.user_id = 'alice'
       AND a.object_id = 'doc_audit' AND a.action = 'INSERT'
     ORDER BY a.performed_at DESC LIMIT 1;
    PERFORM _test_assert('api_16_performed_by_write', v_text, 'admin');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_17: performed_by tracked on delete_tuple
DO $$
DECLARE
    s smallint;
    v_text text;
BEGIN
    PERFORM _test_setup_api();
    s := authz._s('test_api');
    PERFORM authz.write_tuple('test_api',
        'user', 'alice', 'reader', 'doc', 'doc_audit');
    PERFORM authz.delete_tuple('test_api',
        'user', 'alice', 'reader', 'doc', 'doc_audit',
        p_performed_by => 'admin');
    SELECT a.performed_by INTO v_text
      FROM authz.tuples_audit a
     WHERE a.store_id = s AND a.user_id = 'alice'
       AND a.object_id = 'doc_audit' AND a.action = 'DELETE'
     ORDER BY a.performed_at DESC LIMIT 1;
    PERFORM _test_assert('api_17_performed_by_delete', v_text, 'admin');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_18: performed_by tracked on write_tuples (batch)
DO $$
DECLARE
    s smallint;
    v_text text;
BEGIN
    PERFORM _test_setup_api();
    s := authz._s('test_api');
    PERFORM authz.write_tuples('test_api', ARRAY[
        ROW('user', 'alice', NULL, 'reader', 'doc', 'doc_audit2')
    ]::authz.tuple_input[], p_performed_by => 'batch_admin');
    SELECT a.performed_by INTO v_text
      FROM authz.tuples_audit a
     WHERE a.store_id = s AND a.user_id = 'alice'
       AND a.object_id = 'doc_audit2' AND a.action = 'INSERT'
     ORDER BY a.performed_at DESC LIMIT 1;
    PERFORM _test_assert('api_18_performed_by_batch_write', v_text, 'batch_admin');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_19: performed_by tracked on delete_user_tuples
DO $$
DECLARE
    s smallint;
    v_text text;
BEGIN
    PERFORM _test_setup_api();
    s := authz._s('test_api');
    PERFORM authz.write_tuple('test_api', 'user', 'zara', 'reader', 'doc', 'doc_audit3');
    PERFORM authz.delete_user_tuples('test_api', 'user', 'zara',
        p_performed_by => 'offboarding');
    SELECT a.performed_by INTO v_text
      FROM authz.tuples_audit a
     WHERE a.store_id = s AND a.user_id = 'zara'
       AND a.object_id = 'doc_audit3' AND a.action = 'DELETE'
     ORDER BY a.performed_at DESC LIMIT 1;
    PERFORM _test_assert('api_19_performed_by_delete_user', v_text, 'offboarding');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- audit_list_user / audit_list_object tests
-- ================================================================

-- api_20: audit_list_user returns entries
DO $$
DECLARE v_count bigint;
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM authz.delete_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    SELECT count(*) INTO v_count FROM authz.audit_list_user('test_api', 'user', 'alice');
    PERFORM _test_assert_true('api_20_audit_list_user', v_count >= 2,
        v_count::text || ' entries');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_21: audit_list_user returns empty for out-of-range timestamps
DO $$
DECLARE v_count bigint;
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    SELECT count(*) INTO v_count FROM authz.audit_list_user('test_api', 'user', 'alice',
        '2000-01-01'::timestamptz, '2000-01-02'::timestamptz);
    PERFORM _test_assert('api_21_audit_list_user_empty_range', v_count::text, '0');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_22: audit_list_object returns entries
DO $$
DECLARE v_count bigint;
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc_audit',
        p_performed_by => 'admin');
    PERFORM authz.delete_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc_audit',
        p_performed_by => 'admin');
    SELECT count(*) INTO v_count FROM authz.audit_list_object('test_api', 'doc', 'doc_audit');
    PERFORM _test_assert_true('api_22_audit_list_object', v_count >= 2,
        v_count::text || ' entries');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_23: audit_list_object includes performed_by
DO $$
DECLARE v_text text;
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc_audit',
        p_performed_by => 'admin');
    SELECT a.performed_by INTO v_text
      FROM authz.audit_list_object('test_api', 'doc', 'doc_audit') a
     WHERE a.action = 'INSERT' LIMIT 1;
    PERFORM _test_assert('api_23_object_audit_performed_by', v_text, 'admin');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- audit_check_access / audit_list_actions (time-travel) tests
-- ================================================================

-- api_24-28: time-travel tests. Versioning is transactional, so the write
-- and the delete go in SEPARATE transactions with the "had access" marker
-- captured between them. (A write+delete in one transaction would be atomic
-- — the tuple would never be observable at any timestamp.)
--   tx1: grant access
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc_tt');
END;
$$;
SELECT set_config('test.had_access_at', clock_timestamp()::text, false);
--   tx2: revoke, then time-travel around the marker
DO $$
DECLARE
    v_bool    boolean;
    v_actions text[];
BEGIN
    PERFORM authz.delete_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc_tt');

    v_bool := authz.audit_check_access('test_api',
        'user', 'alice', 'reader', 'doc', 'doc_tt',
        current_setting('test.had_access_at')::timestamptz);
    PERFORM _test_assert('api_24_access_at_tuple_existed', v_bool::text, 'true');

    v_bool := authz.audit_check_access('test_api',
        'user', 'alice', 'reader', 'doc', 'doc_tt', clock_timestamp());
    PERFORM _test_assert('api_25_access_at_after_delete', v_bool::text, 'false');

    v_bool := authz.audit_check_access('test_api',
        'user', 'alice', 'reader', 'doc', 'doc_tt',
        '2000-01-01T00:00:00Z'::timestamptz);
    PERFORM _test_assert('api_26_access_at_before_create', v_bool::text, 'false');

    SELECT array_agg(a.action ORDER BY a.action) INTO v_actions
      FROM authz.audit_list_actions('test_api',
          'user', 'alice', 'doc', 'doc_tt',
          current_setting('test.had_access_at')::timestamptz) a;
    PERFORM _test_assert_true('api_27_actions_at_tuple_existed',
        v_actions @> ARRAY['reader'], v_actions::text);

    SELECT array_agg(a.action ORDER BY a.action) INTO v_actions
      FROM authz.audit_list_actions('test_api',
          'user', 'alice', 'doc', 'doc_tt', clock_timestamp()) a;
    PERFORM _test_assert('api_28_actions_at_after_delete', v_actions::text, NULL);
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- model_add_rule / model_remove_rule / model_remove_rules tests
-- ================================================================

-- api_33: model_add_rule — add a direct rule, verify it exists
DO $$
DECLARE
    v_rule_id smallint;
    v_count   bigint;
BEGIN
    PERFORM _test_setup_api();
    -- Remove existing direct reader rule so we can re-add it
    DELETE FROM authz.models
     WHERE store_id = authz._s('test_api')
       AND object_type = authz._t(authz._s('test_api'), 'doc')
       AND relation = authz._r(authz._s('test_api'), 'reader')
       AND rule_type = authz._rel_direct();

    v_rule_id := authz.model_add_rule('test_api', 'doc', 'reader', 'direct');
    SELECT count(*) INTO v_count FROM authz.models
     WHERE id = v_rule_id AND store_id = authz._s('test_api');
    PERFORM _test_assert('api_33_add_direct_rule', v_count::text, '1');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_34: model_add_rule — add a computed rule, verify check_access works
DO $$
DECLARE
    v_rule_id smallint;
    v_access  boolean;
BEGIN
    PERFORM _test_setup_api();
    -- Add computed rule: 'reader' is implied by 'editor'
    v_rule_id := authz.model_add_rule('test_api', 'doc', 'reader', 'computed',
        p_computed_relation => 'editor');

    -- Write an editor tuple, check reader access via computed rule
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'editor', 'doc', 'doc1');
    v_access := authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM _test_assert('api_34_add_computed_rule', v_access::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_35: model_add_rule — add a TTU rule, verify check_access works
DO $$
DECLARE
    s         smallint;
    v_rule_id smallint;
    v_access  boolean;
BEGIN
    PERFORM _test_setup_api();
    s := authz._s('test_api');

    -- Add a 'folder' type and 'parent' + 'can_read' relations for TTU test
    INSERT INTO authz.types (store_id, name) VALUES (s, 'folder');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'parent'), (s, 'can_read');
    PERFORM authz._ensure_tuple_partition(s, 'folder');

    -- Add direct rule on folder for can_read
    PERFORM authz.model_add_rule('test_api', 'folder', 'can_read', 'direct');

    -- Add TTU rule on doc: can_read = can_read from parent
    v_rule_id := authz.model_add_rule('test_api', 'doc', 'can_read', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'can_read');

    -- Create parent link and permission
    PERFORM authz.write_tuple('test_api', 'folder', 'folder1', 'parent', 'doc', 'doc1');
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'can_read', 'folder', 'folder1');

    v_access := authz.check_access('test_api', 'user', 'alice', 'can_read', 'doc', 'doc1');
    PERFORM _test_assert('api_35_add_ttu_rule', v_access::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_36: model_add_rule — duplicate insert is idempotent (returns same ID)
DO $$
DECLARE
    v_id1 smallint;
    v_id2 smallint;
BEGIN
    PERFORM _test_setup_api();
    -- Remove existing direct reader rule first
    DELETE FROM authz.models
     WHERE store_id = authz._s('test_api')
       AND object_type = authz._t(authz._s('test_api'), 'doc')
       AND relation = authz._r(authz._s('test_api'), 'reader')
       AND rule_type = authz._rel_direct();

    v_id1 := authz.model_add_rule('test_api', 'doc', 'reader', 'direct');
    v_id2 := authz.model_add_rule('test_api', 'doc', 'reader', 'direct');
    PERFORM _test_assert('api_36_add_rule_idempotent', (v_id1 = v_id2)::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_37: model_add_rule — group_op mismatch raises error
DO $$
DECLARE
    v_raised boolean := false;
BEGIN
    PERFORM _test_setup_api();
    -- First rule in group 1 with 'intersection'
    PERFORM authz.model_add_rule('test_api', 'doc', 'reader', 'direct',
        p_group_id => 1::smallint, p_group_op => 'intersection');
    -- Second rule in group 1 with 'or' should fail
    BEGIN
        PERFORM authz.model_add_rule('test_api', 'doc', 'reader', 'computed',
            p_computed_relation => 'editor',
            p_group_id => 1::smallint, p_group_op => 'or');
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM _test_assert('api_37_group_op_mismatch', v_raised::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_38: model_add_rule — invalid rule_type raises error
DO $$
DECLARE
    v_raised boolean := false;
BEGIN
    PERFORM _test_setup_api();
    BEGIN
        PERFORM authz.model_add_rule('test_api', 'doc', 'reader', 'bogus');
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM _test_assert('api_38_invalid_rule_type', v_raised::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_39: model_remove_rule — remove by ID, verify check_access changes
DO $$
DECLARE
    v_rule_id smallint;
    v_deleted boolean;
    v_access  boolean;
BEGIN
    PERFORM _test_setup_api();

    -- Write a tuple, verify access works
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    v_access := authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM _test_assert('api_39a_access_before_remove', v_access::text, 'true');

    -- Get the rule ID for the direct reader rule
    SELECT id INTO v_rule_id FROM authz.models
     WHERE store_id = authz._s('test_api')
       AND object_type = authz._t(authz._s('test_api'), 'doc')
       AND relation = authz._r(authz._s('test_api'), 'reader')
       AND rule_type = authz._rel_direct();

    -- Remove the rule
    v_deleted := authz.model_remove_rule('test_api', v_rule_id);
    PERFORM _test_assert('api_39b_remove_rule_returns_true', v_deleted::text, 'true');

    -- Access should now be denied
    v_access := authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM _test_assert('api_39c_access_after_remove', v_access::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_40: model_remove_rule — wrong store returns false
DO $$
DECLARE
    v_rule_id smallint;
    v_deleted boolean;
    ds        smallint;
BEGIN
    PERFORM _test_setup_api();
    -- Create a second store
    BEGIN PERFORM authz.delete_store('test_api_other'); EXCEPTION WHEN OTHERS THEN NULL; END;
    ds := authz.create_store('test_api_other');

    -- Get a rule ID from test_api
    SELECT id INTO v_rule_id FROM authz.models
     WHERE store_id = authz._s('test_api') LIMIT 1;

    -- Try to remove it via wrong store
    v_deleted := authz.model_remove_rule('test_api_other', v_rule_id);
    PERFORM _test_assert('api_40_wrong_store', v_deleted::text, 'false');

    PERFORM authz.delete_store('test_api_other');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_41: model_remove_rules — remove all rules for a relation, returns count
DO $$
DECLARE
    v_count int;
BEGIN
    PERFORM _test_setup_api();
    -- Add a computed rule alongside the existing direct rule
    PERFORM authz.model_add_rule('test_api', 'doc', 'reader', 'computed',
        p_computed_relation => 'editor');

    -- Remove all rules for doc/reader
    v_count := authz.model_remove_rules('test_api', 'doc', 'reader');
    PERFORM _test_assert('api_41_remove_rules_count', v_count::text, '2');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- check_access_batch tests
-- ================================================================

-- api_42: batch check returns correct results for mixed access
DO $$
DECLARE
    v_decisions boolean[];
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    -- alice has reader on doc1, but not editor
    SELECT array_agg(decision ORDER BY ordinality) INTO v_decisions
      FROM authz.check_access_batch_typed('test_api', ARRAY[
          ('user','alice','reader','doc','doc1'),
          ('user','alice','editor','doc','doc1')
      ]::authz.access_check[]) WITH ORDINALITY;
    PERFORM _test_assert('api_42_batch_mixed', v_decisions::text, '{t,f}');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_42b: batch result includes input fields
DO $$
DECLARE
    v_row authz.access_check_result;
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    SELECT * INTO v_row
      FROM authz.check_access_batch_typed('test_api', ARRAY[
          ('user','alice','reader','doc','doc1')
      ]::authz.access_check[]) LIMIT 1;
    PERFORM _test_assert('api_42b_result_user_type', v_row.user_type, 'user');
    PERFORM _test_assert('api_42b_result_relation', v_row.relation, 'reader');
    PERFORM _test_assert_true('api_42b_result_decision', v_row.decision, 'decision should be true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_43: batch with deny_on_first_deny short-circuits
DO $$
DECLARE
    v_decisions boolean[];
BEGIN
    PERFORM _test_setup_api();
    -- No tuples written — first check will be false
    SELECT array_agg(decision ORDER BY ordinality) INTO v_decisions
      FROM authz.check_access_batch_typed('test_api', ARRAY[
          ('user','alice','reader','doc','doc1'),
          ('user','alice','editor','doc','doc1')
      ]::authz.access_check[], p_semantic => 'deny_on_first_deny') WITH ORDINALITY;
    -- First is false, second should be NULL (short-circuited)
    PERFORM _test_assert('api_43_deny_short_circuit', v_decisions::text, '{f,NULL}');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_44: batch with permit_on_first_permit short-circuits
DO $$
DECLARE
    v_decisions boolean[];
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    SELECT array_agg(decision ORDER BY ordinality) INTO v_decisions
      FROM authz.check_access_batch_typed('test_api', ARRAY[
          ('user','alice','reader','doc','doc1'),
          ('user','alice','editor','doc','doc1')
      ]::authz.access_check[], p_semantic => 'permit_on_first_permit') WITH ORDINALITY;
    -- First is true, second should be NULL (short-circuited)
    PERFORM _test_assert('api_44_permit_short_circuit', v_decisions::text, '{t,NULL}');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_45: batch execute_all evaluates all checks
DO $$
DECLARE
    v_decisions boolean[];
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'editor', 'doc', 'doc1');
    SELECT array_agg(decision ORDER BY ordinality) INTO v_decisions
      FROM authz.check_access_batch_typed('test_api', ARRAY[
          ('user','alice','reader','doc','doc1'),
          ('user','alice','editor','doc','doc1')
      ]::authz.access_check[]) WITH ORDINALITY;
    PERFORM _test_assert('api_45_batch_all_true', v_decisions::text, '{t,t}');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_46: batch with empty array returns no rows
DO $$
DECLARE
    v_count int;
BEGIN
    PERFORM _test_setup_api();
    SELECT count(*) INTO v_count
      FROM authz.check_access_batch_typed('test_api', ARRAY[]::authz.access_check[]);
    PERFORM _test_assert('api_46_batch_empty', v_count::text, '0');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- write_tuples_jsonb / delete_tuples_jsonb tests
-- ================================================================

-- api_50: write_tuples_jsonb inserts tuples and returns count
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM _test_assert('api_50_write_tuples_jsonb',
        authz.write_tuples_jsonb('test_api', '[
            {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"},
            {"user_type":"user","user_id":"bob","relation":"reader","object_type":"doc","object_id":"doc1"}
        ]'::jsonb)::text, '2');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_51: write_tuples_jsonb grants access (end-to-end)
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuples_jsonb('test_api', '[
        {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"}
    ]'::jsonb);
    PERFORM _test_assert('api_51_write_tuples_jsonb_grants',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_52: write_tuples_jsonb skips duplicates
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM _test_assert('api_52_write_tuples_jsonb_skip_dup',
        authz.write_tuples_jsonb('test_api', '[
            {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"},
            {"user_type":"user","user_id":"bob","relation":"reader","object_type":"doc","object_id":"doc1"}
        ]'::jsonb)::text, '1');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_53: write_tuples_jsonb with performed_by tracks audit
DO $$
DECLARE
    s smallint;
    v_text text;
BEGIN
    PERFORM _test_setup_api();
    s := authz._s('test_api');
    PERFORM authz.write_tuples_jsonb('test_api', '[
        {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc_j1"}
    ]'::jsonb, p_performed_by => 'json_admin');
    SELECT a.performed_by INTO v_text
      FROM authz.tuples_audit a
     WHERE a.store_id = s AND a.user_id = 'alice'
       AND a.object_id = 'doc_j1' AND a.action = 'INSERT'
     ORDER BY a.performed_at DESC LIMIT 1;
    PERFORM _test_assert('api_53_write_tuples_jsonb_audit', v_text, 'json_admin');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_54: write_tuples_jsonb with optional user_relation
DO $$
DECLARE
    s smallint;
    v_count bigint;
BEGIN
    PERFORM _test_setup_api();
    s := authz._s('test_api');
    -- user_relation omitted — should be treated as NULL (direct tuple)
    PERFORM authz.write_tuples_jsonb('test_api', '[
        {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"}
    ]'::jsonb);
    SELECT count(*) INTO v_count FROM authz.tuples
     WHERE store_id = s AND user_id = 'alice' AND user_relation IS NULL;
    PERFORM _test_assert_true('api_54_jsonb_omit_user_relation', v_count = 1,
        'user_relation should be NULL');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_55: delete_tuples_jsonb deletes tuples and returns count
DO $$
DECLARE v_int integer;
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM authz.write_tuple('test_api', 'user', 'bob',   'reader', 'doc', 'doc1');
    v_int := authz.delete_tuples_jsonb('test_api', '[
        {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"},
        {"user_type":"user","user_id":"bob","relation":"reader","object_type":"doc","object_id":"doc1"}
    ]'::jsonb);
    PERFORM _test_assert('api_55_delete_tuples_jsonb', v_int::text, '2');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_56: delete_tuples_jsonb revokes access (end-to-end)
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM authz.delete_tuples_jsonb('test_api', '[
        {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"}
    ]'::jsonb);
    PERFORM _test_assert('api_56_delete_tuples_jsonb_revokes',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc1')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_57: delete_tuples_jsonb returns 0 for nonexistent tuples
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM _test_assert('api_57_delete_tuples_jsonb_empty',
        authz.delete_tuples_jsonb('test_api', '[
            {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"}
        ]'::jsonb)::text, '0');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- check_access_with_contextual_tuples_jsonb tests
-- ================================================================

-- api_58: contextual tuples via JSONB grant access
DO $$
BEGIN
    PERFORM _test_setup_api();
    -- No stored tuple for alice on doc1
    PERFORM _test_assert('api_58a_no_access_without_ctx',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc1')::text, 'false');
    -- With contextual tuple via JSONB
    PERFORM _test_assert('api_58b_access_with_ctx_jsonb',
        authz.check_access_with_contextual_tuples_jsonb('test_api',
            'user', 'alice', 'reader', 'doc', 'doc1',
            NULL,
            '[{"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"}]'::jsonb
        )::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_59: contextual tuples via JSONB are NOT persisted
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.check_access_with_contextual_tuples_jsonb('test_api',
        'user', 'alice', 'reader', 'doc', 'doc1',
        NULL,
        '[{"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"}]'::jsonb
    );
    PERFORM _test_assert('api_59_ctx_jsonb_not_persisted',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc1')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_60: contextual tuples JSONB with NULL contextual_tuples falls back
DO $$
BEGIN
    PERFORM _test_setup_api();
    -- NULL contextual_tuples should work (no tuples injected)
    PERFORM _test_assert('api_60_ctx_jsonb_null_tuples',
        authz.check_access_with_contextual_tuples_jsonb('test_api',
            'user', 'alice', 'reader', 'doc', 'doc1',
            NULL, NULL
        )::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- check_access_batch_typed_jsonb tests
-- ================================================================

-- api_70: batch JSONB returns correct results for mixed access
DO $$
DECLARE
    v_decisions boolean[];
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    SELECT array_agg(decision ORDER BY ordinality) INTO v_decisions
      FROM authz.check_access_batch_typed_jsonb('test_api', '[
          {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"},
          {"user_type":"user","user_id":"alice","relation":"editor","object_type":"doc","object_id":"doc1"}
      ]'::jsonb) WITH ORDINALITY;
    PERFORM _test_assert('api_70_batch_jsonb_mixed', v_decisions::text, '{t,f}');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_71: batch JSONB with deny_on_first_deny short-circuits
DO $$
DECLARE
    v_decisions boolean[];
BEGIN
    PERFORM _test_setup_api();
    SELECT array_agg(decision ORDER BY ordinality) INTO v_decisions
      FROM authz.check_access_batch_typed_jsonb('test_api', '[
          {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"},
          {"user_type":"user","user_id":"alice","relation":"editor","object_type":"doc","object_id":"doc1"}
      ]'::jsonb, p_semantic => 'deny_on_first_deny') WITH ORDINALITY;
    PERFORM _test_assert('api_71_batch_jsonb_deny_short', v_decisions::text, '{f,NULL}');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_72: batch JSONB result includes input fields
DO $$
DECLARE
    v_row authz.access_check_result;
BEGIN
    PERFORM _test_setup_api();
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    SELECT * INTO v_row
      FROM authz.check_access_batch_typed_jsonb('test_api', '[
          {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"}
      ]'::jsonb) LIMIT 1;
    PERFORM _test_assert('api_72a_result_user_type', v_row.user_type, 'user');
    PERFORM _test_assert('api_72b_result_relation', v_row.relation, 'reader');
    PERFORM _test_assert_true('api_72c_result_decision', v_row.decision, 'decision should be true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_73: batch JSONB validates input (missing key raises error)
DO $$
DECLARE
    v_raised boolean := false;
BEGIN
    PERFORM _test_setup_api();
    BEGIN
        PERFORM authz.check_access_batch_typed_jsonb('test_api', '[
            {"user_type":"user","user_id":"alice","object_type":"doc","object_id":"doc1"}
        ]'::jsonb);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM _test_assert('api_73_batch_jsonb_validates', v_raised::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_74: batch JSONB with empty array returns no rows
DO $$
DECLARE
    v_count int;
BEGIN
    PERFORM _test_setup_api();
    SELECT count(*) INTO v_count
      FROM authz.check_access_batch_typed_jsonb('test_api', '[]'::jsonb);
    PERFORM _test_assert('api_74_batch_jsonb_empty', v_count::text, '0');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- JSONB validation tests (_validate_tuple_jsonb)
-- ================================================================

-- api_61: missing required key raises error
DO $$
DECLARE
    v_raised boolean := false;
    v_msg    text;
BEGIN
    PERFORM _test_setup_api();
    BEGIN
        -- "usr_type" is a typo — should be "user_type"
        PERFORM authz.write_tuples_jsonb('test_api', '[
            {"usr_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"}
        ]'::jsonb);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
        v_msg := SQLERRM;
    END;
    PERFORM _test_assert('api_61a_missing_key_raises', v_raised::text, 'true');
    PERFORM _test_assert_true('api_61b_error_mentions_key',
        v_msg LIKE '%user_type%', v_msg);
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_62: null required value raises error
DO $$
DECLARE
    v_raised boolean := false;
    v_msg    text;
BEGIN
    PERFORM _test_setup_api();
    BEGIN
        PERFORM authz.write_tuples_jsonb('test_api', '[
            {"user_type":"user","user_id":null,"relation":"reader","object_type":"doc","object_id":"doc1"}
        ]'::jsonb);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
        v_msg := SQLERRM;
    END;
    PERFORM _test_assert('api_62a_null_required_raises', v_raised::text, 'true');
    PERFORM _test_assert_true('api_62b_error_mentions_user_id',
        v_msg LIKE '%user_id%', v_msg);
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_63: non-array input raises error
DO $$
DECLARE
    v_raised boolean := false;
    v_msg    text;
BEGIN
    PERFORM _test_setup_api();
    BEGIN
        PERFORM authz.write_tuples_jsonb('test_api', '{"not":"an_array"}'::jsonb);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
        v_msg := SQLERRM;
    END;
    PERFORM _test_assert('api_63a_non_array_raises', v_raised::text, 'true');
    PERFORM _test_assert_true('api_63b_error_mentions_array',
        v_msg LIKE '%JSON array%', v_msg);
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_64: non-object element raises error
DO $$
DECLARE
    v_raised boolean := false;
    v_msg    text;
BEGIN
    PERFORM _test_setup_api();
    BEGIN
        PERFORM authz.write_tuples_jsonb('test_api', '["not_an_object"]'::jsonb);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
        v_msg := SQLERRM;
    END;
    PERFORM _test_assert('api_64a_non_object_raises', v_raised::text, 'true');
    PERFORM _test_assert_true('api_64b_error_mentions_object',
        v_msg LIKE '%JSON object%', v_msg);
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_65: error message includes tuple index
DO $$
DECLARE
    v_raised boolean := false;
    v_msg    text;
BEGIN
    PERFORM _test_setup_api();
    BEGIN
        -- First tuple is valid, second is missing object_id
        PERFORM authz.write_tuples_jsonb('test_api', '[
            {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"},
            {"user_type":"user","user_id":"bob","relation":"reader","object_type":"doc"}
        ]'::jsonb);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
        v_msg := SQLERRM;
    END;
    PERFORM _test_assert('api_65a_index_in_error', v_raised::text, 'true');
    PERFORM _test_assert_true('api_65b_mentions_index_1',
        v_msg LIKE '%index 1%', v_msg);
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_66: validation also works for delete_tuples_jsonb
DO $$
DECLARE
    v_raised boolean := false;
BEGIN
    PERFORM _test_setup_api();
    BEGIN
        PERFORM authz.delete_tuples_jsonb('test_api', '[
            {"user_type":"user","relation":"reader","object_type":"doc","object_id":"doc1"}
        ]'::jsonb);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM _test_assert('api_66_delete_jsonb_validates', v_raised::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_67: validation also works for check_access_with_contextual_tuples_jsonb
DO $$
DECLARE
    v_raised boolean := false;
BEGIN
    PERFORM _test_setup_api();
    BEGIN
        PERFORM authz.check_access_with_contextual_tuples_jsonb('test_api',
            'user', 'alice', 'reader', 'doc', 'doc1',
            NULL,
            '[{"usr_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"}]'::jsonb
        );
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM _test_assert('api_67_ctx_jsonb_validates', v_raised::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_68: empty JSON array is accepted (no tuples to insert)
DO $$
BEGIN
    PERFORM _test_setup_api();
    PERFORM _test_assert('api_68_empty_array_ok',
        authz.write_tuples_jsonb('test_api', '[]'::jsonb)::text, '0');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- delete_store tests (uses its own store, independent of test_api)
-- ================================================================

-- api_29-32: delete_store creates, verifies, deletes, and checks cleanup
DO $$
DECLARE
    ds smallint;
    v_count bigint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_delete_store'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_delete_store');
    ds := authz._s('test_delete_store');

    INSERT INTO authz.types (store_id, name) VALUES (ds, 'user'), (ds, 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES (ds, 'reader');
    PERFORM authz._ensure_tuple_partition(ds, 'doc');
    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, tupleset_relation, tupleset_computed)
    VALUES (ds, authz._t(ds, 'doc'), authz._r(ds, 'reader'),
            authz._rel_direct(), NULL, NULL, NULL);
    PERFORM authz.write_tuple('test_delete_store', 'user', 'u1', 'reader', 'doc', 'doc1');

    PERFORM _test_assert('api_29_store_accessible_before_delete',
        authz.check_access('test_delete_store', 'user', 'u1', 'reader', 'doc', 'doc1')::text, 'true');

    PERFORM authz.delete_store('test_delete_store');

    SELECT count(*) INTO v_count FROM authz.stores WHERE name = 'test_delete_store';
    PERFORM _test_assert('api_30_delete_store_removes_store', v_count::text, '0');

    SELECT count(*) INTO v_count
      FROM authz.types WHERE name IN ('user', 'doc')
       AND store_id NOT IN (SELECT id FROM authz.stores);
    PERFORM _test_assert('api_31_delete_store_cleans_types', v_count::text, '0');

    SELECT count(*) INTO v_count
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'authz'
       AND c.relname = 'tuples_test_delete_store_doc'
       AND c.relispartition;
    PERFORM _test_assert('api_32_delete_store_drops_partition', v_count::text, '0');
END;
$$;
-- No store-specific teardown needed (store already deleted by the test).
-- Drain results for IDE visibility.
DELETE FROM _test_results RETURNING *;

-- ================================================================
-- Unknown name validation: a typo'd store/type/relation name must
-- raise instead of silently denying (or silently reporting
-- "nothing deleted"). User/object IDs are data, not schema — they
-- are never validated.
-- ================================================================

SELECT _test_setup_api();

-- api_80: check_access raises on unknown store
DO $$
BEGIN
    PERFORM authz.check_access('no_such_store', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM _test_assert_true('api_80_check_access_unknown_store_raises', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('api_80_check_access_unknown_store_raises',
        SQLERRM LIKE 'Unknown store%', SQLERRM);
END;
$$;

-- api_81: check_access raises on unknown user type
DO $$
BEGIN
    PERFORM authz.check_access('test_api', 'no_such_type', 'alice', 'reader', 'doc', 'doc1');
    PERFORM _test_assert_true('api_81_check_access_unknown_user_type_raises', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('api_81_check_access_unknown_user_type_raises',
        SQLERRM LIKE 'Unknown type%', SQLERRM);
END;
$$;

-- api_82: check_access raises on unknown relation
DO $$
BEGIN
    PERFORM authz.check_access('test_api', 'user', 'alice', 'no_such_relation', 'doc', 'doc1');
    PERFORM _test_assert_true('api_82_check_access_unknown_relation_raises', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('api_82_check_access_unknown_relation_raises',
        SQLERRM LIKE 'Unknown relation%', SQLERRM);
END;
$$;

-- api_83: check_access raises on unknown object type
DO $$
BEGIN
    PERFORM authz.check_access('test_api', 'user', 'alice', 'reader', 'no_such_type', 'doc1');
    PERFORM _test_assert_true('api_83_check_access_unknown_object_type_raises', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('api_83_check_access_unknown_object_type_raises',
        SQLERRM LIKE 'Unknown type%', SQLERRM);
END;
$$;

-- api_84: list_objects raises on unknown store
DO $$
BEGIN
    PERFORM authz.list_objects('no_such_store', 'user', 'alice', 'reader', 'doc');
    PERFORM _test_assert_true('api_84_list_objects_unknown_store_raises', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('api_84_list_objects_unknown_store_raises',
        SQLERRM LIKE 'Unknown store%', SQLERRM);
END;
$$;

-- api_85: audit_check_access raises on unknown relation
DO $$
BEGIN
    PERFORM authz.audit_check_access('test_api', 'user', 'alice', 'no_such_relation', 'doc', 'doc1', now());
    PERFORM _test_assert_true('api_85_audit_check_unknown_relation_raises', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('api_85_audit_check_unknown_relation_raises',
        SQLERRM LIKE 'Unknown relation%', SQLERRM);
END;
$$;

-- api_86: delete_tuple raises on unknown relation (instead of returning
-- false as if the tuple were already gone)
DO $$
BEGIN
    PERFORM authz.delete_tuple('test_api', 'user', 'alice', 'no_such_relation', 'doc', 'doc1');
    PERFORM _test_assert_true('api_86_delete_tuple_unknown_relation_raises', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('api_86_delete_tuple_unknown_relation_raises',
        SQLERRM LIKE 'Unknown relation%', SQLERRM);
END;
$$;

-- api_87: unknown object/user IDs are data, not schema — still plain deny
DO $$
BEGIN
    PERFORM _test_assert('api_87_unknown_ids_still_plain_deny',
        authz.check_access('test_api', 'user', 'no_such_user', 'reader', 'doc', 'no_such_doc')::text, 'false');
END;
$$;

SELECT * FROM _test_teardown_api();

-- ================================================================
-- Audit replay ordering: when two events for the same tuple carry an
-- identical performed_at timestamp — the normal case now that audit rows
-- are stamped with the transaction timestamp, so all events in one
-- transaction tie — the later-inserted event (higher seq) must win during
-- time-travel reconstruction, not an arbitrary pick.
--
-- The tuple events are backdated, but the model is versioned too, so we
-- probe at clock_timestamp() (after the model was created in setup) —
-- the reconstructed model must include the reader rule for the check to
-- reach the tuple evaluation this test is about.
-- ================================================================
SELECT _test_setup_api();
DO $$
DECLARE
    s  smallint := authz._s('test_api');
    ts timestamptz := now() - interval '1 hour';
BEGIN
    -- doc_tie1: granted then revoked in the same microsecond -> no access
    INSERT INTO authz.tuples_audit (action, performed_at, performed_by,
        store_id, user_type, user_id, relation, object_type, object_id)
    VALUES
        ('INSERT', ts, '_tie_probe', s, authz._t(s, 'user'), 'alice',
         authz._r(s, 'reader'), authz._t(s, 'doc'), 'doc_tie1'),
        ('DELETE', ts, '_tie_probe', s, authz._t(s, 'user'), 'alice',
         authz._r(s, 'reader'), authz._t(s, 'doc'), 'doc_tie1');

    PERFORM _test_assert('api_88_audit_tie_insert_then_delete_denies',
        authz.audit_check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc_tie1',
            clock_timestamp())::text, 'false');

    -- doc_tie2: revoked then re-granted in the same microsecond -> access
    INSERT INTO authz.tuples_audit (action, performed_at, performed_by,
        store_id, user_type, user_id, relation, object_type, object_id)
    VALUES
        ('DELETE', ts, '_tie_probe', s, authz._t(s, 'user'), 'alice',
         authz._r(s, 'reader'), authz._t(s, 'doc'), 'doc_tie2'),
        ('INSERT', ts, '_tie_probe', s, authz._t(s, 'user'), 'alice',
         authz._r(s, 'reader'), authz._t(s, 'doc'), 'doc_tie2');

    PERFORM _test_assert('api_89_audit_tie_delete_then_insert_allows',
        authz.audit_check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc_tie2',
            clock_timestamp())::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- SECURITY DEFINER hygiene: every definer function must pin
-- search_path so a caller's search_path cannot influence name
-- resolution inside the trusted code.
-- ================================================================
DO $$
BEGIN
    PERFORM _test_assert('api_90_all_security_definer_functions_pin_search_path',
        (SELECT count(*) FROM pg_catalog.pg_proc p
           JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'authz'
            AND p.prosecdef
            AND (p.proconfig IS NULL OR NOT EXISTS (
                SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%')))::text,
        '0');

    -- api_111: no SECURITY DEFINER function runs as a superuser owner.
    -- Definer functions execute with the owner's privileges, so a
    -- superuser owner would make every one a potential superuser entry
    -- point. They must be owned by the non-superuser authz_owner.
    PERFORM _test_assert('api_111_no_security_definer_owned_by_superuser',
        (SELECT count(*) FROM pg_catalog.pg_proc p
           JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
           JOIN pg_catalog.pg_roles  r ON r.oid = p.proowner
          WHERE n.nspname = 'authz' AND p.prosecdef AND r.rolsuper)::text,
        '0');

    -- api_112: the object owner role exists and is NOT a superuser
    PERFORM _test_assert('api_112_authz_owner_is_not_superuser',
        (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = 'authz_owner')::text,
        'false');

    -- api_113: the condition sandbox is still owned by the zero-privilege
    -- authz_eval role (ownership transfer must not capture it)
    PERFORM _test_assert('api_113_exec_condition_owned_by_authz_eval',
        (SELECT proowner::regrole::text FROM pg_catalog.pg_proc
          WHERE proname = '_exec_condition' LIMIT 1),
        'authz_eval');
END;
$$;
DELETE FROM _test_results RETURNING *;

-- ================================================================
-- api_anon boundary: the PostgREST anonymous role is a full READER
-- by design (OPA is the mandatory front door) and must never gain
-- write or admin capabilities.
-- ================================================================
SELECT _test_setup_api();
DO $$
DECLARE
    v_bool boolean;
    v_err  text;
BEGIN
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');

    -- api_91: anonymous role can run read checks
    PERFORM set_config('role', 'api_anon', true);
    v_bool := authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'doc1');
    PERFORM set_config('role', 'none', true);
    PERFORM _test_assert('api_91_anon_can_read', v_bool::text, 'true');

    -- api_92: anonymous role cannot write tuples
    PERFORM set_config('role', 'api_anon', true);
    BEGIN
        PERFORM authz.write_tuple('test_api', 'user', 'bob', 'reader', 'doc', 'doc1');
        v_err := 'no exception raised';
    EXCEPTION WHEN insufficient_privilege THEN
        v_err := NULL;
    END;
    PERFORM set_config('role', 'none', true);
    PERFORM _test_assert_true('api_92_anon_cannot_write', v_err IS NULL, v_err);

    -- api_93: anonymous role cannot manage stores
    PERFORM set_config('role', 'api_anon', true);
    BEGIN
        PERFORM authz.create_store('anon_probe');
        v_err := 'no exception raised';
    EXCEPTION WHEN insufficient_privilege THEN
        v_err := NULL;
    END;
    PERFORM set_config('role', 'none', true);
    PERFORM _test_assert_true('api_93_anon_cannot_admin', v_err IS NULL, v_err);
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- Audit immutability: tuples_audit is append-only. UPDATE is never
-- allowed; DELETE only via sanctioned maintenance (partition row
-- migration, explicit purge in delete_store).
-- ================================================================
SELECT _test_setup_api();
DO $$
DECLARE
    s     smallint := authz._s('test_api');
    v_err text;
    v_cnt bigint;
BEGIN
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'imm1');

    -- api_94: UPDATE on the audit trail is blocked
    BEGIN
        UPDATE authz.tuples_audit SET performed_by = 'tampered' WHERE store_id = s;
        v_err := 'no exception raised';
    EXCEPTION WHEN raise_exception THEN
        v_err := NULL;
    END;
    PERFORM _test_assert_true('api_94_audit_update_blocked', v_err IS NULL, v_err);

    -- api_95: DELETE on the audit trail is blocked
    BEGIN
        DELETE FROM authz.tuples_audit WHERE store_id = s;
        v_err := 'no exception raised';
    EXCEPTION WHEN raise_exception THEN
        v_err := NULL;
    END;
    PERFORM _test_assert_true('api_95_audit_delete_blocked', v_err IS NULL, v_err);

    -- api_96: delete_store preserves the audit history by default
    PERFORM authz.delete_store('test_api');
    SELECT count(*) INTO v_cnt FROM authz.tuples_audit WHERE store_id = s;
    PERFORM _test_assert_true('api_96_delete_store_preserves_audit',
        v_cnt > 0, 'expected audit rows to remain, found ' || v_cnt);
END;
$$;
DELETE FROM _test_results RETURNING *;

-- api_97: delete_store(p_purge_audit => true) removes the history
SELECT _test_setup_api();
DO $$
DECLARE
    s     smallint := authz._s('test_api');
    v_cnt bigint;
BEGIN
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'imm2');
    PERFORM authz.delete_store('test_api', p_purge_audit => true);
    SELECT count(*) INTO v_cnt FROM authz.tuples_audit WHERE store_id = s;
    PERFORM _test_assert('api_97_delete_store_purges_audit_on_request', v_cnt::text, '0');
END;
$$;
DELETE FROM _test_results RETURNING *;

-- ================================================================
-- Conditional tuples in JSONB batch writes: elements may carry
-- optional "condition" / "condition_context" keys.
-- ================================================================
SELECT _test_setup_api();
DO $$
DECLARE
    v_count integer;
BEGIN
    INSERT INTO authz.conditions (store_id, name, expression)
    VALUES (authz._s('test_api'), 'flag_set', $cond$($1->>'ok')::boolean$cond$);

    -- api_98: mixed batch — one plain, one conditional — writes both
    v_count := authz.write_tuples_jsonb('test_api', '[
        {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"plain1"},
        {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"cond1",
         "condition":"flag_set"}
    ]'::jsonb);
    PERFORM _test_assert('api_98_jsonb_batch_mixed_conditional_count', v_count::text, '2');

    -- api_99: the condition is attached — denied without context,
    -- allowed with it (a silently unconditional write would grant both)
    PERFORM _test_assert('api_99a_jsonb_batch_condition_enforced',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'cond1')::text, 'false');
    PERFORM _test_assert('api_99b_jsonb_batch_condition_passes_with_context',
        authz.check_access_with_context('test_api', 'user', 'alice', 'reader', 'doc', 'cond1',
            '{"ok": true}'::jsonb)::text, 'true');
    PERFORM _test_assert('api_99c_jsonb_batch_plain_unconditional',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'plain1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_api();

-- api_100: unknown condition names in a batch element raise
SELECT _test_setup_api();
DO $$
BEGIN
    PERFORM authz.write_tuples_jsonb('test_api', '[
        {"user_type":"user","user_id":"alice","relation":"reader","object_type":"doc","object_id":"cond2",
         "condition":"no_such_condition"}
    ]'::jsonb);
    PERFORM _test_assert_true('api_100_jsonb_batch_unknown_condition_raises', false, 'expected exception');
EXCEPTION WHEN OTHERS THEN
    PERFORM _test_assert_true('api_100_jsonb_batch_unknown_condition_raises', true);
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- write_tuple condition upsert: re-writing an existing tuple with a
-- different condition must apply the new condition (and audit the
-- change), not silently keep the old state.
-- ================================================================
SELECT _test_setup_api();
DO $$
DECLARE
    v_bool boolean;
    v_cnt  bigint;
BEGIN
    INSERT INTO authz.conditions (store_id, name, expression)
    VALUES (authz._s('test_api'), 'flag_set', $cond$($1->>'ok')::boolean$cond$);

    -- api_101: adding a condition to an existing unconditional tuple
    PERFORM authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'up1');
    v_bool := authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'up1',
        p_condition => 'flag_set');
    PERFORM _test_assert('api_101a_condition_change_reports_change', v_bool::text, 'true');
    PERFORM _test_assert('api_101b_condition_now_enforced',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'up1')::text, 'false');
    PERFORM _test_assert('api_101c_condition_passes_with_context',
        authz.check_access_with_context('test_api', 'user', 'alice', 'reader', 'doc', 'up1',
            '{"ok": true}'::jsonb)::text, 'true');

    -- api_102: removing the condition (unconditional write wins)
    v_bool := authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'up1');
    PERFORM _test_assert('api_102a_condition_removal_reports_change', v_bool::text, 'true');
    PERFORM _test_assert('api_102b_tuple_now_unconditional',
        authz.check_access('test_api', 'user', 'alice', 'reader', 'doc', 'up1')::text, 'true');

    -- api_103: identical re-write stays an idempotent no-op
    v_bool := authz.write_tuple('test_api', 'user', 'alice', 'reader', 'doc', 'up1');
    PERFORM _test_assert('api_103_identical_rewrite_noop', v_bool::text, 'false');

    -- api_104: the two condition changes were audited as DELETE+INSERT
    -- pairs: initial INSERT + 2 changes x 2 events = 5 audit rows
    SELECT count(*) INTO v_cnt
      FROM authz.tuples_audit
     WHERE store_id = authz._s('test_api') AND object_id = 'up1';
    PERFORM _test_assert('api_104_condition_changes_audited', v_cnt::text, '5');
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- Model referential integrity: rules and type restrictions must not
-- reference unknown (or other-store) types and relations.
-- ================================================================
SELECT _test_setup_api();
DO $$
DECLARE
    s     smallint := authz._s('test_api');
    v_err text;
BEGIN
    -- api_105: dangling object_type is rejected
    BEGIN
        INSERT INTO authz.models (store_id, object_type, relation, rule_type)
        VALUES (s, 32000::smallint, authz._r(s, 'reader'), authz._rel_direct());
        v_err := 'no exception raised';
    EXCEPTION WHEN foreign_key_violation THEN
        v_err := NULL;
    END;
    PERFORM _test_assert_true('api_105_dangling_object_type_rejected', v_err IS NULL, v_err);

    -- api_106: dangling computed_relation is rejected
    BEGIN
        INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation)
        VALUES (s, authz._t(s, 'doc'), authz._r(s, 'reader'), authz._rel_computed(), 32000::smallint);
        v_err := 'no exception raised';
    EXCEPTION WHEN foreign_key_violation THEN
        v_err := NULL;
    END;
    PERFORM _test_assert_true('api_106_dangling_computed_relation_rejected', v_err IS NULL, v_err);

    -- api_107: a relation belonging to ANOTHER store is rejected.
    -- Uses a dedicated throwaway store so the test does not depend on
    -- any example model being loaded.
    BEGIN PERFORM authz.delete_store('test_api_other'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_api_other');
    INSERT INTO authz.relations (store_id, name)
    VALUES (authz._s('test_api_other'), 'foreign_rel');
    BEGIN
        INSERT INTO authz.models (store_id, object_type, relation, rule_type)
        VALUES (s, authz._t(s, 'doc'),
                authz._r(authz._s('test_api_other'), 'foreign_rel'), authz._rel_direct());
        v_err := 'no exception raised';
    EXCEPTION WHEN foreign_key_violation THEN
        v_err := NULL;
    END;
    PERFORM authz.delete_store('test_api_other');
    PERFORM _test_assert_true('api_107_cross_store_relation_rejected', v_err IS NULL, v_err);

    -- api_108: dangling allowed_user_type in type restrictions is rejected
    BEGIN
        INSERT INTO authz.type_restrictions (store_id, object_type, relation, allowed_user_type)
        VALUES (s, authz._t(s, 'doc'), authz._r(s, 'reader'), 32000::smallint);
        v_err := 'no exception raised';
    EXCEPTION WHEN foreign_key_violation THEN
        v_err := NULL;
    END;
    PERFORM _test_assert_true('api_108_dangling_allowed_user_type_rejected', v_err IS NULL, v_err);
END;
$$;
SELECT * FROM _test_teardown_api();

-- ================================================================
-- check_access_batch (JSONB overload) input validation: malformed
-- payloads must fail with clear validation errors, like the
-- _typed_jsonb variant.
-- ================================================================
SELECT _test_setup_api();
DO $$
DECLARE
    v_err text;
BEGIN
    -- api_109: non-array payload is rejected with a clear message
    BEGIN
        PERFORM authz.check_access_batch('test_api', '{"not": "an array"}'::jsonb);
        v_err := 'no exception raised';
    EXCEPTION WHEN OTHERS THEN
        v_err := CASE WHEN SQLERRM LIKE '%must be a JSON array%' THEN NULL ELSE SQLERRM END;
    END;
    PERFORM _test_assert_true('api_109_batch_jsonb_rejects_non_array', v_err IS NULL, v_err);

    -- api_110: an element missing a required key names the key
    BEGIN
        PERFORM authz.check_access_batch('test_api', '[
            {"user_id":"alice","relation":"reader","object_type":"doc","object_id":"doc1"}
        ]'::jsonb);
        v_err := 'no exception raised';
    EXCEPTION WHEN OTHERS THEN
        v_err := CASE WHEN SQLERRM LIKE '%Missing required key%user_type%' THEN NULL ELSE SQLERRM END;
    END;
    PERFORM _test_assert_true('api_110_batch_jsonb_rejects_missing_key', v_err IS NULL, v_err);
END;
$$;
SELECT * FROM _test_teardown_api();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_api();
DROP FUNCTION IF EXISTS _test_setup_api();

SELECT _test_report('checks');
