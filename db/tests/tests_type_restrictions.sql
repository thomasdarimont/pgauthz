-- Tests for type restriction (write-time validation).
-- Covers: _check_type_restriction, model_add_type_restriction,
--         model_remove_type_restriction, model_remove_type_restrictions,
--         write_tuple validation, write_tuples batch validation,
--         cascade from model_remove_rules and delete_store,
--         import_openfga_model extraction.

SELECT _test_reset();

-- Setup: create test store with model.
CREATE OR REPLACE FUNCTION _test_setup_tr() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_tr'); EXCEPTION WHEN OTHERS THEN NULL; END;

    s := authz.create_store('test_tr');

    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'group'), (s, 'document');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer'), (s, 'editor'), (s, 'member');
    PERFORM authz._ensure_tuple_partition(s, 'user');
    PERFORM authz._ensure_tuple_partition(s, 'group');
    PERFORM authz._ensure_tuple_partition(s, 'document');

    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, tupleset_relation, tupleset_computed)
    VALUES
        (s, authz._t(s, 'document'), authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL),
        (s, authz._t(s, 'document'), authz._r(s, 'editor'), authz._rel_direct(), NULL, NULL, NULL);
    RETURN true;
END;
$$;

-- Teardown: remove test store and return accumulated results.
DROP FUNCTION IF EXISTS _test_teardown_tr();
CREATE OR REPLACE FUNCTION _test_teardown_tr()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_tr');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ================================================================
-- tr_01: No restrictions defined -> write_tuple allows any type (backward compat)
-- ================================================================
DO $$
BEGIN
    PERFORM _test_setup_tr();
    PERFORM _test_assert('tr_01_no_restrictions_any_type',
        authz.write_tuple('test_tr', 'group', 'engineering', 'viewer', 'document', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_02: Restriction [user] -> valid write succeeds
-- ================================================================
DO $$
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    PERFORM _test_assert('tr_02_valid_user_type',
        authz.write_tuple('test_tr', 'user', 'alice', 'viewer', 'document', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_03: Restriction [user] -> invalid user_type rejected
-- ================================================================
DO $$
DECLARE
    v_ok boolean := false;
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    BEGIN
        PERFORM authz.write_tuple('test_tr', 'group', 'engineering', 'viewer', 'document', 'doc1');
    EXCEPTION WHEN OTHERS THEN
        v_ok := true;
    END;
    PERFORM _test_assert_true('tr_03_invalid_user_type_rejected', v_ok,
        'group should be rejected when only user is allowed');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_04: Restriction [user] (no wildcard) -> wildcard * rejected
-- ================================================================
DO $$
DECLARE
    v_ok boolean := false;
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    BEGIN
        PERFORM authz.write_tuple('test_tr', 'user', '*', 'viewer', 'document', 'doc1');
    EXCEPTION WHEN OTHERS THEN
        v_ok := true;
    END;
    PERFORM _test_assert_true('tr_04_wildcard_rejected', v_ok,
        'user:* should be rejected when wildcard is not allowed');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_05: Restriction [user:*] -> wildcard accepted
-- ================================================================
DO $$
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user',
        p_allow_wildcard => true);
    PERFORM _test_assert('tr_05_wildcard_accepted',
        authz.write_tuple('test_tr', 'user', '*', 'viewer', 'document', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_06: Restriction [group#member] -> userset write accepted
-- ================================================================
DO $$
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'group',
        p_allowed_user_relation => 'member');
    PERFORM _test_assert('tr_06_userset_accepted',
        authz.write_tuple('test_tr', 'group', 'engineering', 'viewer', 'document', 'doc1',
            p_user_relation => 'member')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_07: Restriction [group#member] -> direct group write rejected (no user_relation)
-- ================================================================
DO $$
DECLARE
    v_ok boolean := false;
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'group',
        p_allowed_user_relation => 'member');
    BEGIN
        PERFORM authz.write_tuple('test_tr', 'group', 'engineering', 'viewer', 'document', 'doc1');
    EXCEPTION WHEN OTHERS THEN
        v_ok := true;
    END;
    PERFORM _test_assert_true('tr_07_direct_group_rejected', v_ok,
        'direct group write should be rejected when only group#member is allowed');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_08: Multiple restrictions [user, group#member] -> both forms accepted
-- ================================================================
DO $$
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'group',
        p_allowed_user_relation => 'member');
    PERFORM _test_assert('tr_08_multi_user',
        authz.write_tuple('test_tr', 'user', 'alice', 'viewer', 'document', 'doc1')::text, 'true');
    PERFORM _test_assert('tr_08_multi_userset',
        authz.write_tuple('test_tr', 'group', 'engineering', 'viewer', 'document', 'doc1',
            p_user_relation => 'member')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_09: write_tuples batch with invalid tuple -> exception
-- ================================================================
DO $$
DECLARE
    v_ok boolean := false;
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    BEGIN
        PERFORM authz.write_tuples('test_tr', ARRAY[
            ('user','alice',NULL,'viewer','document','doc1'),
            ('group','engineering',NULL,'viewer','document','doc2')
        ]::authz.tuple_input[]);
    EXCEPTION WHEN OTHERS THEN
        v_ok := true;
    END;
    PERFORM _test_assert_true('tr_09_batch_invalid_rejected', v_ok,
        'batch with invalid tuple should raise exception');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_10: write_tuples batch all valid -> success
-- ================================================================
DO $$
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'editor', 'user');
    PERFORM _test_assert('tr_10_batch_valid',
        authz.write_tuples('test_tr', ARRAY[
            ('user','alice',NULL,'viewer','document','doc1'),
            ('user','bob',NULL,'editor','document','doc1')
        ]::authz.tuple_input[])::text, '2');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_11: model_remove_type_restrictions -> subsequent writes unrestricted
-- ================================================================
DO $$
DECLARE
    v_removed int;
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    v_removed := authz.model_remove_type_restrictions('test_tr', 'document', 'viewer');
    PERFORM _test_assert('tr_11_removed_count', v_removed::text, '1');
    -- Now group should be allowed again (no restrictions)
    PERFORM _test_assert('tr_11_unrestricted_after_remove',
        authz.write_tuple('test_tr', 'group', 'engineering', 'viewer', 'document', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_12: model_remove_rules cascades type restriction deletion
-- ================================================================
DO $$
DECLARE
    v_count int;
BEGIN
    PERFORM _test_setup_tr();
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    PERFORM authz.model_remove_rules('test_tr', 'document', 'viewer');
    SELECT count(*) INTO v_count FROM authz.type_restrictions
     WHERE store_id = authz._s('test_tr')
       AND object_type = authz._t('test_tr', 'document')
       AND relation = authz._r('test_tr', 'viewer');
    PERFORM _test_assert('tr_12_cascade_remove_rules', v_count::text, '0');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_13: delete_store cleans up type restrictions
-- ================================================================
DO $$
DECLARE
    v_store_id smallint;
    v_count int;
BEGIN
    PERFORM _test_setup_tr();
    v_store_id := authz._s('test_tr');
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    PERFORM authz.delete_store('test_tr');
    SELECT count(*) INTO v_count FROM authz.type_restrictions WHERE store_id = v_store_id;
    PERFORM _test_assert('tr_13_delete_store_cleanup', v_count::text, '0');
END;
$$;
-- Store already deleted by test — just drain results, skip teardown.
DELETE FROM _test_results RETURNING *;

-- ================================================================
-- tr_14: model_add_type_restriction idempotent
-- ================================================================
DO $$
DECLARE
    v_id1 smallint;
    v_id2 smallint;
BEGIN
    PERFORM _test_setup_tr();
    v_id1 := authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    v_id2 := authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    PERFORM _test_assert('tr_14_idempotent', v_id1::text, v_id2::text);
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_15: import_openfga_model extracts directly_related_user_types
-- ================================================================
DO $$
DECLARE
    v_result jsonb;
    v_count  int;
BEGIN
    BEGIN PERFORM authz.delete_store('test_tr_openfga'); EXCEPTION WHEN OTHERS THEN NULL; END;

    v_result := authz.import_openfga_model('test_tr_openfga', '{
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "user"},
            {"type": "group",
             "relations": {
                "member": {"this": {}}
             },
             "metadata": {
                "relations": {
                    "member": {
                        "directly_related_user_types": [
                            {"type": "user"}
                        ]
                    }
                }
             }
            },
            {"type": "document",
             "relations": {
                "viewer": {
                    "this": {}
                }
             },
             "metadata": {
                "relations": {
                    "viewer": {
                        "directly_related_user_types": [
                            {"type": "user"},
                            {"type": "user", "wildcard": {}},
                            {"type": "group", "relation": "member"}
                        ]
                    }
                }
             }
            }
        ]
    }'::jsonb);

    PERFORM _test_assert('tr_15_import_has_restrictions',
        (v_result->>'type_restrictions_imported')::text, '4');

    -- Verify restrictions were actually created
    SELECT count(*) INTO v_count FROM authz.type_restrictions
     WHERE store_id = authz._s('test_tr_openfga')
       AND object_type = authz._t('test_tr_openfga', 'document')
       AND relation = authz._r('test_tr_openfga', 'viewer');
    PERFORM _test_assert('tr_15_import_viewer_restrictions', v_count::text, '3');

    PERFORM authz.delete_store('test_tr_openfga');
END;
$$;
-- test_tr_openfga already deleted above; just drain results.
DELETE FROM _test_results RETURNING *;

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_tr();
DROP FUNCTION IF EXISTS _test_setup_tr();

-- ================================================================
-- Summary
-- ================================================================
SELECT _test_report('type restriction checks');
