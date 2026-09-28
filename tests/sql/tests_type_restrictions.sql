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

-- ================================================================
-- tr_16: condition-bound facets (migration 0015) — `[user, user:* with cond]`
-- ================================================================
DO $$
DECLARE
    s        integer;
    v_msg    text;
    v_export jsonb;
    v_n      int;
BEGIN
    PERFORM _test_setup_tr();
    s := authz._s('test_tr');
    INSERT INTO authz.conditions (store_id, name, expression, required_context) VALUES
        (s, 'cond',  'coalesce(($1->>''k'')::text, '''') = ''ok''', '{"request":["k"]}'::jsonb),
        (s, 'other', 'true', NULL);

    -- viewer: [user, user:* with cond]   editor: [user with cond]
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user');
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'user',
        p_allow_wildcard => true, p_condition => 'cond');
    PERFORM authz.model_add_type_restriction('test_tr', 'document', 'editor', 'user',
        p_condition => 'cond');

    -- a) wildcard viewer WITHOUT the condition: rejected, names the requirement
    BEGIN
        PERFORM authz.write_tuple('test_tr', 'user', '*', 'viewer', 'document', 'd1');
        v_msg := 'no error';
    EXCEPTION WHEN OTHERS THEN v_msg := SQLERRM; END;
    PERFORM _test_assert_true('tr_16a_wildcard_without_required_condition_rejected',
        v_msg LIKE '%requires a condition%cond%', v_msg);

    -- b) with the bound condition: accepted
    PERFORM _test_assert('tr_16b_wildcard_with_required_condition_ok',
        authz.write_tuple('test_tr', 'user', '*', 'viewer', 'document', 'd1', p_condition => 'cond')::text, 'true');

    -- c) with a DIFFERENT condition: rejected
    BEGIN
        PERFORM authz.write_tuple('test_tr', 'user', '*', 'viewer', 'document', 'd2', p_condition => 'other');
        v_msg := 'no error';
    EXCEPTION WHEN OTHERS THEN v_msg := SQLERRM; END;
    PERFORM _test_assert_true('tr_16c_wildcard_with_other_condition_rejected',
        v_msg LIKE '%does not allow condition "other"%', v_msg);

    -- d) the OPEN [user] facet accepts an unconditioned AND a conditioned tuple
    PERFORM _test_assert('tr_16d_open_facet_unconditioned_ok',
        authz.write_tuple('test_tr', 'user', 'alice', 'viewer', 'document', 'd1')::text, 'true');
    PERFORM _test_assert('tr_16d2_open_facet_any_condition_ok',
        authz.write_tuple('test_tr', 'user', 'bob', 'viewer', 'document', 'd1', p_condition => 'other')::text, 'true');

    -- e) editor has ONLY a conditioned facet: unconditioned rejected, bound ok
    BEGIN
        PERFORM authz.write_tuple('test_tr', 'user', 'carol', 'editor', 'document', 'd1');
        v_msg := 'no error';
    EXCEPTION WHEN OTHERS THEN v_msg := SQLERRM; END;
    PERFORM _test_assert_true('tr_16e_direct_without_required_condition_rejected',
        v_msg LIKE '%user as editor on document requires a condition (one of: cond)%', v_msg);
    PERFORM _test_assert('tr_16e2_direct_with_required_condition_ok',
        authz.write_tuple('test_tr', 'user', 'carol', 'editor', 'document', 'd1', p_condition => 'cond')::text, 'true');

    -- f) the composite-type batch path cannot carry a condition → rejected with a hint
    BEGIN
        PERFORM authz.write_tuples('test_tr', ARRAY[
            ROW('user', 'dave', NULL, 'editor', 'document', 'd1')::authz.tuple_input]);
        v_msg := 'no error';
    EXCEPTION WHEN OTHERS THEN v_msg := SQLERRM; END;
    PERFORM _test_assert_true('tr_16f_batch_without_condition_rejected',
        v_msg LIKE 'Type restriction violation(s): user -> editor on document%', v_msg);

    -- g) the JSON batch path with the condition succeeds
    PERFORM _test_assert('tr_16g_jsonb_batch_with_condition_ok',
        authz.write_tuples_jsonb('test_tr',
            '[{"user_type":"user","user_id":"dave","relation":"editor","object_type":"document","object_id":"d1","condition":"cond"}]'::jsonb)::text,
        '1');

    -- h) a bound condition cannot be deleted from under its facets
    BEGIN
        PERFORM authz.delete_condition('test_tr', 'cond');
        v_msg := 'no error';
    EXCEPTION WHEN OTHERS THEN v_msg := SQLERRM; END;
    PERFORM _test_assert_true('tr_16h_bound_condition_delete_refused',
        v_msg LIKE '%required by 2 type restriction facet(s)%', v_msg);
    PERFORM _test_assert('tr_16h2_unbound_condition_delete_ok',
        authz.delete_condition('test_tr', 'other')::text, 'true');

    -- i) binding an unknown condition is an error
    BEGIN
        PERFORM authz.model_add_type_restriction('test_tr', 'document', 'viewer', 'group',
            p_allowed_user_relation => 'member', p_condition => 'nope');
        v_msg := 'no error';
    EXCEPTION WHEN OTHERS THEN v_msg := SQLERRM; END;
    PERFORM _test_assert_true('tr_16i_unknown_condition_rejected',
        v_msg LIKE 'Unknown condition "nope"%', v_msg);

    -- j) describe_model renders the binding, k) the view exposes it
    PERFORM _test_assert_true('tr_16j_describe_shows_with_condition',
        position('[user, user:* with cond]' in authz.describe_model('test_tr')) > 0,
        authz.describe_model('test_tr'));
    SELECT count(*) INTO v_n FROM authz.type_restrictions_view
     WHERE store = 'test_tr' AND relation = 'editor' AND condition = 'cond';
    PERFORM _test_assert('tr_16k_view_condition_column', v_n::text, '1');

    -- l) export carries `condition` only on bound facets (checksum-neutral otherwise)
    v_export := authz.export_model('test_tr');
    SELECT count(*) INTO v_n FROM jsonb_array_elements(v_export->'type_restrictions') e
     WHERE e ? 'condition';
    PERFORM _test_assert('tr_16l_export_bound_facets_have_condition', v_n::text, '2');
    SELECT count(*) INTO v_n FROM jsonb_array_elements(v_export->'type_restrictions') e
     WHERE NOT (e ? 'condition');
    PERFORM _test_assert('tr_16l2_export_open_facets_lack_key', v_n::text, '1');

    -- m) idempotent: the same bound facet again returns the same id
    PERFORM _test_assert('tr_16m_bound_facet_idempotent',
        (authz.model_add_type_restriction('test_tr', 'document', 'editor', 'user', p_condition => 'cond')
         = authz.model_add_type_restriction('test_tr', 'document', 'editor', 'user', p_condition => 'cond'))::text,
        'true');
END;
$$;
SELECT * FROM _test_teardown_tr();

-- ================================================================
-- tr_17: import_openfga_model keeps `with <cond>` facets (previously dropped
-- silently): an undefined condition becomes a deny-all placeholder + warning
-- ================================================================
DO $$
DECLARE
    v_result jsonb;
    v_msg    text;
BEGIN
    BEGIN PERFORM authz.delete_store('test_tr_ofga_cond'); EXCEPTION WHEN OTHERS THEN NULL; END;

    v_result := authz.import_openfga_model('test_tr_ofga_cond', '{
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "user"},
            {"type": "document",
             "relations": {"viewer": {"this": {}}},
             "metadata": {"relations": {"viewer": {"directly_related_user_types": [
                 {"type": "user"},
                 {"type": "user", "wildcard": {}, "condition": "in_office_hours"}
             ]}}}}
        ],
        "conditions": {"in_office_hours": {"name": "in_office_hours",
            "expression": "request.hour >= 8 && request.hour <= 17",
            "parameters": {"hour": {"type_name": "TYPE_NAME_INT"}}}}
    }'::jsonb);

    PERFORM _test_assert('tr_17a_import_counts_bound_facet',
        (v_result->>'type_restrictions_imported')::text, '2');
    PERFORM _test_assert('tr_17b_import_reports_placeholder',
        (v_result->'placeholder_conditions')::text, '["in_office_hours"]');
    PERFORM _test_assert_true('tr_17c_import_warns',
        (v_result->'warnings')::text LIKE '%deny-all placeholder%', (v_result->'warnings')::text);

    -- the facet binding is enforced: wildcard viewer without the condition is rejected
    BEGIN
        PERFORM authz.write_tuple('test_tr_ofga_cond', 'user', '*', 'viewer', 'document', 'd1');
        v_msg := 'no error';
    EXCEPTION WHEN OTHERS THEN v_msg := SQLERRM; END;
    PERFORM _test_assert_true('tr_17d_bound_facet_enforced_after_import',
        v_msg LIKE '%requires a condition (one of: in_office_hours)%', v_msg);

    -- with the condition it is writable but DENIES (placeholder) until defined
    PERFORM authz.write_tuple('test_tr_ofga_cond', 'user', '*', 'viewer', 'document', 'd1',
        p_condition => 'in_office_hours');
    PERFORM _test_assert('tr_17e_placeholder_denies',
        authz.check_access_with_context('test_tr_ofga_cond', 'user', 'zed', 'viewer', 'document', 'd1',
            '{"hour": 10}')::text, 'false');

    -- defining the real expression upserts in place: the binding survives, access works
    PERFORM authz.create_condition_sql('test_tr_ofga_cond', 'in_office_hours',
        '($1->>''hour'')::int BETWEEN 8 AND 17', '{"request":["hour"]}'::jsonb);
    PERFORM _test_assert('tr_17f_defined_condition_allows',
        authz.check_access_with_context('test_tr_ofga_cond', 'user', 'zed', 'viewer', 'document', 'd1',
            '{"hour": 10}')::text, 'true');
    PERFORM _test_assert('tr_17g_binding_survives_redefinition',
        (SELECT count(*)::text FROM authz.type_restrictions_view
          WHERE store = 'test_tr_ofga_cond' AND condition = 'in_office_hours'), '1');

    -- re-import binds to the now-existing condition: no placeholder, no warning
    v_result := authz.import_openfga_model('test_tr_ofga_cond', '{
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "user"},
            {"type": "document",
             "relations": {"viewer": {"this": {}}},
             "metadata": {"relations": {"viewer": {"directly_related_user_types": [
                 {"type": "user", "wildcard": {}, "condition": "in_office_hours"}
             ]}}}}
        ]
    }'::jsonb);
    PERFORM _test_assert('tr_17h_reimport_no_placeholder',
        (v_result->'placeholder_conditions')::text, '[]');

    PERFORM authz.delete_store('test_tr_ofga_cond');
END;
$$;
DELETE FROM _test_results RETURNING *;

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_tr();
DROP FUNCTION IF EXISTS _test_setup_tr();

-- ================================================================
-- Summary
-- ================================================================
SELECT _test_report('type restriction checks');
