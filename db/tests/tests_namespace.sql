-- Tests for namespace-based access control (read and write).
--
-- Uses its own stores with a minimal model:
--   type user
--   type doc       (namespace = 'documents')
--   type open_doc  (namespace = NULL, unrestricted)
--     relations
--       define viewer: [user]

SELECT _test_reset();

-- Setup write store (idempotent). No namespace grants — tests add their own.
DROP FUNCTION IF EXISTS _test_setup_ns_write();
CREATE OR REPLACE FUNCTION _test_setup_ns_write() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_ns_write'); EXCEPTION WHEN OTHERS THEN NULL; END;

    PERFORM authz.create_store('test_ns_write');
    s := authz._s('test_ns_write');

    INSERT INTO authz.types (store_id, name, namespace) VALUES
        (s, 'user', NULL), (s, 'doc', 'documents'), (s, 'open_doc', NULL);
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer');

    PERFORM authz._ensure_tuple_partition(s, 'doc');
    PERFORM authz._ensure_tuple_partition(s, 'open_doc');

    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, tupleset_relation, tupleset_computed)
    VALUES
        (s, authz._t(s, 'doc'),      authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL),
        (s, authz._t(s, 'open_doc'), authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL);

    RETURN true;
END;
$$;

DROP FUNCTION IF EXISTS _test_teardown_ns_write();
CREATE OR REPLACE FUNCTION _test_teardown_ns_write()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_ns_write');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- Setup read store (idempotent). Grants write access and seeds tuples,
-- but does NOT grant read access — tests add their own.
DROP FUNCTION IF EXISTS _test_setup_ns_read();
CREATE OR REPLACE FUNCTION _test_setup_ns_read() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_ns_read'); EXCEPTION WHEN OTHERS THEN NULL; END;

    PERFORM authz.create_store('test_ns_read');
    s := authz._s('test_ns_read');

    INSERT INTO authz.types (store_id, name, namespace) VALUES
        (s, 'user', NULL), (s, 'doc', 'documents'), (s, 'open_doc', NULL);
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer');

    PERFORM authz._ensure_tuple_partition(s, 'doc');
    PERFORM authz._ensure_tuple_partition(s, 'open_doc');

    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, tupleset_relation, tupleset_computed)
    VALUES
        (s, authz._t(s, 'doc'),      authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL),
        (s, authz._t(s, 'open_doc'), authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL);

    PERFORM authz.grant_namespace_access('test_ns_read', 'documents', session_user, p_can_write := true);
    PERFORM authz.write_tuple('test_ns_read', 'user', 'u1', 'viewer', 'doc', 'doc1');
    PERFORM authz.write_tuple('test_ns_read', 'user', 'u1', 'viewer', 'open_doc', 'open1');

    RETURN true;
END;
$$;

DROP FUNCTION IF EXISTS _test_teardown_ns_read();
CREATE OR REPLACE FUNCTION _test_teardown_ns_read()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_ns_read');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ================================================================
-- namespace write access control tests
-- ================================================================

-- ns_w_01: write_tuple succeeds for unrestricted namespace (NULL)
DO $$
BEGIN
    PERFORM _test_setup_ns_write();
    PERFORM _test_assert('ns_w_01_write_unrestricted_namespace',
        authz.write_tuple('test_ns_write', 'user', 'u1', 'viewer', 'open_doc', 'open1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_ns_write();

-- ns_w_02: write_tuple fails for restricted namespace without grant
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_ns_write();
DO $$
DECLARE v_bool boolean;
BEGIN
    v_bool := authz.write_tuple('test_ns_write',
        'user', 'u1', 'viewer', 'doc', 'doc1');
    PERFORM _test_assert_true('ns_w_02_write_blocked_without_grant', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ns_w_02_write_blocked_without_grant',
        SQLERRM LIKE '%Permission denied%namespace%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ns_write();

-- ns_w_03: write_tuple succeeds after namespace grant
DO $$
BEGIN
    PERFORM _test_setup_ns_write();
    PERFORM authz.grant_namespace_access('test_ns_write', 'documents', session_user, p_can_write := true);
    PERFORM _test_assert('ns_w_03_write_after_grant',
        authz.write_tuple('test_ns_write', 'user', 'u1', 'viewer', 'doc', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_ns_write();

-- ns_w_04: delete_tuple succeeds with namespace grant
DO $$
BEGIN
    PERFORM _test_setup_ns_write();
    PERFORM authz.grant_namespace_access('test_ns_write', 'documents', session_user, p_can_write := true);
    PERFORM authz.write_tuple('test_ns_write', 'user', 'u1', 'viewer', 'doc', 'doc1');
    PERFORM _test_assert('ns_w_04_delete_with_grant',
        authz.delete_tuple('test_ns_write', 'user', 'u1', 'viewer', 'doc', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_ns_write();

-- ns_w_05: write_tuples (batch) succeeds with namespace grant
DO $$
BEGIN
    PERFORM _test_setup_ns_write();
    PERFORM authz.grant_namespace_access('test_ns_write', 'documents', session_user, p_can_write := true);
    PERFORM _test_assert('ns_w_05_write_tuples_batch_with_grant',
        authz.write_tuples('test_ns_write', ARRAY[
            ROW('user', 'u1', NULL, 'viewer', 'doc', 'doc2'),
            ROW('user', 'u2', NULL, 'viewer', 'doc', 'doc3')
        ]::authz.tuple_input[])::text, '2');
END;
$$;
SELECT * FROM _test_teardown_ns_write();

-- ns_w_06: delete_tuples (batch) succeeds with namespace grant
DO $$
DECLARE v_int integer;
BEGIN
    PERFORM _test_setup_ns_write();
    PERFORM authz.grant_namespace_access('test_ns_write', 'documents', session_user, p_can_write := true);
    PERFORM authz.write_tuples('test_ns_write', ARRAY[
        ROW('user', 'u1', NULL, 'viewer', 'doc', 'doc2'),
        ROW('user', 'u2', NULL, 'viewer', 'doc', 'doc3')
    ]::authz.tuple_input[]);
    v_int := authz.delete_tuples('test_ns_write', ARRAY[
        ROW('user', 'u1', NULL, 'viewer', 'doc', 'doc2'),
        ROW('user', 'u2', NULL, 'viewer', 'doc', 'doc3')
    ]::authz.tuple_input[]);
    PERFORM _test_assert('ns_w_06_delete_tuples_batch_with_grant', v_int::text, '2');
END;
$$;
SELECT * FROM _test_teardown_ns_write();

-- ================================================================
-- namespace read access control tests
-- ================================================================

-- ns_r_01: check_access succeeds for unrestricted namespace (NULL)
DO $$
BEGIN
    PERFORM _test_setup_ns_read();
    PERFORM _test_assert('ns_r_01_check_access_unrestricted_namespace',
        authz.check_access('test_ns_read', 'user', 'u1', 'viewer', 'open_doc', 'open1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_ns_read();

-- ns_r_02: check_access fails for restricted namespace without reader grant
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_ns_read();
DO $$
DECLARE v_bool boolean;
BEGIN
    v_bool := authz.check_access('test_ns_read',
        'user', 'u1', 'viewer', 'doc', 'doc1');
    PERFORM _test_assert_true('ns_r_02_check_access_blocked_without_read_grant', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ns_r_02_check_access_blocked_without_read_grant',
        SQLERRM LIKE '%Permission denied%cannot query%namespace%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ns_read();

-- ns_r_03: check_access succeeds after namespace reader grant
DO $$
BEGIN
    PERFORM _test_setup_ns_read();
    PERFORM authz.grant_namespace_access('test_ns_read', 'documents', session_user, p_can_read := true);
    PERFORM _test_assert('ns_r_03_check_access_after_read_grant',
        authz.check_access('test_ns_read', 'user', 'u1', 'viewer', 'doc', 'doc1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_ns_read();

-- ns_r_04: list_objects blocked without reader grant
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_ns_read();
DO $$
BEGIN
    PERFORM authz.list_objects('test_ns_read', 'user', 'u1', 'viewer', 'doc');
    PERFORM _test_assert_true('ns_r_04_list_objects_blocked', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ns_r_04_list_objects_blocked',
        SQLERRM LIKE '%Permission denied%cannot query%namespace%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ns_read();

-- ns_r_05: list_subjects blocked without reader grant
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_ns_read();
DO $$
BEGIN
    PERFORM authz.list_subjects('test_ns_read', 'user', 'viewer', 'doc', 'doc1');
    PERFORM _test_assert_true('ns_r_05_list_subjects_blocked', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ns_r_05_list_subjects_blocked',
        SQLERRM LIKE '%Permission denied%cannot query%namespace%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ns_read();

-- ns_r_06: list_actions blocked without reader grant
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_ns_read();
DO $$
BEGIN
    PERFORM authz.list_actions('test_ns_read', 'user', 'u1', 'doc', 'doc1');
    PERFORM _test_assert_true('ns_r_06_list_actions_blocked', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ns_r_06_list_actions_blocked',
        SQLERRM LIKE '%Permission denied%cannot query%namespace%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ns_read();

-- ns_r_07: explain_access blocked without reader grant
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_ns_read();
DO $$
BEGIN
    PERFORM authz.explain_access('test_ns_read', 'user', 'u1', 'viewer', 'doc', 'doc1');
    PERFORM _test_assert_true('ns_r_07_explain_access_blocked', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ns_r_07_explain_access_blocked',
        SQLERRM LIKE '%Permission denied%cannot query%namespace%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ns_read();

-- ns_r_08: contextual tuples referencing restricted namespace blocked without grant
-- (setup outside DO block: exception handler rolls back the block)
SELECT _test_setup_ns_read();
DO $$
DECLARE v_bool boolean;
BEGIN
    v_bool := authz.check_access_with_contextual_tuples('test_ns_read',
        'user', 'u1', 'viewer', 'open_doc', 'open1',
        contextual_tuples => ARRAY[
            ROW('user', 'u1', NULL, 'viewer', 'doc', 'doc1')
        ]::authz.tuple_input[]
    );
    PERFORM _test_assert_true('ns_r_08_contextual_tuple_namespace_blocked', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ns_r_08_contextual_tuple_namespace_blocked',
        SQLERRM LIKE '%Permission denied%namespace%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ns_read();

-- ns_r_09: all read functions succeed after namespace reader grant
DO $$
DECLARE
    v_bool boolean;
    v_all_pass boolean := true;
BEGIN
    PERFORM _test_setup_ns_read();
    PERFORM authz.grant_namespace_access('test_ns_read', 'documents', session_user, p_can_read := true);

    v_bool := authz.check_access('test_ns_read',
        'user', 'u1', 'viewer', 'doc', 'doc1');
    IF NOT v_bool THEN v_all_pass := false; END IF;

    PERFORM authz.list_objects('test_ns_read', 'user', 'u1', 'viewer', 'doc');
    PERFORM authz.list_subjects('test_ns_read', 'user', 'viewer', 'doc', 'doc1');
    PERFORM authz.list_actions('test_ns_read', 'user', 'u1', 'doc', 'doc1');
    PERFORM authz.explain_access('test_ns_read', 'user', 'u1', 'viewer', 'doc', 'doc1');

    PERFORM _test_assert_true('ns_r_09_all_read_functions_after_grant', v_all_pass);
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ns_r_09_all_read_functions_after_grant', false, SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ns_read();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_ns_read();
DROP FUNCTION IF EXISTS _test_setup_ns_read();
DROP FUNCTION IF EXISTS _test_teardown_ns_write();
DROP FUNCTION IF EXISTS _test_setup_ns_write();

SELECT _test_report('namespace checks');
