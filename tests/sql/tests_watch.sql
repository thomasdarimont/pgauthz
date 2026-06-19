-- Tests for the Watch / changefeed API (authz.watch_changes / watch_cursor).
--
-- watch_changes streams tuple changes from the immutable tuples_audit log,
-- cursored by (performed_at, seq) and gated by a stability lag so a poller never
-- skips a row committed out of seq-assignment order. See db/engine/watch.sql.

SELECT _test_reset();

DROP FUNCTION IF EXISTS _test_setup_watch(text);
CREATE FUNCTION _test_setup_watch(p_store text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store(p_store); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store(p_store);
    s := authz._s(p_store);
    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc'), (s, 'folder');
    -- 'doc' lives in the 'docs' namespace; 'folder' is unnamespaced. Grant the
    -- test's own role write access so the namespaced 'doc' writes are permitted.
    UPDATE authz.types SET namespace = 'docs' WHERE store_id = s AND name = 'doc';
    PERFORM authz.grant_namespace_access(p_store, 'docs', session_user,
                                         p_can_read := true, p_can_write := true);
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer'), (s, 'editor');
    PERFORM authz._ensure_tuple_partition(s, 'doc');
    PERFORM authz._ensure_tuple_partition(s, 'folder');
    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, tupleset_relation, tupleset_computed)
    VALUES (s, authz._t(s, 'doc'),    authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL),
           (s, authz._t(s, 'doc'),    authz._r(s, 'editor'), authz._rel_direct(), NULL, NULL, NULL),
           (s, authz._t(s, 'folder'), authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL),
           (s, authz._t(s, 'folder'), authz._r(s, 'editor'), authz._rel_direct(), NULL, NULL, NULL);
END;
$$;

SELECT _test_setup_watch('test_watch');

-- Two writes in separate (autocommit) transactions → distinct performed_at.
SELECT authz.write_tuple('test_watch', 'user', 'alice', 'viewer', 'doc', 'doc1');
SELECT authz.write_tuple('test_watch', 'user', 'bob',   'viewer', 'doc', 'doc2');

-- w_01: returns both changes, decoded to names, ordered, action=INSERT.
DO $$
DECLARE n int; obj text; rel text; act text;
BEGIN
    SELECT count(*) INTO n FROM authz.watch_changes('test_watch', p_lag => '0 seconds');
    PERFORM _test_assert('w_01_returns_two', n::text, '2');
    SELECT object_type, relation, action INTO obj, rel, act
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds') ORDER BY seq LIMIT 1;
    PERFORM _test_assert('w_01_decoded_object_type', obj, 'doc');
    PERFORM _test_assert('w_01_decoded_relation', rel, 'viewer');
    PERFORM _test_assert('w_01_action_insert', act, 'INSERT');
END $$;

-- w_02: a cursor at the latest change sees nothing new; a later write appears.
DO $$
DECLARE c_at timestamptz; c_seq bigint; n int; obj text;
BEGIN
    SELECT performed_at, seq INTO c_at, c_seq
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds')
     ORDER BY performed_at DESC, seq DESC LIMIT 1;

    SELECT count(*) INTO n FROM authz.watch_changes('test_watch', c_at, c_seq, p_lag => '0 seconds');
    PERFORM _test_assert('w_02_cursor_no_new', n::text, '0');

    PERFORM authz.write_tuple('test_watch', 'user', 'carol', 'viewer', 'doc', 'doc3');
    SELECT count(*), max(object_id) INTO n, obj
      FROM authz.watch_changes('test_watch', c_at, c_seq, p_lag => '0 seconds');
    PERFORM _test_assert('w_02_cursor_returns_only_new', n::text, '1');
    PERFORM _test_assert('w_02_cursor_new_is_doc3', obj, 'doc3');
END $$;

-- w_03: a delete is recorded as a DELETE change.
SELECT authz.delete_tuple('test_watch', 'user', 'alice', 'viewer', 'doc', 'doc1');
DO $$
DECLARE act text;
BEGIN
    SELECT action INTO act FROM authz.watch_changes('test_watch', p_lag => '0 seconds')
     WHERE object_id = 'doc1' AND action = 'DELETE' ORDER BY seq DESC LIMIT 1;
    PERFORM _test_assert('w_03_delete_recorded', coalesce(act, '<none>'), 'DELETE');
END $$;

-- w_04: store isolation — another store's changes never appear.
SELECT _test_setup_watch('test_watch2');
SELECT authz.write_tuple('test_watch2', 'user', 'zoe', 'viewer', 'doc', 'doc_other');
DO $$
DECLARE n_other int; n_self int;
BEGIN
    SELECT count(*) INTO n_other FROM authz.watch_changes('test_watch', p_lag => '0 seconds')
     WHERE object_id = 'doc_other';
    SELECT count(*) INTO n_self FROM authz.watch_changes('test_watch2', p_lag => '0 seconds');
    PERFORM _test_assert('w_04_isolation_other_absent', n_other::text, '0');
    PERFORM _test_assert('w_04_isolation_self_present', n_self::text, '1');
END $$;

-- w_05: the stability lag hides fresh rows; lag 0 reveals them.
SELECT authz.write_tuple('test_watch', 'user', 'dave', 'viewer', 'doc', 'doc_lag');
DO $$
DECLARE n_big int; n_zero int;
BEGIN
    SELECT count(*) INTO n_big FROM authz.watch_changes('test_watch', p_lag => '1 hour')
     WHERE object_id = 'doc_lag';
    SELECT count(*) INTO n_zero FROM authz.watch_changes('test_watch', p_lag => '0 seconds')
     WHERE object_id = 'doc_lag';
    PERFORM _test_assert('w_05_lag_hides_fresh', n_big::text, '0');
    PERFORM _test_assert('w_05_lag0_reveals', n_zero::text, '1');
END $$;

-- w_06: watch_cursor reports the store's current high-water seq.
DO $$
DECLARE cur_seq bigint; mx bigint;
BEGIN
    SELECT seq INTO cur_seq FROM authz.watch_cursor('test_watch');
    SELECT max(seq) INTO mx FROM authz.tuples_audit WHERE store_id = authz._s('test_watch');
    PERFORM _test_assert('w_06_cursor_is_max_seq', cur_seq::text, mx::text);
END $$;

-- w_07: object-type filter (array) returns only the requested types' changes.
SELECT authz.write_tuple('test_watch', 'user', 'fred', 'viewer', 'folder', 'folder1');
DO $$
DECLARE n_folder int; n_nonfolder int;
BEGIN
    SELECT count(*) INTO n_folder
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds', p_object_types => ARRAY['folder']);
    SELECT count(*) INTO n_nonfolder
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds', p_object_types => ARRAY['folder'])
     WHERE object_type <> 'folder';
    PERFORM _test_assert_true('w_07_type_filter_has_folder', n_folder >= 1, n_folder::text);
    PERFORM _test_assert('w_07_type_filter_excludes_others', n_nonfolder::text, '0');
END $$;

-- w_08: multiple types in one array returns changes for all of them.
DO $$
DECLARE n_both int; n_outside int;
BEGIN
    SELECT count(*) INTO n_both
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds', p_object_types => ARRAY['doc','folder']);
    SELECT count(*) INTO n_outside
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds', p_object_types => ARRAY['doc','folder'])
     WHERE object_type NOT IN ('doc','folder');
    PERFORM _test_assert_true('w_08_type_array_covers_both', n_both >= 2, n_both::text);
    PERFORM _test_assert('w_08_type_array_excludes_outside', n_outside::text, '0');
END $$;

-- w_09: namespace filter (array) returns only changes for types in the namespace.
DO $$
DECLARE n_docs int; n_folder_in_docs int;
BEGIN
    SELECT count(*) INTO n_docs
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds', p_namespaces => ARRAY['docs']);
    SELECT count(*) INTO n_folder_in_docs
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds', p_namespaces => ARRAY['docs'])
     WHERE object_type = 'folder';
    PERFORM _test_assert_true('w_09_namespace_filter_has_docs', n_docs >= 1, n_docs::text);
    PERFORM _test_assert('w_09_namespace_excludes_unnamespaced', n_folder_in_docs::text, '0');
END $$;

-- w_10: relation filter returns only the requested relation's changes.
SELECT authz.write_tuple('test_watch', 'user', 'gwen', 'editor', 'doc', 'doc_ed');
DO $$
DECLARE n_editor_in_viewer int; n_editor int;
BEGIN
    SELECT count(*) INTO n_editor_in_viewer
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds', p_relations => ARRAY['viewer'])
     WHERE relation = 'editor';
    SELECT count(*) INTO n_editor
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds', p_relations => ARRAY['editor'])
     WHERE object_id = 'doc_ed';
    PERFORM _test_assert('w_10_relation_filter_excludes_others', n_editor_in_viewer::text, '0');
    PERFORM _test_assert_true('w_10_relation_filter_has_editor', n_editor >= 1, n_editor::text);
END $$;

-- w_11: the combined example — viewer on doc/folder within the 'docs' namespace.
DO $$
DECLARE n int; bad int;
BEGIN
    SELECT count(*) INTO n
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds',
               p_object_types => ARRAY['doc','folder'],
               p_namespaces   => ARRAY['docs'],
               p_relations    => ARRAY['viewer']);
    SELECT count(*) INTO bad
      FROM authz.watch_changes('test_watch', p_lag => '0 seconds',
               p_object_types => ARRAY['doc','folder'],
               p_namespaces   => ARRAY['docs'],
               p_relations    => ARRAY['viewer'])
     WHERE relation <> 'viewer' OR object_type NOT IN ('doc','folder');
    PERFORM _test_assert_true('w_11_combined_filter_has_rows', n >= 1, n::text);
    PERFORM _test_assert('w_11_combined_filter_precise', bad::text, '0');
END $$;

SELECT authz.delete_store('test_watch');
SELECT authz.delete_store('test_watch2');
DROP FUNCTION IF EXISTS _test_setup_watch(text);

SELECT _test_report('watch checks');
