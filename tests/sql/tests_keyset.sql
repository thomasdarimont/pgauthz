-- Tests for keyset (cursor) pagination on list_objects / list_subjects.
-- p_after is the last id from the previous page (NULL = first page); pages must
-- not overlap or skip, and must cover the same set as the unpaged result.

SELECT _test_reset();

DROP FUNCTION IF EXISTS _test_setup_ks();
CREATE FUNCTION _test_setup_ks() RETURNS void LANGUAGE plpgsql AS $$
DECLARE s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_ks'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_ks');
    s := authz._s('test_ks');
    INSERT INTO authz.types (store_id, name) VALUES (s,'user'),(s,'doc');
    INSERT INTO authz.relations (store_id, name) VALUES (s,'viewer');
    PERFORM authz._ensure_tuple_partition(s,'doc');
    INSERT INTO authz.models (store_id,object_type,relation,rule_type,computed_relation,tupleset_relation,tupleset_computed)
      VALUES (s, authz._t(s,'doc'), authz._r(s,'viewer'), authz._rel_direct(), NULL,NULL,NULL);
    -- alice can view doc1..doc5 (for list_objects)
    PERFORM authz.write_tuple('test_ks','user','alice','viewer','doc','doc'||g) FROM generate_series(1,5) g;
    -- doc1 has 5 viewers (for list_subjects)
    PERFORM authz.write_tuple('test_ks','user', u, 'viewer','doc','doc1')
       FROM unnest(ARRAY['alice','bob','carol','dave','eve']) u;
END;
$$;

SELECT _test_setup_ks();

-- list_objects keyset paging
DO $$
DECLARE p1 text; p2 text; p3 text; p4 text; allids text;
BEGIN
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO p1
      FROM authz.list_objects('test_ks','user','alice','viewer','doc', p_limit => 2);
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO p2
      FROM authz.list_objects('test_ks','user','alice','viewer','doc', p_limit => 2, p_after => 'doc2');
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO p3
      FROM authz.list_objects('test_ks','user','alice','viewer','doc', p_limit => 2, p_after => 'doc4');
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO p4
      FROM authz.list_objects('test_ks','user','alice','viewer','doc', p_limit => 2, p_after => 'doc5');
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO allids
      FROM authz.list_objects('test_ks','user','alice','viewer','doc');

    PERFORM _test_assert('kp_01_objects_page1', p1, 'doc1,doc2');
    PERFORM _test_assert('kp_02_objects_page2', p2, 'doc3,doc4');
    PERFORM _test_assert('kp_03_objects_page3', p3, 'doc5');
    PERFORM _test_assert('kp_04_objects_past_end_empty', coalesce(p4,'<empty>'), '<empty>');
    PERFORM _test_assert('kp_05_objects_keyset_covers_all', p1||','||p2||','||p3, allids);
END $$;

-- p_after with offset present: keyset wins (offset ignored when p_after is set)
DO $$
DECLARE p text;
BEGIN
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO p
      FROM authz.list_objects('test_ks','user','alice','viewer','doc', p_limit => 2, p_offset => 99, p_after => 'doc2');
    PERFORM _test_assert('kp_06_after_overrides_offset', p, 'doc3,doc4');
END $$;

-- list_subjects keyset paging
DO $$
DECLARE p1 text; p2 text;
BEGIN
    SELECT string_agg(subject_id, ',' ORDER BY subject_id) INTO p1
      FROM authz.list_subjects('test_ks','user','viewer','doc','doc1', p_limit => 2);
    SELECT string_agg(subject_id, ',' ORDER BY subject_id) INTO p2
      FROM authz.list_subjects('test_ks','user','viewer','doc','doc1', p_limit => 2, p_after => 'bob');
    PERFORM _test_assert('kp_07_subjects_page1', p1, 'alice,bob');
    PERFORM _test_assert('kp_08_subjects_page2', p2, 'carol,dave');
END $$;

SELECT authz.delete_store('test_ks');
DROP FUNCTION IF EXISTS _test_setup_ks();

SELECT _test_report('keyset pagination checks');
