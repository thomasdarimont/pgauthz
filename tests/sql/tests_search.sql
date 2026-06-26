-- Tests for search API functions: list_objects, list_subjects, list_actions.
--
-- Uses its own 'test_search' store with a simple folder/document model:
--   type user
--   type folder
--     relations
--       define viewer: [user]
--   type doc
--     relations
--       define owner:    [user]
--       define parent:   [folder]
--       define viewer:   [user]
--       define can_read: viewer or owner or viewer from parent
--       define can_edit: owner

SELECT _test_reset();

-- Setup: create test store with folder/document model and seed data (idempotent).
DROP FUNCTION IF EXISTS _test_setup_search();
CREATE OR REPLACE FUNCTION _test_setup_search() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s          smallint;
    t_folder   smallint;
    t_doc      smallint;
    r_owner    smallint;
    r_parent   smallint;
    r_viewer   smallint;
    r_can_read smallint;
    r_can_edit smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_search'); EXCEPTION WHEN OTHERS THEN NULL; END;

    s := authz.create_store('test_search');

    INSERT INTO authz.types (store_id, name) VALUES
        (s, 'user'), (s, 'folder'), (s, 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES
        (s, 'owner'), (s, 'parent'), (s, 'viewer'), (s, 'can_read'), (s, 'can_edit');

    PERFORM authz._ensure_tuple_partition(s, 'folder');
    PERFORM authz._ensure_tuple_partition(s, 'doc');

    t_folder   := authz._t(s, 'folder');
    t_doc      := authz._t(s, 'doc');
    r_owner    := authz._r(s, 'owner');
    r_parent   := authz._r(s, 'parent');
    r_viewer   := authz._r(s, 'viewer');
    r_can_read := authz._r(s, 'can_read');
    r_can_edit := authz._r(s, 'can_edit');

    INSERT INTO authz.models
        (store_id, object_type, relation, rule_type,
         computed_relation, tupleset_relation, tupleset_computed)
    VALUES
        (s, t_folder, r_viewer, authz._rel_direct(), NULL, NULL, NULL),
        (s, t_doc, r_owner,  authz._rel_direct(), NULL, NULL, NULL),
        (s, t_doc, r_parent, authz._rel_direct(), NULL, NULL, NULL),
        (s, t_doc, r_viewer, authz._rel_direct(), NULL, NULL, NULL),
        (s, t_doc, r_can_read, authz._rel_computed(), r_viewer, NULL, NULL),
        (s, t_doc, r_can_read, authz._rel_computed(), r_owner,  NULL, NULL),
        (s, t_doc, r_can_read, authz._rel_ttu(),      NULL, r_parent, r_viewer),
        (s, t_doc, r_can_edit, authz._rel_computed(), r_owner, NULL, NULL);

    PERFORM authz.write_tuple('test_search', 'user', 'alice', 'viewer', 'folder', 'f1');
    PERFORM authz.write_tuple('test_search', 'user', 'bob',   'viewer', 'folder', 'f1');
    PERFORM authz.write_tuple('test_search', 'user',   'alice', 'owner',  'doc', 'd1');
    PERFORM authz.write_tuple('test_search', 'folder', 'f1',    'parent', 'doc', 'd1');
    PERFORM authz.write_tuple('test_search', 'user', 'bob', 'viewer', 'doc', 'd2');
    PERFORM authz.write_tuple('test_search', 'user',   'charlie', 'owner',  'doc', 'd3');
    PERFORM authz.write_tuple('test_search', 'folder', 'f1',      'parent', 'doc', 'd3');

    RETURN true;
END;
$$;

-- Teardown: remove test store and return accumulated results.
DROP FUNCTION IF EXISTS _test_teardown_search();
CREATE OR REPLACE FUNCTION _test_teardown_search()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_search');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ================================================================
-- list_objects tests
-- ================================================================

-- search_01: alice can_read d1 (owner) and d3 (viewer from parent f1)
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_01_list_objects_alice_can_read',
        (SELECT array_agg(object_id ORDER BY object_id)::text FROM authz.list_objects('test_search', 'user', 'alice', 'can_read', 'doc')),
        '{d1,d3}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_02: bob can_read d1, d2, d3
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_02_list_objects_bob_can_read',
        (SELECT array_agg(object_id ORDER BY object_id)::text FROM authz.list_objects('test_search', 'user', 'bob', 'can_read', 'doc')),
        '{d1,d2,d3}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_03: charlie can_read d3 only (owner)
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_03_list_objects_charlie_can_read',
        (SELECT array_agg(object_id ORDER BY object_id)::text FROM authz.list_objects('test_search', 'user', 'charlie', 'can_read', 'doc')),
        '{d3}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_04: alice can_edit d1 only (owner)
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_04_list_objects_alice_can_edit',
        (SELECT array_agg(object_id ORDER BY object_id)::text FROM authz.list_objects('test_search', 'user', 'alice', 'can_edit', 'doc')),
        '{d1}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_05: unknown user can_read nothing
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_05_list_objects_nobody_can_read',
        (SELECT array_agg(object_id ORDER BY object_id)::text FROM authz.list_objects('test_search', 'user', 'nobody', 'can_read', 'doc')),
        NULL);
END;
$$;
SELECT * FROM _test_teardown_search();

-- ================================================================
-- list_subjects tests
-- ================================================================

-- search_06: who can_read d1? alice, bob
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_06_list_subjects_can_read_d1',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text FROM authz.list_subjects('test_search', 'user', 'can_read', 'doc', 'd1')),
        '{alice,bob}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_07: who can_read d2? bob only
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_07_list_subjects_can_read_d2',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text FROM authz.list_subjects('test_search', 'user', 'can_read', 'doc', 'd2')),
        '{bob}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_08: who can_read d3? alice, bob, charlie
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_08_list_subjects_can_read_d3',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text FROM authz.list_subjects('test_search', 'user', 'can_read', 'doc', 'd3')),
        '{alice,bob,charlie}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_09: who can_edit d1? alice only
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_09_list_subjects_can_edit_d1',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text FROM authz.list_subjects('test_search', 'user', 'can_edit', 'doc', 'd1')),
        '{alice}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_10: who can_read d4? nobody
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_10_list_subjects_can_read_d4',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text FROM authz.list_subjects('test_search', 'user', 'can_read', 'doc', 'd4')),
        NULL);
END;
$$;
SELECT * FROM _test_teardown_search();

-- ================================================================
-- list_actions tests
-- ================================================================

-- search_11: alice on d1 -> can_edit, can_read, owner
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_11_list_actions_alice_on_d1',
        (SELECT array_agg(action ORDER BY action)::text FROM authz.list_actions('test_search', 'user', 'alice', 'doc', 'd1')),
        '{can_edit,can_read,owner}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_12: bob on d1 -> can_read only
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_12_list_actions_bob_on_d1',
        (SELECT array_agg(action ORDER BY action)::text FROM authz.list_actions('test_search', 'user', 'bob', 'doc', 'd1')),
        '{can_read}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_13: charlie on d3 -> can_edit, can_read, owner
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_13_list_actions_charlie_on_d3',
        (SELECT array_agg(action ORDER BY action)::text FROM authz.list_actions('test_search', 'user', 'charlie', 'doc', 'd3')),
        '{can_edit,can_read,owner}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_14: bob on d2 -> can_read, viewer
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_14_list_actions_bob_on_d2',
        (SELECT array_agg(action ORDER BY action)::text FROM authz.list_actions('test_search', 'user', 'bob', 'doc', 'd2')),
        '{can_read,viewer}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_15: nobody on d1 -> empty
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_15_list_actions_nobody_on_d1',
        (SELECT array_agg(action ORDER BY action)::text FROM authz.list_actions('test_search', 'user', 'nobody', 'doc', 'd1')),
        NULL);
END;
$$;
SELECT * FROM _test_teardown_search();

-- ================================================================
-- Pagination tests
-- ================================================================

-- search_16: list_objects with limit=1 returns exactly 1 result
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_16_list_objects_limit_1',
        (SELECT count(*)::text FROM authz.list_objects('test_search', 'user', 'bob', 'can_read', 'doc', p_limit => 1)),
        '1');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_17: list_objects with offset=1,limit=1 returns second result
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_17_list_objects_offset_limit',
        (SELECT array_agg(object_id ORDER BY object_id)::text FROM authz.list_objects('test_search', 'user', 'bob', 'can_read', 'doc', p_limit => 1, p_offset => 1)),
        '{d2}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_18: list_objects with offset beyond results returns empty
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_18_list_objects_offset_beyond',
        (SELECT array_agg(object_id)::text FROM authz.list_objects('test_search', 'user', 'bob', 'can_read', 'doc', p_offset => 100)),
        NULL);
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_19: list_subjects with limit=2 returns exactly 2
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_19_list_subjects_limit_2',
        (SELECT count(*)::text FROM authz.list_subjects('test_search', 'user', 'can_read', 'doc', 'd3', p_limit => 2)),
        '2');
END;
$$;
SELECT * FROM _test_teardown_search();

-- search_20: list_objects with NULL limit returns all (backward compat)
DO $$
BEGIN
    PERFORM _test_setup_search();
    PERFORM _test_assert('search_20_list_objects_null_limit',
        (SELECT array_agg(object_id ORDER BY object_id)::text FROM authz.list_objects('test_search', 'user', 'bob', 'can_read', 'doc')),
        '{d1,d2,d3}');
END;
$$;
SELECT * FROM _test_teardown_search();

-- ================================================================
-- Authorization-as-a-JOIN filtering pattern (wildcard-safe)
-- ================================================================
-- Verifies the documented pattern (README "Authorization as a JOIN"): filter an
-- application table by JOINing list_objects(...), honouring is_wildcard. Uses
-- its own object-wildcard-capable store and a temp app table.
DO $$
DECLARE
    v_explicit   text;
    v_wild       text;
    v_none       text;
    v_naive_wild text;
BEGIN
    BEGIN PERFORM authz.delete_store('test_aojoin'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_aojoin');

    INSERT INTO authz.types (store_id, name) VALUES
        (authz._s('test_aojoin'), 'user'), (authz._s('test_aojoin'), 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES
        (authz._s('test_aojoin'), 'viewer'), (authz._s('test_aojoin'), 'can_read');
    PERFORM authz._ensure_tuple_partition(authz._s('test_aojoin'), 'doc');
    PERFORM authz.model_add_rule('test_aojoin', 'doc', 'viewer', 'direct',
        p_allow_object_wildcard => true);
    PERFORM authz.model_add_rule('test_aojoin', 'doc', 'can_read', 'computed',
        p_computed_relation => 'viewer');

    -- bob: explicit grants on d1,d2; auditor: object-wildcard (every doc)
    PERFORM authz.write_tuple('test_aojoin', 'user', 'bob',     'viewer', 'doc', 'd1');
    PERFORM authz.write_tuple('test_aojoin', 'user', 'bob',     'viewer', 'doc', 'd2');
    PERFORM authz.write_tuple('test_aojoin', 'user', 'auditor', 'viewer', 'doc', '*');

    -- stand-in for the application's own table
    DROP TABLE IF EXISTS _aojoin_docs;
    CREATE TEMP TABLE _aojoin_docs (id text PRIMARY KEY);
    INSERT INTO _aojoin_docs VALUES ('d1'), ('d2'), ('d3');

    -- aojoin_01: explicit grants filter to exactly the authorized rows
    SELECT array_agg(d.id ORDER BY d.id)::text INTO v_explicit
      FROM _aojoin_docs d
     WHERE EXISTS (SELECT 1 FROM authz.list_objects('test_aojoin','user','bob','can_read','doc') WHERE is_wildcard)
        OR d.id IN (SELECT object_id FROM authz.list_objects('test_aojoin','user','bob','can_read','doc'));
    PERFORM _test_assert('aojoin_01_explicit_grants_filter', v_explicit, '{d1,d2}');

    -- aojoin_02: a wildcard grant widens the filter to ALL rows
    SELECT array_agg(d.id ORDER BY d.id)::text INTO v_wild
      FROM _aojoin_docs d
     WHERE EXISTS (SELECT 1 FROM authz.list_objects('test_aojoin','user','auditor','can_read','doc') WHERE is_wildcard)
        OR d.id IN (SELECT object_id FROM authz.list_objects('test_aojoin','user','auditor','can_read','doc'));
    PERFORM _test_assert('aojoin_02_wildcard_returns_all', v_wild, '{d1,d2,d3}');

    -- aojoin_03: no grants → no rows
    SELECT array_agg(d.id ORDER BY d.id)::text INTO v_none
      FROM _aojoin_docs d
     WHERE EXISTS (SELECT 1 FROM authz.list_objects('test_aojoin','user','nobody','can_read','doc') WHERE is_wildcard)
        OR d.id IN (SELECT object_id FROM authz.list_objects('test_aojoin','user','nobody','can_read','doc'));
    PERFORM _test_assert('aojoin_03_no_access_returns_none', v_none, NULL);

    -- aojoin_04: the FOOTGUN — a naive id-only JOIN silently returns nothing for
    -- the wildcard user (its set is the single '*' row), which is why the
    -- is_wildcard branch above is required.
    SELECT array_agg(d.id ORDER BY d.id)::text INTO v_naive_wild
      FROM _aojoin_docs d
      JOIN authz.list_objects('test_aojoin','user','auditor','can_read','doc') a
        ON a.object_id = d.id;
    PERFORM _test_assert_true('aojoin_04_naive_id_join_misses_wildcard',
        v_naive_wild IS NULL, 'naive join result=' || coalesce(v_naive_wild, '<null>'));

    DROP TABLE IF EXISTS _aojoin_docs;
    PERFORM authz.delete_store('test_aojoin');
END;
$$;

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_search();
DROP FUNCTION IF EXISTS _test_setup_search();

SELECT _test_report('search checks');
