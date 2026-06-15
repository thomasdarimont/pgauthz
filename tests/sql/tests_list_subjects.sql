-- Tests for list_subjects across every resolution mechanism.
--
-- list_subjects answers "which subjects of type T have relation R on object Z?"
-- These pin its behavior — especially the paths not exercised by the
-- tests_search suite (userset/team membership, conditions, intersection,
-- exclusion) — so the reverse-expansion rewrite is provably behavior-
-- preserving. The wildcard contract ('*' as a typed is_wildcard row) is
-- covered in tests_wildcard / tests_object_wildcard; a couple of sanity
-- checks are repeated here.

SELECT _test_reset();

DROP FUNCTION IF EXISTS _test_setup_ls();
CREATE OR REPLACE FUNCTION _test_setup_ls() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s smallint;
    t_user smallint; t_team smallint; t_doc smallint;
    r_member smallint; r_viewer smallint; r_owner smallint; r_blocked smallint;
    r_can_edit smallint; r_can_comment smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_ls'); EXCEPTION WHEN OTHERS THEN NULL; END;
    s := authz.create_store('test_ls');

    INSERT INTO authz.types (store_id, name) VALUES (s,'user'),(s,'team'),(s,'doc');
    INSERT INTO authz.relations (store_id, name) VALUES
        (s,'member'),(s,'viewer'),(s,'owner'),(s,'blocked'),(s,'can_edit'),(s,'can_comment');
    PERFORM authz._ensure_tuple_partition(s,'team');
    PERFORM authz._ensure_tuple_partition(s,'doc');

    t_user := authz._t(s,'user'); t_team := authz._t(s,'team'); t_doc := authz._t(s,'doc');
    r_member := authz._r(s,'member'); r_viewer := authz._r(s,'viewer');
    r_owner := authz._r(s,'owner'); r_blocked := authz._r(s,'blocked');
    r_can_edit := authz._r(s,'can_edit'); r_can_comment := authz._r(s,'can_comment');

    -- Condition: access only when request context carries level >= 5.
    INSERT INTO authz.conditions (store_id, name, expression, required_context)
    VALUES (s, 'high_level', 'coalesce(($1->>''level'')::int, 0) >= 5', '{"request":["level"]}'::jsonb);

    INSERT INTO authz.models
        (store_id, object_type, relation, rule_type,
         computed_relation, tupleset_relation, tupleset_computed, group_id, group_op, negated)
    VALUES
        -- team.member: direct (subjects may be user or team#member usersets)
        (s, t_team, r_member,   authz._rel_direct(),   NULL,     NULL, NULL, 0, 0, false),
        (s, t_doc,  r_viewer,   authz._rel_direct(),   NULL,     NULL, NULL, 0, 0, false),
        (s, t_doc,  r_owner,    authz._rel_direct(),   NULL,     NULL, NULL, 0, 0, false),
        (s, t_doc,  r_blocked,  authz._rel_direct(),   NULL,     NULL, NULL, 0, 0, false),
        -- can_edit = viewer AND owner  (intersection group 1)
        (s, t_doc,  r_can_edit, authz._rel_computed(), r_viewer, NULL, NULL, 1, 1, false),
        (s, t_doc,  r_can_edit, authz._rel_computed(), r_owner,  NULL, NULL, 1, 1, false),
        -- can_comment = viewer BUT NOT blocked  (exclusion group 2)
        (s, t_doc,  r_can_comment, authz._rel_computed(), r_viewer,  NULL, NULL, 2, 2, false),
        (s, t_doc,  r_can_comment, authz._rel_computed(), r_blocked, NULL, NULL, 2, 2, true);

    -- direct viewer on doc1: alice, bob; alice also owner -> can_edit
    PERFORM authz.write_tuple('test_ls','user','alice','viewer','doc','doc1');
    PERFORM authz.write_tuple('test_ls','user','bob','viewer','doc','doc1');
    PERFORM authz.write_tuple('test_ls','user','alice','owner','doc','doc1');

    -- userset: team:eng#member granted viewer on doc2; alice & frank are members
    PERFORM authz.write_tuple('test_ls','user','alice','member','team','eng');
    PERFORM authz.write_tuple('test_ls','user','frank','member','team','eng');
    PERFORM authz.write_tuple('test_ls','team','eng','viewer','doc','doc2', p_user_relation => 'member');

    -- exclusion: carol & dave viewer doc3; carol is blocked
    PERFORM authz.write_tuple('test_ls','user','carol','viewer','doc','doc3');
    PERFORM authz.write_tuple('test_ls','user','dave','viewer','doc','doc3');
    PERFORM authz.write_tuple('test_ls','user','carol','blocked','doc','doc3');

    -- condition: eve has viewer on doc4 only when level >= 5
    PERFORM authz.write_tuple('test_ls','user','eve','viewer','doc','doc4', p_condition => 'high_level');

    -- user-wildcard: everyone is a viewer of doc5
    PERFORM authz.write_tuple('test_ls','user','*','viewer','doc','doc5');

    RETURN true;
END;
$$;

DROP FUNCTION IF EXISTS _test_teardown_ls();
CREATE OR REPLACE FUNCTION _test_teardown_ls()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_ls');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ls_01: direct — viewer doc1 = {alice, bob}
DO $$
BEGIN
    PERFORM _test_setup_ls();
    PERFORM _test_assert('ls_01_direct_viewer_doc1',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text
           FROM authz.list_subjects('test_ls','user','viewer','doc','doc1')),
        '{alice,bob}');
END;
$$;
SELECT * FROM _test_teardown_ls();

-- ls_02: userset — viewer doc2 via team:eng#member = {alice, frank}
DO $$
BEGIN
    PERFORM _test_setup_ls();
    PERFORM _test_assert('ls_02_userset_viewer_doc2',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text
           FROM authz.list_subjects('test_ls','user','viewer','doc','doc2')),
        '{alice,frank}');
END;
$$;
SELECT * FROM _test_teardown_ls();

-- ls_03: intersection — can_edit doc1 needs viewer AND owner = {alice}
DO $$
BEGIN
    PERFORM _test_setup_ls();
    PERFORM _test_assert('ls_03_intersection_can_edit_doc1',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text
           FROM authz.list_subjects('test_ls','user','can_edit','doc','doc1')),
        '{alice}');
END;
$$;
SELECT * FROM _test_teardown_ls();

-- ls_04: exclusion — can_comment doc3 = viewer BUT NOT blocked = {dave}
DO $$
BEGIN
    PERFORM _test_setup_ls();
    PERFORM _test_assert('ls_04_exclusion_can_comment_doc3',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text
           FROM authz.list_subjects('test_ls','user','can_comment','doc','doc3')),
        '{dave}');
END;
$$;
SELECT * FROM _test_teardown_ls();

-- ls_05: condition — eve appears for viewer doc4 only with level >= 5 context
DO $$
BEGIN
    PERFORM _test_setup_ls();
    PERFORM _test_assert('ls_05a_condition_with_context',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text
           FROM authz.list_subjects('test_ls','user','viewer','doc','doc4',
                    context => '{"level": 7}'::jsonb)),
        '{eve}');
    PERFORM _test_assert('ls_05b_condition_without_context',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text
           FROM authz.list_subjects('test_ls','user','viewer','doc','doc4')),
        NULL);   -- condition fails (missing level) -> no subjects
END;
$$;
SELECT * FROM _test_teardown_ls();

-- ls_06: user-wildcard — viewer doc5 returns the '*' typed row, flagged
DO $$
DECLARE v_id text; v_wc boolean;
BEGIN
    PERFORM _test_setup_ls();
    SELECT subject_id, is_wildcard INTO v_id, v_wc
      FROM authz.list_subjects('test_ls','user','viewer','doc','doc5');
    PERFORM _test_assert('ls_06a_wildcard_subject_id', v_id, '*');
    PERFORM _test_assert('ls_06b_wildcard_flag', v_wc::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_ls();

-- ls_07: empty — no subjects have owner on doc2
DO $$
BEGIN
    PERFORM _test_setup_ls();
    PERFORM _test_assert('ls_07_empty_owner_doc2',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text
           FROM authz.list_subjects('test_ls','user','owner','doc','doc2')),
        NULL);
END;
$$;
SELECT * FROM _test_teardown_ls();

-- ls_08: pagination — limit 1 over viewer doc1 returns exactly one
DO $$
BEGIN
    PERFORM _test_setup_ls();
    PERFORM _test_assert('ls_08_pagination_limit_1',
        (SELECT count(*)::text
           FROM authz.list_subjects('test_ls','user','viewer','doc','doc1', p_limit => 1)),
        '1');
END;
$$;
SELECT * FROM _test_teardown_ls();

-- ls_09: scale — an object granted to a few users must return just those,
-- regardless of how many users exist store-wide (reverse expansion bounds
-- the candidate set to the object's reachable subjects, not all users).
DO $$
BEGIN
    PERFORM _test_setup_ls();
    -- 2000 unrelated users, each a viewer of their own private doc.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT authz._s('test_ls'), authz._t(authz._s('test_ls'),'doc'),
           'priv_' || g, authz._r(authz._s('test_ls'),'viewer'),
           authz._t(authz._s('test_ls'),'user'), 'u' || g
      FROM generate_series(1, 2000) g;

    -- doc1 is still shared only with alice and bob.
    PERFORM _test_assert('ls_09_scale_bounded_to_grantees',
        (SELECT array_agg(subject_id ORDER BY subject_id)::text
           FROM authz.list_subjects('test_ls','user','viewer','doc','doc1')),
        '{alice,bob}');
END;
$$;
SELECT * FROM _test_teardown_ls();

DROP FUNCTION IF EXISTS _test_teardown_ls();
DROP FUNCTION IF EXISTS _test_setup_ls();

SELECT _test_report('list_subjects checks');
