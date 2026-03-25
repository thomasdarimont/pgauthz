-- Tests for intersection (AND) and exclusion (BUT NOT) rule groups.
-- Uses a dedicated 'test_groups' store to avoid polluting the demo model.

SELECT _test_reset();

-- Setup: create test store with intersection/exclusion model and seed data (idempotent).
DROP FUNCTION IF EXISTS _test_setup_groups();
CREATE OR REPLACE FUNCTION _test_setup_groups() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s             smallint;
    t_resource    smallint;
    r_member      smallint;
    r_licensed    smallint;
    r_blocked     smallint;
    r_admin       smallint;
    r_can_view    smallint;
    r_can_comment smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_groups'); EXCEPTION WHEN OTHERS THEN NULL; END;

    s := authz.create_store('test_groups');

    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'resource');
    INSERT INTO authz.relations (store_id, name) VALUES
        (s, 'member'), (s, 'licensed'), (s, 'blocked'), (s, 'admin'),
        (s, 'can_view'), (s, 'can_comment');

    t_resource    := authz._t(s, 'resource');
    r_member      := authz._r(s, 'member');
    r_licensed    := authz._r(s, 'licensed');
    r_blocked     := authz._r(s, 'blocked');
    r_admin       := authz._r(s, 'admin');
    r_can_view    := authz._r(s, 'can_view');
    r_can_comment := authz._r(s, 'can_comment');

    INSERT INTO authz.models (store_id, object_type, relation, rule_type) VALUES
        (s, t_resource, r_member,   authz._rel_direct()),
        (s, t_resource, r_licensed, authz._rel_direct()),
        (s, t_resource, r_blocked,  authz._rel_direct()),
        (s, t_resource, r_admin,    authz._rel_direct());

    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, group_id, group_op) VALUES
        (s, t_resource, r_can_view, authz._rel_computed(), r_member,   1, authz._combine_and()),
        (s, t_resource, r_can_view, authz._rel_computed(), r_licensed, 1, authz._combine_and()),
        (s, t_resource, r_can_view, authz._rel_computed(), r_admin,    0, authz._combine_or());

    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, group_id, group_op, negated) VALUES
        (s, t_resource, r_can_comment, authz._rel_computed(), r_member,  1, authz._combine_exclusion(), false),
        (s, t_resource, r_can_comment, authz._rel_computed(), r_blocked, 1, authz._combine_exclusion(), true);

    PERFORM authz.write_tuple('test_groups', 'user', 'alice', 'member',   'resource', 'r1');
    PERFORM authz.write_tuple('test_groups', 'user', 'alice', 'licensed', 'resource', 'r1');
    PERFORM authz.write_tuple('test_groups', 'user', 'bob',   'member',   'resource', 'r1');
    PERFORM authz.write_tuple('test_groups', 'user', 'carol', 'member',   'resource', 'r1');
    PERFORM authz.write_tuple('test_groups', 'user', 'carol', 'licensed', 'resource', 'r1');
    PERFORM authz.write_tuple('test_groups', 'user', 'carol', 'blocked',  'resource', 'r1');
    PERFORM authz.write_tuple('test_groups', 'user', 'dave',  'licensed', 'resource', 'r1');
    PERFORM authz.write_tuple('test_groups', 'user', 'eve',   'admin',    'resource', 'r1');
    PERFORM authz.write_tuple('test_groups', 'user', 'frank', 'blocked',  'resource', 'r1');

    RETURN true;
END;
$$;

-- Teardown: remove test store and return accumulated results.
DROP FUNCTION IF EXISTS _test_teardown_groups();
CREATE OR REPLACE FUNCTION _test_teardown_groups()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_groups');
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
    PERFORM _test_setup_groups();

    CREATE TEMP TABLE test_group_checks (
        id          serial,
        description text,
        user_id     text,
        relation    text,
        expected    boolean
    );

    INSERT INTO test_group_checks (description, user_id, relation, expected) VALUES
    ('grp_01_alice_can_view',               'alice', 'can_view',    true),
    ('grp_02_bob_cannot_can_view',          'bob',   'can_view',    false),
    ('grp_03_carol_can_view',               'carol', 'can_view',    true),
    ('grp_04_dave_cannot_can_view',         'dave',  'can_view',    false),
    ('grp_05_eve_can_view_admin_bypass',    'eve',   'can_view',    true),
    ('grp_06_frank_cannot_can_view',        'frank', 'can_view',    false),
    ('grp_07_alice_can_comment',            'alice', 'can_comment', true),
    ('grp_08_bob_can_comment',              'bob',   'can_comment', true),
    ('grp_09_carol_cannot_can_comment',     'carol', 'can_comment', false),
    ('grp_10_dave_cannot_can_comment',      'dave',  'can_comment', false),
    ('grp_11_eve_cannot_can_comment',       'eve',   'can_comment', false),
    ('grp_12_frank_cannot_can_comment',     'frank', 'can_comment', false);

    FOR rec IN SELECT * FROM test_group_checks ORDER BY id LOOP
        result := authz.check_access(
            'test_groups', 'user', rec.user_id,
            rec.relation, 'resource', 'r1'
        );
        PERFORM _test_assert(rec.description, result::text, rec.expected::text);
    END LOOP;

    DROP TABLE test_group_checks;
END;
$$;
SELECT * FROM _test_teardown_groups();

-- grp_13: explain_access works for intersection (alice can_view)
DO $$
DECLARE
    v_result boolean;
    v_detail text;
BEGIN
    PERFORM _test_setup_groups();
    SELECT (e->>'result')::boolean = true AND e->>'summary' IS NOT NULL,
           e::text
      INTO v_result, v_detail
      FROM authz.explain_access('test_groups', 'user', 'alice', 'can_view', 'resource', 'r1') e;
    PERFORM _test_assert_true('grp_13_explain_access_intersection', v_result, v_detail);
END;
$$;
SELECT * FROM _test_teardown_groups();

-- grp_14: explain_access works for exclusion (carol cannot can_comment)
DO $$
DECLARE
    v_result boolean;
    v_detail text;
BEGIN
    PERFORM _test_setup_groups();
    SELECT (e->>'result')::boolean = false AND e->>'summary' IS NOT NULL,
           e::text
      INTO v_result, v_detail
      FROM authz.explain_access('test_groups', 'user', 'carol', 'can_comment', 'resource', 'r1') e;
    PERFORM _test_assert_true('grp_14_explain_access_exclusion', v_result, v_detail);
END;
$$;
SELECT * FROM _test_teardown_groups();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_groups();
DROP FUNCTION IF EXISTS _test_setup_groups();

SELECT _test_report('group checks');
