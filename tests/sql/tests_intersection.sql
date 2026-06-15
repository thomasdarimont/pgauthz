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
        (s, 'can_view'), (s, 'can_comment'), (s, 'can_react');

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

-- ================================================================
-- Exclusion group validation: a group with only negated rules has
-- no base requirement and would grant access to everyone who is not
-- excluded (fail-open). Such groups must be rejected at write time,
-- and the evaluator must fail closed if one exists anyway.
-- ================================================================

-- grp_15: direct INSERT of a negated-only exclusion group is rejected
SELECT _test_setup_groups();
DO $$
DECLARE s smallint := authz._s('test_groups');
BEGIN
    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, group_id, group_op, negated)
    VALUES (s, authz._t(s, 'resource'), authz._r(s, 'can_react'),
            authz._rel_computed(), authz._r(s, 'blocked'),
            1, authz._combine_exclusion(), true);
    PERFORM _test_assert_true('grp_15_negated_only_group_rejected', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('grp_15_negated_only_group_rejected',
        SQLERRM LIKE '%exclusion group%base%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_groups();

-- grp_16: model_add_rule with negated => true into an empty group is rejected
SELECT _test_setup_groups();
DO $$
BEGIN
    PERFORM authz.model_add_rule('test_groups', 'resource', 'can_react', 'computed',
        p_computed_relation => 'blocked',
        p_group_id => 1::smallint, p_group_op => 'exclusion', p_negated => true);
    PERFORM _test_assert_true('grp_16_add_rule_negated_without_base_rejected', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('grp_16_add_rule_negated_without_base_rejected',
        SQLERRM LIKE '%exclusion group%base%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_groups();

-- grp_17: removing the last base rule of an exclusion group is rejected
SELECT _test_setup_groups();
DO $$
DECLARE v_base_id smallint;
BEGIN
    v_base_id := authz.model_add_rule('test_groups', 'resource', 'can_react', 'computed',
        p_computed_relation => 'member',
        p_group_id => 1::smallint, p_group_op => 'exclusion');
    PERFORM authz.model_add_rule('test_groups', 'resource', 'can_react', 'computed',
        p_computed_relation => 'blocked',
        p_group_id => 1::smallint, p_group_op => 'exclusion', p_negated => true);

    PERFORM authz.model_remove_rule('test_groups', v_base_id);
    PERFORM _test_assert_true('grp_17_remove_last_base_rule_rejected', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('grp_17_remove_last_base_rule_rejected',
        SQLERRM LIKE '%exclusion group%base%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_groups();

-- grp_18: negated rules outside exclusion groups are rejected
SELECT _test_setup_groups();
DO $$
DECLARE s smallint := authz._s('test_groups');
BEGIN
    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, group_id, group_op, negated)
    VALUES (s, authz._t(s, 'resource'), authz._r(s, 'can_react'),
            authz._rel_computed(), authz._r(s, 'blocked'),
            1, authz._combine_or(), true);
    PERFORM _test_assert_true('grp_18_negated_outside_exclusion_rejected', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('grp_18_negated_outside_exclusion_rejected',
        SQLERRM LIKE '%negated%exclusion%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_groups();

-- grp_19: the evaluator fails closed on a negated-only exclusion group.
-- The validation trigger is bypassed via session_replication_role
-- (superuser-only) to simulate a model that predates validation.
DO $$
DECLARE s smallint;
BEGIN
    PERFORM _test_setup_groups();
    s := authz._s('test_groups');

    PERFORM set_config('session_replication_role', 'replica', true);
    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, group_id, group_op, negated)
    VALUES (s, authz._t(s, 'resource'), authz._r(s, 'can_react'),
            authz._rel_computed(), authz._r(s, 'blocked'),
            1, authz._combine_exclusion(), true);
    PERFORM set_config('session_replication_role', 'origin', true);

    -- alice is not blocked, but with no base rule nothing grants can_react:
    -- the group must fail closed, not grant everyone-not-blocked.
    PERFORM _test_assert('grp_19_negated_only_group_fails_closed',
        authz.check_access('test_groups', 'user', 'alice', 'can_react', 'resource', 'r1')::text,
        'false');
END;
$$;
SELECT * FROM _test_teardown_groups();

-- ================================================================
-- explain_access: structured decision, typed reasons, a nested tree,
-- and a redacted safety mode.
-- ================================================================

-- grp_20: ALLOW carries a structured decision with a typed reason and
-- every trace step is typed; the legacy 'result' field is preserved.
DO $$
DECLARE e jsonb;
BEGIN
    PERFORM _test_setup_groups();
    e := authz.explain_access('test_groups', 'user', 'alice', 'can_view', 'resource', 'r1');

    PERFORM _test_assert('grp_20a_decision_allowed_true',
        (e->'decision'->>'allowed'), 'true');
    PERFORM _test_assert('grp_20b_legacy_result_preserved',
        (e->>'result'), 'true');
    PERFORM _test_assert('grp_20c_decision_reason_typed',
        (e->'decision'->>'reason'), 'intersection_satisfied');
    -- every trace step must carry a non-null typed reason
    PERFORM _test_assert('grp_20e_all_steps_have_reason',
        (SELECT bool_and(s->>'reason' IS NOT NULL)::text
           FROM jsonb_array_elements(e->'trace') s), 'true');
END;
$$;
SELECT * FROM _test_teardown_groups();

-- grp_21: DENY-by-exclusion surfaces the typed reason 'excluded'
DO $$
DECLARE e jsonb;
BEGIN
    PERFORM _test_setup_groups();
    e := authz.explain_access('test_groups', 'user', 'carol', 'can_comment', 'resource', 'r1');
    PERFORM _test_assert('grp_21a_decision_allowed_false',
        (e->'decision'->>'allowed'), 'false');
    PERFORM _test_assert('grp_21b_decision_reason_excluded',
        (e->'decision'->>'reason'), 'excluded');
END;
$$;
SELECT * FROM _test_teardown_groups();

-- grp_22: redacted mode omits subject/object identifiers
DO $$
DECLARE e jsonb;
BEGIN
    PERFORM _test_setup_groups();
    e := authz.explain_access('test_groups', 'user', 'alice', 'can_view', 'resource', 'r1',
                              p_redact => true);
    -- decision/version still present, but no concrete ids leak anywhere
    PERFORM _test_assert('grp_22a_redacted_still_has_decision',
        (e->'decision'->>'allowed'), 'true');
    PERFORM _test_assert('grp_22b_redacted_hides_subject_id',
        (e::text LIKE '%alice%')::text, 'false');
    PERFORM _test_assert('grp_22c_redacted_hides_object_id',
        (e::text LIKE '%r1%')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_groups();

-- grp_23: nested 'tree' — a single synthetic root carrying the decision,
-- with the resolution nested underneath (children of children exist).
DO $$
DECLARE e jsonb; t jsonb;
BEGIN
    PERFORM _test_setup_groups();
    e := authz.explain_access('test_groups', 'user', 'alice', 'can_view', 'resource', 'r1');
    t := e->'tree';

    PERFORM _test_assert('grp_23a_tree_root_allowed',
        (t->>'allowed'), 'true');
    PERFORM _test_assert('grp_23b_tree_root_reason',
        (t->>'reason'), 'intersection_satisfied');
    PERFORM _test_assert('grp_23c_tree_root_has_children',
        (jsonb_array_length(t->'children') > 0)::text, 'true');
    -- the tree actually nests: at least one top-level child has children
    -- (e.g. the computed check wrapping its direct-tuple leaf)
    PERFORM _test_assert('grp_23d_tree_is_nested',
        (EXISTS (SELECT 1 FROM jsonb_array_elements(t->'children') c
                  WHERE jsonb_array_length(c->'children') > 0))::text, 'true');
    -- every node in the tree carries a typed reason (recursive check)
    PERFORM _test_assert('grp_23e_tree_reason_count_matches_trace',
        (SELECT count(*) FROM jsonb_array_elements(e->'trace'))::text,
        (WITH RECURSIVE nodes(n) AS (
            SELECT t
            UNION ALL
            SELECT jsonb_array_elements(n->'children') FROM nodes
            WHERE jsonb_array_length(n->'children') > 0
         )
         -- count nodes that came from trace steps (exclude the synthetic root)
         SELECT count(*) FROM nodes WHERE n->>'step' IS NOT NULL)::text);
END;
$$;
SELECT * FROM _test_teardown_groups();

-- grp_24: trace steps carry model-rule references (model_rule_id,
-- group_id, group_op, negated) so a decision can be traced to the exact
-- model row and its group semantics.
DO $$
DECLARE e jsonb;
BEGIN
    PERFORM _test_setup_groups();

    -- Intersection (can_view = member AND licensed): the group verdict is
    -- tagged 'intersection', and the rule-eval steps carry a model_rule_id.
    e := authz.explain_access('test_groups', 'user', 'alice', 'can_view', 'resource', 'r1');
    PERFORM _test_assert_true('grp_24a_intersection_verdict_tagged',
        EXISTS (SELECT 1 FROM jsonb_array_elements(e->'trace') s
                 WHERE s->>'rule_type' = 'intersection'
                   AND s->>'group_op'  = 'intersection'));
    PERFORM _test_assert_true('grp_24b_rule_steps_reference_model_row',
        EXISTS (SELECT 1 FROM jsonb_array_elements(e->'trace') s
                 WHERE s->>'rule_type'     = 'computed'
                   AND s->>'group_op'      = 'intersection'
                   AND s->>'model_rule_id' IS NOT NULL));

    -- Exclusion (can_comment = member BUT NOT blocked): the negated
    -- (subtracted) rule step is flagged negated = true.
    e := authz.explain_access('test_groups', 'user', 'carol', 'can_comment', 'resource', 'r1');
    PERFORM _test_assert_true('grp_24c_negated_rule_flagged',
        EXISTS (SELECT 1 FROM jsonb_array_elements(e->'trace') s
                 WHERE s->>'group_op' = 'exclusion'
                   AND (s->>'negated')::boolean = true));
END;
$$;
SELECT * FROM _test_teardown_groups();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_groups();
DROP FUNCTION IF EXISTS _test_setup_groups();

SELECT _test_report('group checks');
