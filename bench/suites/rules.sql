-- Benchmark suite: rule-combination semantics — intersection (AND),
-- exclusion (BUT NOT), and conditions (ABAC).
--
-- Requires the harness (bench/lib/harness.sql) in the same psql session —
-- bench/run.sh does that. Uses its own 'bench_rules' store. Tunables are the
-- constants in the data-generation block.
--
-- Distinct from `drive`/`github` (which only union/OR rules): this times the
-- AND combine, the BUT-NOT exclusion combine, and per-tuple condition
-- evaluation — the rule-group code paths the other suites never touch.

SELECT pg_temp._bench_title('Rules: intersection (AND) + exclusion (BUT NOT) + conditions (ABAC)');

-- ── Schema: model ───────────────────────────────────────────────────
DO $$ BEGIN PERFORM authz.delete_store('bench_rules', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$;
SELECT authz.create_store('bench_rules');

SELECT authz.model_register_type('bench_rules', t) FROM unnest(ARRAY['user','resource']) t;
SELECT authz.model_register_relation('bench_rules', r)
  FROM unnest(ARRAY['assigned','cleared','editor','banned','viewer',
                    'can_access','can_edit','can_view']) r;

-- Direct base relations.
SELECT authz.model_add_rule('bench_rules','resource', r, 'direct')
  FROM unnest(ARRAY['assigned','cleared','editor','banned','viewer']) r;

-- can_access = assigned AND cleared        (intersection)
SELECT authz.model_add_rule('bench_rules','resource','can_access','computed',
    p_computed_relation => 'assigned', p_group_id => 1::smallint, p_group_op => 'intersection');
SELECT authz.model_add_rule('bench_rules','resource','can_access','computed',
    p_computed_relation => 'cleared',  p_group_id => 1::smallint, p_group_op => 'intersection');

-- can_edit = editor BUT NOT banned         (exclusion)
SELECT authz.model_add_rule('bench_rules','resource','can_edit','computed',
    p_computed_relation => 'editor', p_group_id => 2::smallint, p_group_op => 'exclusion', p_negated => false);
SELECT authz.model_add_rule('bench_rules','resource','can_edit','computed',
    p_computed_relation => 'banned', p_group_id => 2::smallint, p_group_op => 'exclusion', p_negated => true);

-- can_view = viewer                        (viewer tuples carry a time condition)
SELECT authz.model_add_rule('bench_rules','resource','can_view','computed',
    p_computed_relation => 'viewer');

-- ABAC condition: a grant valid only until a stored timestamp.
SELECT authz.create_condition_sql('bench_rules', 'non_expired',
    $cond$ ($1->>'now')::timestamptz < ($2->>'until')::timestamptz $cond$,
    '{"request":["now"],"stored":["until"]}'::jsonb);

-- ── Data generation ─────────────────────────────────────────────────
DO $$
DECLARE
    -- tunables
    n_users  int := 20000;
    n_res    int := 5000;
    hot_size int := 500;     -- subjects on the "hot" resource (list_subjects)

    s          smallint := authz._s('bench_rules');
    t_user     smallint := authz._t(s,'user');
    t_res      smallint := authz._t(s,'resource');
    r_assigned smallint := authz._r(s,'assigned');
    r_cleared  smallint := authz._r(s,'cleared');
    r_editor   smallint := authz._r(s,'editor');
    r_banned   smallint := authz._r(s,'banned');
    t0         timestamptz := clock_timestamp();
BEGIN
    -- Bulk: every user assigned to + editor of one resource; half are cleared;
    -- every 10th user banned. Round-robin over resources.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_res, 'r'||(1 + g % n_res), r_assigned, t_user, 'u'||g FROM generate_series(1, n_users) g;
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_res, 'r'||(1 + g % n_res), r_editor,   t_user, 'u'||g FROM generate_series(1, n_users) g;
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_res, 'r'||(1 + g % n_res), r_cleared,  t_user, 'u'||g FROM generate_series(1, n_users) g WHERE g % 2 = 0;
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_res, 'r'||(1 + g % n_res), r_banned,   t_user, 'u'||g FROM generate_series(1, n_users) g WHERE g % 10 = 0;

    -- Named fixtures on r1 (deterministic ALLOW/DENY for each combine path).
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id) VALUES
        (s, t_res, 'r1', r_assigned, t_user, 'aa_user'),   -- assigned + cleared → can_access
        (s, t_res, 'r1', r_cleared,  t_user, 'aa_user'),
        (s, t_res, 'r1', r_assigned, t_user, 'a_user'),    -- assigned only      → NOT can_access
        (s, t_res, 'r1', r_editor,   t_user, 'ed_user'),   -- editor, not banned → can_edit
        (s, t_res, 'r1', r_editor,   t_user, 'eb_user'),   -- editor + banned    → NOT can_edit
        (s, t_res, 'r1', r_banned,   t_user, 'eb_user');

    -- multi_user: assigned + cleared on 20 resources (list_objects intersection).
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_res, 'rm'||g, r_assigned, t_user, 'multi_user' FROM generate_series(1, 20) g;
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_res, 'rm'||g, r_cleared,  t_user, 'multi_user' FROM generate_series(1, 20) g;

    -- Hot resource: hot_size assigned+cleared subjects, and hot_size editors of
    -- whom every 10th is banned (list_subjects over AND / BUT-NOT).
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_res, 'r_hot', r_assigned, t_user, 'hot'||g FROM generate_series(1, hot_size) g;
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_res, 'r_hot', r_cleared,  t_user, 'hot'||g FROM generate_series(1, hot_size) g;
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_res, 'r_hot', r_editor,   t_user, 'hot'||g FROM generate_series(1, hot_size) g;
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_res, 'r_hot', r_banned,   t_user, 'hot'||g FROM generate_series(1, hot_size) g WHERE g % 10 = 0;

    ANALYZE authz.tuples;
    RAISE INFO 'data loaded in % ms (% users, % resources, hot %); % tuples',
        round(extract(epoch from clock_timestamp()-t0)*1000), n_users, n_res, hot_size,
        (SELECT count(*) FROM authz.tuples WHERE store_id = s);
END $$;

-- Conditional viewer grants on r1 (one valid, one expired by request time).
SELECT authz.write_tuple('bench_rules','user','cond_ok','viewer','resource','r1',
    p_condition => 'non_expired', p_condition_context => '{"until":"2027-01-01T00:00:00Z"}'::jsonb);
SELECT authz.write_tuple('bench_rules','user','cond_exp','viewer','resource','r1',
    p_condition => 'non_expired', p_condition_context => '{"until":"2026-01-01T00:00:00Z"}'::jsonb);

-- ── Scenarios ───────────────────────────────────────────────────────
SELECT pg_temp._bench('check_access  intersection ALLOW (assigned AND cleared)',
    $$ SELECT authz.check_access('bench_rules','user','aa_user','can_access','resource','r1') $$, 500);

SELECT pg_temp._bench('check_access  intersection DENY (assigned, not cleared)',
    $$ SELECT authz.check_access('bench_rules','user','a_user','can_access','resource','r1') $$, 500);

SELECT pg_temp._bench('check_access  exclusion ALLOW (editor, not banned)',
    $$ SELECT authz.check_access('bench_rules','user','ed_user','can_edit','resource','r1') $$, 500);

SELECT pg_temp._bench('check_access  exclusion DENY (editor BUT banned)',
    $$ SELECT authz.check_access('bench_rules','user','eb_user','can_edit','resource','r1') $$, 500);

SELECT pg_temp._bench('check_with_context  condition ALLOW (within window)',
    $$ SELECT authz.check_access_with_context('bench_rules','user','cond_ok','can_view','resource','r1','{"now":"2026-06-01T00:00:00Z"}'::jsonb) $$, 500);

SELECT pg_temp._bench('check_with_context  condition DENY (expired)',
    $$ SELECT authz.check_access_with_context('bench_rules','user','cond_exp','can_view','resource','r1','{"now":"2026-06-01T00:00:00Z"}'::jsonb) $$, 500);

SELECT pg_temp._bench('list_objects  intersection (20 of 5k resources)',
    $$ SELECT count(*) FROM authz.list_objects('bench_rules','user','multi_user','can_access','resource') $$, 50);

SELECT pg_temp._bench('list_subjects intersection on hot resource',
    $$ SELECT count(*) FROM authz.list_subjects('bench_rules','user','can_access','resource','r_hot') $$, 20);

SELECT pg_temp._bench('list_subjects exclusion on hot resource (editors - banned)',
    $$ SELECT count(*) FROM authz.list_subjects('bench_rules','user','can_edit','resource','r_hot') $$, 20);

-- Tidy up (idempotent; the suite also resets at the top).
DO $$ BEGIN PERFORM authz.delete_store('bench_rules', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$;
