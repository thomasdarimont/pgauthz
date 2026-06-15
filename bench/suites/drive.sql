-- Benchmark suite: Drive-shaped model (nested folders, groups, large user base).
--
-- Requires the harness (bench/lib/harness.sql) to be loaded in the same psql
-- session — bench/run.sh does that. Uses its own 'bench_drive' store.
-- Tunables are the constants in the data-generation block below.

SELECT pg_temp._bench_title('Drive model: nested folders + groups + 50k users');

-- ── Schema: model ───────────────────────────────────────────────────
DO $$ BEGIN PERFORM authz.delete_store('bench_drive', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$;
SELECT authz.create_store('bench_drive');

SELECT authz.model_register_type('bench_drive', 'user');
SELECT authz.model_register_type('bench_drive', 'group');
SELECT authz.model_register_type('bench_drive', 'folder');
SELECT authz.model_register_type('bench_drive', 'document');
SELECT authz.model_register_relation('bench_drive', r)
  FROM unnest(ARRAY['member','parent','viewer','editor','owner','can_view','can_edit']) r;

DO $$
DECLARE
    s         smallint := authz._s('bench_drive');
    t_group   smallint := authz._t(s,'group');
    t_folder  smallint := authz._t(s,'folder');
    t_doc     smallint := authz._t(s,'document');
    r_member  smallint := authz._r(s,'member');
    r_parent  smallint := authz._r(s,'parent');
    r_viewer  smallint := authz._r(s,'viewer');
    r_editor  smallint := authz._r(s,'editor');
    r_owner   smallint := authz._r(s,'owner');
    r_can_view smallint := authz._r(s,'can_view');
    r_can_edit smallint := authz._r(s,'can_edit');
BEGIN
    INSERT INTO authz.models
        (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed) VALUES
        -- group.member: direct (user or nested group#member)
        (s, t_group,  r_member,  authz._rel_direct(),   NULL,       NULL,     NULL),
        -- folder: viewer (direct), parent (direct), can_view = viewer OR parent->can_view
        (s, t_folder, r_viewer,  authz._rel_direct(),   NULL,       NULL,     NULL),
        (s, t_folder, r_parent,  authz._rel_direct(),   NULL,       NULL,     NULL),
        (s, t_folder, r_can_view,authz._rel_computed(), r_viewer,   NULL,     NULL),
        (s, t_folder, r_can_view,authz._rel_ttu(),      NULL,       r_parent, r_can_view),
        -- document: viewer/editor/owner/parent (direct)
        (s, t_doc, r_viewer, authz._rel_direct(), NULL, NULL, NULL),
        (s, t_doc, r_editor, authz._rel_direct(), NULL, NULL, NULL),
        (s, t_doc, r_owner,  authz._rel_direct(), NULL, NULL, NULL),
        (s, t_doc, r_parent, authz._rel_direct(), NULL, NULL, NULL),
        -- document.can_view = viewer OR owner OR parent->can_view
        (s, t_doc, r_can_view, authz._rel_computed(), r_viewer, NULL,     NULL),
        (s, t_doc, r_can_view, authz._rel_computed(), r_owner,  NULL,     NULL),
        (s, t_doc, r_can_view, authz._rel_ttu(),      NULL,     r_parent, r_can_view),
        -- document.can_edit = editor OR owner
        (s, t_doc, r_can_edit, authz._rel_computed(), r_editor, NULL, NULL),
        (s, t_doc, r_can_edit, authz._rel_computed(), r_owner,  NULL, NULL);
END $$;

-- ── Data generation ─────────────────────────────────────────────────
DO $$
DECLARE
    -- tunables
    n_users   int := 50000;   -- each owns a private doc (the large user base)
    n_groups  int := 200;
    grp_size  int := 50;      -- members per group
    depth     int := 15;      -- nested-folder chain length

    s        smallint := authz._s('bench_drive');
    t_group  smallint := authz._t(s,'group');
    t_folder smallint := authz._t(s,'folder');
    t_doc    smallint := authz._t(s,'document');
    t_user   smallint := authz._t(s,'user');
    r_member smallint := authz._r(s,'member');
    r_parent smallint := authz._r(s,'parent');
    r_viewer smallint := authz._r(s,'viewer');
    t0       timestamptz := clock_timestamp();
BEGIN
    -- Large user base: each user owns/views a private document.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_doc, 'priv_'||g, r_viewer, t_user, 'u'||g FROM generate_series(1, n_users) g;

    -- Groups with members (userset expansion targets).
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_group, 'g'||grp, r_member, t_user, 'u'||mem
      FROM generate_series(1, n_groups) grp
      CROSS JOIN LATERAL generate_series((grp-1)*grp_size + 1, grp*grp_size) mem;

    -- Nested folder chain f1 <- f2 <- ... <- f{depth}.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_folder, 'f'||lvl, r_parent, t_folder, 'f'||(lvl-1)
      FROM generate_series(2, depth) lvl;

    -- Deep scenario: deep_user views the TOP folder; a doc lives at the BOTTOM.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id) VALUES
        (s, t_folder, 'f1',        r_viewer, t_user,   'deep_user'),
        (s, t_doc,    'deep_doc',  r_parent, t_folder, 'f'||depth);

    -- Sparse user (list_objects): alice views 10 documents only.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_doc, 'alice_doc_'||g, r_viewer, t_user, 'alice' FROM generate_series(1, 10) g;

    -- Shared doc (list_subjects): granted to just 3 users out of n_users.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id) VALUES
        (s, t_doc, 'shared_doc', r_viewer, t_user, 'u1'),
        (s, t_doc, 'shared_doc', r_viewer, t_user, 'u2'),
        (s, t_doc, 'shared_doc', r_viewer, t_user, 'u3');

    -- Public doc (wildcard): everyone is a viewer.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id) VALUES
        (s, t_doc, 'public_doc', r_viewer, t_user, '*');

    -- Group-shared doc (userset): g1#member are viewers.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id, user_relation) VALUES
        (s, t_doc, 'group_doc', r_viewer, t_group, 'g1', r_member);

    ANALYZE authz.tuples;
    RAISE INFO 'data loaded in % ms (% users, % groups, depth %); % tuples',
        round(extract(epoch from clock_timestamp()-t0)*1000), n_users, n_groups, depth,
        (SELECT count(*) FROM authz.tuples WHERE store_id = s);
END $$;

-- ── Scenarios ───────────────────────────────────────────────────────
SELECT pg_temp._bench('check_access  shallow (direct viewer)',
    $$ SELECT authz.check_access('bench_drive','user','u1','can_view','document','priv_1') $$, 500);

SELECT pg_temp._bench('check_access  deep (15-folder TTU chain)',
    $$ SELECT authz.check_access('bench_drive','user','deep_user','can_view','document','deep_doc') $$, 300);

SELECT pg_temp._bench('check_access  via group membership (userset)',
    $$ SELECT authz.check_access('bench_drive','user','u1','can_view','document','group_doc') $$, 300);

SELECT pg_temp._bench('check_access  DENY (no path, full traversal)',
    $$ SELECT authz.check_access('bench_drive','user','nobody','can_view','document','deep_doc') $$, 300);

SELECT pg_temp._bench('check_access  via wildcard (public doc)',
    $$ SELECT authz.check_access('bench_drive','user','anyone','can_view','document','public_doc') $$, 500);

SELECT pg_temp._bench('list_objects  grant-sparse user (10 of 50k docs)',
    $$ SELECT count(*) FROM authz.list_objects('bench_drive','user','alice','can_view','document') $$, 50);

SELECT pg_temp._bench('list_subjects shared doc (3 of 50k users)',
    $$ SELECT count(*) FROM authz.list_subjects('bench_drive','user','can_view','document','shared_doc') $$, 50);

SELECT pg_temp._bench('list_subjects wildcard doc (O(1) row)',
    $$ SELECT count(*) FROM authz.list_subjects('bench_drive','user','can_view','document','public_doc') $$, 100);

SELECT pg_temp._bench('list_subjects group doc (userset expansion)',
    $$ SELECT count(*) FROM authz.list_subjects('bench_drive','user','can_view','document','group_doc') $$, 50);

SELECT pg_temp._bench('list_actions  (one user, one doc)',
    $$ SELECT count(*) FROM authz.list_actions('bench_drive','user','deep_user','document','deep_doc') $$, 300);

SELECT pg_temp._bench('check_with_contextual_tuples (inject 1)',
    $$ SELECT authz.check_access_with_contextual_tuples('bench_drive','user','ephemeral','can_view','document','shared_doc',
           NULL, ARRAY[ROW('user','ephemeral',NULL,'viewer','document','shared_doc')]::authz.tuple_input[]) $$, 300);

SELECT pg_temp._bench('audit_check_access (time-travel, replay)',
    $$ SELECT authz.audit_check_access('bench_drive','user','u1','can_view','document','priv_1', clock_timestamp()) $$, 20);

-- Tidy up (idempotent; the suite also resets at the top).
DO $$ BEGIN PERFORM authz.delete_store('bench_drive', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$;
