-- Benchmark suite: GitHub-shaped model (orgs, teams, repos, role hierarchy).
--
-- Requires the harness (bench/lib/harness.sql) in the same psql session —
-- bench/run.sh does that. Uses its own 'bench_github' store. Tunables are the
-- constants in the data-generation block.
--
-- Distinct from `drive`: a multi-level computed role hierarchy
-- (can_read <- can_write <- can_admin), tuple-to-userset to the parent org, and
-- NESTED TEAMS (team.member of team#member) — userset-of-userset recursion that
-- the flat groups in `drive` don't exercise.

SELECT pg_temp._bench_title('GitHub model: orgs + teams + repos + role hierarchy');

-- ── Schema: model ───────────────────────────────────────────────────
DO $$ BEGIN PERFORM authz.delete_store('bench_github', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$;
SELECT authz.create_store('bench_github');

SELECT authz.model_register_type('bench_github', t)
  FROM unnest(ARRAY['user','team','org','repo']) t;
SELECT authz.model_register_relation('bench_github', r)
  FROM unnest(ARRAY['member','admin','maintainer','writer','reader','parent_org',
                    'can_admin','can_write','can_read']) r;

DO $$
DECLARE
    s            smallint := authz._s('bench_github');
    t_team       smallint := authz._t(s,'team');
    t_org        smallint := authz._t(s,'org');
    t_repo       smallint := authz._t(s,'repo');
    r_member     smallint := authz._r(s,'member');
    r_admin      smallint := authz._r(s,'admin');
    r_maintainer smallint := authz._r(s,'maintainer');
    r_writer     smallint := authz._r(s,'writer');
    r_reader     smallint := authz._r(s,'reader');
    r_parent_org smallint := authz._r(s,'parent_org');
    r_can_admin  smallint := authz._r(s,'can_admin');
    r_can_write  smallint := authz._r(s,'can_write');
    r_can_read   smallint := authz._r(s,'can_read');
BEGIN
    INSERT INTO authz.models
        (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed) VALUES
        -- team.member: direct (user OR team#member → nested teams)
        (s, t_team, r_member, authz._rel_direct(), NULL, NULL, NULL),
        -- org.member / org.admin: direct
        (s, t_org, r_member, authz._rel_direct(), NULL, NULL, NULL),
        (s, t_org, r_admin,  authz._rel_direct(), NULL, NULL, NULL),
        -- repo direct roles + the org link
        (s, t_repo, r_parent_org, authz._rel_direct(), NULL, NULL, NULL),
        (s, t_repo, r_admin,      authz._rel_direct(), NULL, NULL, NULL),
        (s, t_repo, r_maintainer, authz._rel_direct(), NULL, NULL, NULL),
        (s, t_repo, r_writer,     authz._rel_direct(), NULL, NULL, NULL),
        (s, t_repo, r_reader,     authz._rel_direct(), NULL, NULL, NULL),
        -- repo.can_admin = admin OR parent_org->admin
        (s, t_repo, r_can_admin, authz._rel_computed(), r_admin, NULL,         NULL),
        (s, t_repo, r_can_admin, authz._rel_ttu(),      NULL,    r_parent_org, r_admin),
        -- repo.can_write = can_admin OR maintainer OR writer
        (s, t_repo, r_can_write, authz._rel_computed(), r_can_admin,  NULL, NULL),
        (s, t_repo, r_can_write, authz._rel_computed(), r_maintainer, NULL, NULL),
        (s, t_repo, r_can_write, authz._rel_computed(), r_writer,     NULL, NULL),
        -- repo.can_read = can_write OR reader OR parent_org->member
        (s, t_repo, r_can_read, authz._rel_computed(), r_can_write, NULL,         NULL),
        (s, t_repo, r_can_read, authz._rel_computed(), r_reader,    NULL,         NULL),
        (s, t_repo, r_can_read, authz._rel_ttu(),      NULL,        r_parent_org, r_member);
END $$;

-- ── Data generation ─────────────────────────────────────────────────
DO $$
DECLARE
    -- tunables
    n_users     int := 20000;
    n_orgs      int := 40;
    teams_org   int := 15;     -- teams per org
    team_size   int := 25;     -- members per team
    repos_org   int := 50;     -- repos per org
    nest_depth  int := 10;     -- nested-team chain length

    s            smallint := authz._s('bench_github');
    t_user       smallint := authz._t(s,'user');
    t_team       smallint := authz._t(s,'team');
    t_org        smallint := authz._t(s,'org');
    t_repo       smallint := authz._t(s,'repo');
    r_member     smallint := authz._r(s,'member');
    r_admin      smallint := authz._r(s,'admin');
    r_reader     smallint := authz._r(s,'reader');
    r_parent_org smallint := authz._r(s,'parent_org');
    t0           timestamptz := clock_timestamp();
BEGIN
    -- Every user is a member of one org (round-robin).
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_org, 'o'||(1 + g % n_orgs), r_member, t_user, 'u'||g FROM generate_series(1, n_users) g;

    -- Two admins per org.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_org, 'o'||o, r_admin, t_user, 'u'||((o-1)*2 + a)
      FROM generate_series(1, n_orgs) o CROSS JOIN generate_series(1, 2) a;

    -- Teams per org, each with team_size members (drawn from the org's users).
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_team, 'o'||o||'_t'||tm, r_member, t_user,
           'u'||(((o + tm * 37 + mem * 911) % n_users) + 1)
      FROM generate_series(1, n_orgs) o
      CROSS JOIN generate_series(1, teams_org) tm
      CROSS JOIN generate_series(1, team_size) mem;

    -- Repos per org: parent_org link + one team granted reader (team#member).
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_repo, 'o'||o||'_r'||rp, r_parent_org, t_org, 'o'||o
      FROM generate_series(1, n_orgs) o CROSS JOIN generate_series(1, repos_org) rp;
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id, user_relation)
    SELECT s, t_repo, 'o'||o||'_r'||rp, r_reader, t_team, 'o'||o||'_t'||(1 + rp % teams_org), r_member
      FROM generate_series(1, n_orgs) o CROSS JOIN generate_series(1, repos_org) rp;

    -- Nested-team chain: nest1 <- nest2 <- ... <- nest{depth} (member of member).
    -- deep_user is in nest1; deep_repo grants nest{depth}#member as reader.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id) VALUES
        (s, t_team, 'nest1', r_member, t_user, 'deep_user');
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id, user_relation)
    SELECT s, t_team, 'nest'||lvl, r_member, t_team, 'nest'||(lvl-1), r_member
      FROM generate_series(2, nest_depth) lvl;
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id) VALUES
        (s, t_repo, 'deep_repo', r_parent_org, t_org, 'o1');
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id, user_relation) VALUES
        (s, t_repo, 'deep_repo', r_reader, t_team, 'nest'||nest_depth, r_member);

    ANALYZE authz.tuples;
    RAISE INFO 'data loaded in % ms (% users, % orgs, % teams, % repos, nest %); % tuples',
        round(extract(epoch from clock_timestamp()-t0)*1000), n_users, n_orgs,
        n_orgs*teams_org, n_orgs*repos_org, nest_depth,
        (SELECT count(*) FROM authz.tuples WHERE store_id = s);
END $$;

-- ── Scenarios ───────────────────────────────────────────────────────
-- u1 is an admin of o1 (full role chain: admin -> can_admin -> can_write -> can_read).
SELECT pg_temp._bench('check_access  org-admin can_read (4-level role chain)',
    $$ SELECT authz.check_access('bench_github','user','u1','can_read','repo','o1_r1') $$, 300);

-- u40 is a plain member of o1 (round-robin: 1 + 40 % 40 = o1; admins are u1/u2)
-- → can_read via parent_org->member.
SELECT pg_temp._bench('check_access  org-member can_read (parent_org TTU)',
    $$ SELECT authz.check_access('bench_github','user','u40','can_read','repo','o1_r1') $$, 300);

SELECT pg_temp._bench('check_access  nested-team reader (10-deep userset)',
    $$ SELECT authz.check_access('bench_github','user','deep_user','can_read','repo','deep_repo') $$, 200);

SELECT pg_temp._bench('check_access  DENY (no path, full traversal)',
    $$ SELECT authz.check_access('bench_github','user','nobody','can_read','repo','deep_repo') $$, 200);

SELECT pg_temp._bench('check_access  can_write DENY for plain reader',
    $$ SELECT authz.check_access('bench_github','user','deep_user','can_write','repo','deep_repo') $$, 300);

-- An org admin can_read every repo in the org (parent_org->admin->...->can_read).
SELECT pg_temp._bench('list_objects  org-admin repos (50 of 2k repos)',
    $$ SELECT count(*) FROM authz.list_objects('bench_github','user','u1','can_read','repo') $$, 30);

SELECT pg_temp._bench('list_subjects repo readers (org members + team)',
    $$ SELECT count(*) FROM authz.list_subjects('bench_github','user','can_read','repo','o1_r1') $$, 20);

SELECT pg_temp._bench('list_actions  (admin on a repo)',
    $$ SELECT count(*) FROM authz.list_actions('bench_github','user','u1','repo','o1_r1') $$, 200);

-- Tidy up (idempotent; the suite also resets at the top).
DO $$ BEGIN PERFORM authz.delete_store('bench_github', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$;
