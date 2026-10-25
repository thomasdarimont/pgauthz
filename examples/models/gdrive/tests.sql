-- Authorization checks for the gdrive model: the permission matrix from
-- demo.sql, the share dialog (grant rules) and the one-owner rule. Uses the
-- shared test helpers (tests/sql/tests_helpers.sql); run via tests/test.sh
-- after model.sql + seed.sql. (The download quotas moved to examples/models/fileshare.)

SELECT _test_reset();

-- Permission matrix (seed.sql fixtures)
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('alice',    'can_read',         true),   -- owner of root → viewer from parent chain
        ('alice',    'can_write',        true),
        ('alice',    'can_share',        true),
        ('alice',    'can_change_owner', false),  -- doc ownership only
        ('bob',      'can_read',         true),   -- explicit viewer
        ('bob',      'can_write',        false),
        ('charlie',  'can_read',         true),   -- engineering#member viewer
        ('frank',    'can_change_owner', true),   -- doc owner
        ('stranger', 'can_read',         false)
    ) AS t(u, rel, expected)
    LOOP
        PERFORM _test_assert('gd_matrix_' || r.u || '_' || r.rel,
            authz.check_access('gdrive', 'user', r.u, r.rel, 'doc', 'design_spec')::text, r.expected::text);
    END LOOP;
    -- download = can_read
    PERFORM _test_assert('gd_download_follows_can_read',
        authz.check_access('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec')::text, 'true');
    PERFORM _test_assert('gd_download_denied_without_read',
        authz.check_access('gdrive', 'user', 'stranger', 'download', 'doc', 'design_spec')::text, 'false');
END;
$$;

-- Sharing (grant rules): the share dialog's answers and the write path.
DO $$
DECLARE v_err text; o record; v_res jsonb;
BEGIN
    SELECT * INTO o FROM authz.grant_options('gdrive', 'user', 'bob', 'doc', 'design_spec');
    PERFORM _test_assert('gd_share_bob_cannot', o.can_grant::text || '/' || o.can_revoke::text, 'false/false');
    SELECT * INTO o FROM authz.grant_options('gdrive', 'user', 'alice', 'doc', 'design_spec') WHERE relation = 'viewer';   -- the owner rule is the second row
    PERFORM _test_assert('gd_share_alice_grant_not_revoke', o.can_grant::text || '/' || o.can_revoke::text || '/' || o.requires_revoke, 'true/false/owner');
    PERFORM _test_assert('gd_share_grantee_types', array_to_string(o.grantee_types, ','), 'group#member,user,user:*');
    SELECT * INTO o FROM authz.grant_options('gdrive', 'user', 'frank', 'doc', 'design_spec') WHERE relation = 'viewer';
    PERFORM _test_assert('gd_share_owner_both', o.can_grant::text || '/' || o.can_revoke::text, 'true/true');
    PERFORM _test_assert('gd_share_inherited_on_folder', authz.can_grant('gdrive', 'user', 'alice', 'viewer', 'folder', 'projects')::text, 'true');

    PERFORM _test_assert('gd_share_alice_grants', authz.grant('gdrive', 'user', 'alice', 'user', 'dave', 'viewer', 'doc', 'design_spec')::text, 'true');
    PERFORM _test_assert('gd_share_dave_reads', authz.check_access('gdrive', 'user', 'dave', 'can_read', 'doc', 'design_spec')::text, 'true');
    PERFORM _test_assert('gd_share_attributed',
        (SELECT performed_by FROM authz.audit_list_object('gdrive', 'doc', 'design_spec') WHERE user_id = 'dave' AND action = 'INSERT' LIMIT 1), 'user:alice');
    BEGIN PERFORM authz.grant('gdrive', 'user', 'bob', 'user', 'erin', 'viewer', 'doc', 'design_spec');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('gd_share_bob_refused', v_err, 'grant refused: user:bob is not allowed can_share on doc:design_spec');
    v_err := NULL;
    BEGIN PERFORM authz.revoke('gdrive', 'user', 'alice', 'user', 'dave', 'viewer', 'doc', 'design_spec');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('gd_share_alice_cannot_revoke', v_err, 'revoke refused: user:alice is not allowed owner on doc:design_spec');
    v_res := authz.apply_grants('gdrive', 'user', 'frank',
        p_grants  => '[{"user_type":"user","user_id":"erin","relation":"viewer","object_type":"doc","object_id":"design_spec"}]',
        p_revokes => '[{"user_type":"user","user_id":"dave","relation":"viewer","object_type":"doc","object_id":"design_spec"}]');
    PERFORM _test_assert('gd_share_apply_grants', v_res::text, '{"granted": 1, "revoked": 1}');
    PERFORM _test_assert('gd_share_dave_gone', authz.check_access('gdrive', 'user', 'dave', 'can_read', 'doc', 'design_spec')::text, 'false');
    -- the public folder: viewer may be granted to user:* only by someone who can share the folder
    PERFORM _test_assert('gd_share_describe',
        (position('# grant requires can_share (revoke requires owner)' in authz.describe_model('gdrive')) > 0)::text, 'true');
    PERFORM authz.revoke('gdrive', 'user', 'frank', 'user', 'erin', 'viewer', 'doc', 'design_spec');
END;
$$;

-- Exactly one owner per document (relation constraints): the cap refuses a second
-- owner, the floor refuses revoking the last one, and a handover is one batch.
DO $$
DECLARE v_err text; v_state text; v_res jsonb; u record;
BEGIN
    BEGIN PERFORM authz.write_tuple('gdrive', 'user', 'gina', 'owner', 'doc', 'design_spec');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('gd_owner_cap', v_state || ' ' || v_err, 'ZA001 relation owner on doc:design_spec is full: 1 of 1 active direct assignments (max_direct)');
    v_err := NULL; v_state := NULL;
    BEGIN PERFORM authz.revoke('gdrive', 'user', 'frank', 'user', 'frank', 'owner', 'doc', 'design_spec');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('gd_owner_floor', v_state, 'ZA002');
    SELECT * INTO u FROM authz.relation_usage('gdrive', 'doc', 'design_spec', 'owner');
    PERFORM _test_assert('gd_owner_usage', u.direct_count::text || '/' || u.max_direct::text || ' min ' || u.min_direct::text || ' headroom ' || u.direct_headroom::text, '1/1 min 1 headroom 0');
    -- the handover: frank (can_change_owner as the owner) revokes himself and grants gina in one batch
    v_res := authz.apply_grants('gdrive', 'user', 'frank',
        p_grants  => '[{"user_type":"user","user_id":"gina","relation":"owner","object_type":"doc","object_id":"design_spec"}]',
        p_revokes => '[{"user_type":"user","user_id":"frank","relation":"owner","object_type":"doc","object_id":"design_spec"}]');
    PERFORM _test_assert('gd_owner_handover', v_res::text, '{"granted": 1, "revoked": 1}');
    PERFORM _test_assert('gd_owner_is_gina', authz.check_access('gdrive', 'user', 'gina', 'can_change_owner', 'doc', 'design_spec')::text || '/' || authz.check_access('gdrive', 'user', 'frank', 'can_change_owner', 'doc', 'design_spec')::text, 'true/false');
    -- a former owner cannot take it back: no can_change_owner, nothing changes
    v_state := NULL;
    BEGIN PERFORM authz.apply_grants('gdrive', 'user', 'frank',
        p_grants  => '[{"user_type":"user","user_id":"frank","relation":"owner","object_type":"doc","object_id":"design_spec"}]',
        p_revokes => '[{"user_type":"user","user_id":"gina","relation":"owner","object_type":"doc","object_id":"design_spec"}]');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('gd_owner_former_refused', v_state, '42501');
    PERFORM _test_assert_true('gd_owner_describe', position('# constraint: min_direct 1, max_direct 1' in authz.describe_model('gdrive')) > 0, authz.describe_model('gdrive'));
    -- hand it back so the seed state holds for the demo
    PERFORM authz.apply_grants('gdrive', 'user', 'gina',
        p_grants  => '[{"user_type":"user","user_id":"frank","relation":"owner","object_type":"doc","object_id":"design_spec"}]',
        p_revokes => '[{"user_type":"user","user_id":"gina","relation":"owner","object_type":"doc","object_id":"design_spec"}]');
END;
$$;

SELECT _test_report('gdrive model checks');
