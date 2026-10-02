-- Authorization checks for the gdrive model: the permission matrix from
-- demo.sql plus the temporal gates on doc.download (ADR 0012) — a daily quota
-- and a per-document limit over the action log. Uses the shared test helpers
-- (tests/sql/tests_helpers.sql); run via tests/test.sh after model.sql + seed.sql.

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

-- Temporal gates on doc.download
DO $$
DECLARE v_steps jsonb; v_objs text; r jsonb;
BEGIN
    PERFORM _test_assert('gd_gates_declared',
        (SELECT count(*) FROM authz.model_gates g
          WHERE g.store_id = authz._s('gdrive') AND g.relation = authz._r('gdrive', 'download'))::text, '2');

    -- three recorded downloads of design_spec: the 4th of the SAME doc is denied by the per-file limit
    PERFORM authz.record_event('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec', 'response') FROM generate_series(1, 3);
    PERFORM _test_assert('gd_per_file_limit_denies_4th',
        authz.check_access('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec')::text, 'false');
    PERFORM _test_assert('gd_per_file_limit_is_per_object',
        authz.check_access('gdrive', 'user', 'bob', 'download', 'doc', 'announcement')::text, 'true');
    PERFORM _test_assert('gd_reason_gate_denied',
        authz.explain_access('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec') -> 'decision' ->> 'reason', 'gate_denied');
    v_steps := jsonb_path_query_array(authz.explain_access('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec'),
                                      '$.trace[*] ? (@.rule_type == "temporal_gate")');
    PERFORM _test_assert('gd_explain_two_gate_steps',
        (SELECT string_agg((e->>'gate') || ':' || (e->>'reason') || ':' || (e->>'observed') || '/' || (e->>'threshold'), ' ' ORDER BY e->>'gate')
           FROM jsonb_array_elements(v_steps) e),
        'daily_download_quota:gate_passed:4/100 per_file_limit:gate_denied:4/3');
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO v_objs
      FROM authz.list_objects('gdrive', 'user', 'bob', 'download', 'doc');
    PERFORM _test_assert_true('gd_list_objects_excludes_capped_doc',
        v_objs NOT LIKE '%design_spec%' AND v_objs LIKE '%announcement%', v_objs);
    -- the other user is unaffected (gates are per principal)
    PERFORM _test_assert('gd_gate_is_per_principal',
        authz.check_access('gdrive', 'user', 'charlie', 'download', 'doc', 'design_spec')::text, 'true');

    -- the daily quota: 100 downloads across documents deny the 101st for that user
    PERFORM authz.record_event('gdrive', 'user', 'charlie', 'download', 'doc', 'd' || g, 'response')
       FROM generate_series(1, 100) g;
    PERFORM _test_assert('gd_daily_quota_denies_101st',
        authz.check_access('gdrive', 'user', 'charlie', 'download', 'doc', 'budget')::text, 'false');
    PERFORM _test_assert('gd_daily_quota_step',
        (SELECT (e->>'reason') || ':' || (e->>'observed')
           FROM jsonb_array_elements(jsonb_path_query_array(
                authz.explain_access('gdrive', 'user', 'charlie', 'download', 'doc', 'budget'),
                '$.trace[*] ? (@.gate == "daily_download_quota")')) e),
        'gate_denied:101');

    -- reserve_event: the strict tier records the request (or the refusal) itself
    r := authz.reserve_event('gdrive', 'user', 'bob', 'download', 'doc', 'announcement');
    PERFORM _test_assert('gd_reserve_allowed_records_request', (r->>'allowed') || ' ' || (r->>'kind'), 'true request');
    r := authz.reserve_event('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec');
    PERFORM _test_assert('gd_reserve_refused_records_denied', (r->>'allowed') || ' ' || (r->>'kind') || ' ' || (r->>'reason'), 'false denied gate_denied');

    -- describe_model renders the gates as comment lines under the define
    PERFORM _test_assert_true('gd_describe_renders_gates',
        position('# gate per_file_limit: at most 3 downloads of this document per UTC day' in authz.describe_model('gdrive')) > 0,
        authz.describe_model('gdrive'));
END;
$$;

-- Sharing (grant rules): the share dialog's answers and the write path.
DO $$
DECLARE v_err text; o record; v_res jsonb;
BEGIN
    SELECT * INTO o FROM authz.grant_options('gdrive', 'user', 'bob', 'doc', 'design_spec');
    PERFORM _test_assert('gd_share_bob_cannot', o.can_grant::text || '/' || o.can_revoke::text, 'false/false');
    SELECT * INTO o FROM authz.grant_options('gdrive', 'user', 'alice', 'doc', 'design_spec');
    PERFORM _test_assert('gd_share_alice_grant_not_revoke', o.can_grant::text || '/' || o.can_revoke::text || '/' || o.requires_revoke, 'true/false/owner');
    PERFORM _test_assert('gd_share_grantee_types', array_to_string(o.grantee_types, ','), 'group#member,user,user:*');
    SELECT * INTO o FROM authz.grant_options('gdrive', 'user', 'frank', 'doc', 'design_spec');
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

SELECT _test_report('gdrive model checks');
