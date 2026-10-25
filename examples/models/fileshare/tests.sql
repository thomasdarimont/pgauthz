-- Authorization checks for the fileshare model: the gdrive permission matrix
-- plus what this example adds — the temporal gates on doc.download, sharing
-- as an action with its share-rate gates, the one-owner rule and the editor
-- cap. Uses the shared test helpers (tests/sql/tests_helpers.sql); run via
-- tests/test.sh after model.sql + seed.sql.

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
        ('dana',     'can_read',         true),   -- editor reads …
        ('dana',     'can_write',        true),   -- … and writes …
        ('dana',     'can_share',        false),  -- … but editors do not share here
        ('charlie',  'can_read',         true),   -- engineering#member viewer
        ('frank',    'can_change_owner', true),   -- doc owner
        ('stranger', 'can_read',         false)
    ) AS t(u, rel, expected)
    LOOP
        PERFORM _test_assert('fs_matrix_' || r.u || '_' || r.rel,
            authz.check_access('fileshare', 'user', r.u, r.rel, 'doc', 'design_spec')::text, r.expected::text);
    END LOOP;
    PERFORM _test_assert('fs_expiring_share_reads_now', authz.check_access('fileshare', 'user', 'temp', 'can_read', 'doc', 'budget')::text, 'true');
    PERFORM _test_assert('fs_download_follows_can_read',
        authz.check_access('fileshare', 'user', 'bob', 'download', 'doc', 'design_spec')::text, 'true');
END;
$$;

-- Temporal gates on doc.download
DO $$
DECLARE v_steps jsonb; r jsonb;
BEGIN
    PERFORM _test_assert('fs_gates_declared',
        (SELECT count(*) FROM authz.model_gates g
          WHERE g.store_id = authz._s('fileshare') AND g.relation = authz._r('fileshare', 'download'))::text, '2');
    -- three recorded downloads of design_spec: the 4th of the SAME doc is denied by the per-file limit
    PERFORM authz.record_event('fileshare', 'user', 'bob', 'download', 'doc', 'design_spec', 'response') FROM generate_series(1, 3);
    PERFORM _test_assert('fs_per_file_limit_denies_4th',
        authz.check_access('fileshare', 'user', 'bob', 'download', 'doc', 'design_spec')::text, 'false');
    PERFORM _test_assert('fs_other_doc_still_allowed',
        authz.check_access('fileshare', 'user', 'bob', 'download', 'doc', 'announcement')::text, 'true');
    PERFORM _test_assert('fs_reason_gate_denied',
        authz.explain_access('fileshare', 'user', 'bob', 'download', 'doc', 'design_spec') -> 'decision' ->> 'reason', 'gate_denied');
    v_steps := jsonb_path_query_array(authz.explain_access('fileshare', 'user', 'bob', 'download', 'doc', 'design_spec'),
                                      '$.trace[*] ? (@.rule_type == "temporal_gate")');
    PERFORM _test_assert('fs_explain_two_gate_steps',
        (SELECT string_agg((e->>'gate') || ':' || (e->>'reason') || ':' || (e->>'observed') || '/' || (e->>'threshold'), ' ' ORDER BY e->>'gate')
           FROM jsonb_array_elements(v_steps) e),
        'daily_download_quota:gate_passed:4/100 per_file_limit:gate_denied:4/3');
    PERFORM _test_assert('fs_list_objects_agrees',
        (SELECT string_agg(object_id, ',' ORDER BY object_id) FROM authz.list_objects('fileshare', 'user', 'bob', 'download', 'doc')), 'announcement');
    -- the other user is unaffected (gates are per principal)
    PERFORM _test_assert('fs_gate_is_per_principal',
        authz.check_access('fileshare', 'user', 'charlie', 'download', 'doc', 'design_spec')::text, 'true');
    -- the daily quota: 100 downloads across documents deny the 101st for that user
    PERFORM authz.record_event('fileshare', 'user', 'charlie', 'download', 'doc', 'd' || g, 'response')
       FROM generate_series(1, 100) g;
    PERFORM _test_assert('fs_daily_quota_denies_101st',
        authz.check_access('fileshare', 'user', 'charlie', 'download', 'doc', 'budget')::text, 'false');
    -- reserve_event: the strict tier records the request (or the refusal) itself
    r := authz.reserve_event('fileshare', 'user', 'bob', 'download', 'doc', 'announcement');
    PERFORM _test_assert('fs_reserve_allowed', (r->>'allowed') || ' ' || (r->>'kind'), 'true request');
    r := authz.reserve_event('fileshare', 'user', 'bob', 'download', 'doc', 'design_spec');
    PERFORM _test_assert('fs_reserve_refused_records_denied', (r->>'allowed') || ' ' || (r->>'kind') || ' ' || (r->>'reason'), 'false denied gate_denied');
    PERFORM _test_assert_true('fs_describe_renders_gates',
        position('# gate per_file_limit: at most 3 downloads of this document per UTC day' in authz.describe_model('fileshare')) > 0,
        authz.describe_model('fileshare'));
END;
$$;

-- Sharing as an action: grants and revokes are `share` events of the actor, the share-rate gates bound them
DO $$
DECLARE v_err text; v_n integer; v_res jsonb; o record;
BEGIN
    -- the dialog's answers for design_spec: alice (can_share from root) grants viewer but cannot revoke, frank (owner) does both and hands out editor
    SELECT * INTO o FROM authz.grant_options('fileshare', 'user', 'alice', 'doc', 'design_spec') WHERE relation = 'viewer';
    PERFORM _test_assert('fs_share_alice_viewer', o.can_grant::text || '/' || o.can_revoke::text || '/' || o.requires_revoke, 'true/false/owner');
    SELECT * INTO o FROM authz.grant_options('fileshare', 'user', 'alice', 'doc', 'design_spec') WHERE relation = 'editor';
    PERFORM _test_assert('fs_share_alice_no_editor', o.can_grant::text, 'false');
    SELECT * INTO o FROM authz.grant_options('fileshare', 'user', 'frank', 'doc', 'design_spec') WHERE relation = 'editor';
    PERFORM _test_assert('fs_share_frank_editor', o.can_grant::text || '/' || o.can_revoke::text, 'true/true');
    PERFORM _test_assert('fs_share_dana_cannot', authz.can_grant('fileshare', 'user', 'dana', 'viewer', 'doc', 'design_spec')::text, 'false');

    -- a grant is recorded as a share event of the actor; a no-op is not
    PERFORM _test_assert('fs_share_grant', authz.grant('fileshare', 'user', 'alice', 'user', 'erin', 'viewer', 'doc', 'design_spec')::text, 'true');
    PERFORM _test_assert('fs_share_event',
        (SELECT (payload->>'op') || ':' || (payload->>'user_id') || ' by ' || subject_id
           FROM authz.list_events('fileshare', p_action => 'share', p_subject_type => 'user', p_subject_id => 'alice')), 'grant:erin by alice');
    PERFORM authz.grant('fileshare', 'user', 'alice', 'user', 'erin', 'viewer', 'doc', 'design_spec');
    SELECT count(*) INTO v_n FROM authz.list_events('fileshare', p_action => 'share', p_subject_type => 'user', p_subject_id => 'alice');
    PERFORM _test_assert('fs_share_noop_not_recorded', v_n::text, '1');
    -- the dialog's save: one batch, each entry decided, events for the changes
    v_res := authz.apply_grants('fileshare', 'user', 'frank',
        p_grants  => '[{"user_type":"user","user_id":"gina","relation":"editor","object_type":"doc","object_id":"design_spec"}]',
        p_revokes => '[{"user_type":"user","user_id":"erin","relation":"viewer","object_type":"doc","object_id":"design_spec"}]');
    PERFORM _test_assert('fs_share_apply_grants', v_res::text, '{"granted": 1, "revoked": 1}');
    PERFORM _test_assert('fs_share_batch_events',
        (SELECT string_agg((payload->>'op') || ':' || (payload->>'relation') || ':' || (payload->>'user_id'), ',' ORDER BY seq)
           FROM authz.list_events('fileshare', p_action => 'share', p_subject_type => 'user', p_subject_id => 'frank')), 'revoke:viewer:erin,grant:editor:gina');
    PERFORM _test_assert('fs_share_gina_writes', authz.check_access('fileshare', 'user', 'gina', 'can_write', 'doc', 'design_spec')::text, 'true');

    -- share_spread: a document gains at most 10 new people a day — frank has shared with 1 (gina), 9 more pass, the 11th is vetoed
    PERFORM authz.grant('fileshare', 'user', 'frank', 'user', 'p' || g, 'viewer', 'doc', 'design_spec') FROM generate_series(1, 9) g;
    BEGIN PERFORM authz.grant('fileshare', 'user', 'frank', 'user', 'p10', 'viewer', 'doc', 'design_spec');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('fs_share_spread_vetoes_11th', v_err, 'grant refused: user:frank is not allowed can_share on doc:design_spec');
    PERFORM _test_assert('fs_share_spread_explain',
        (SELECT string_agg((e->>'gate') || ':' || (e->>'reason') || ':' || (e->>'observed') || '/' || (e->>'threshold'), ' ' ORDER BY e->>'gate')
           FROM jsonb_array_elements(jsonb_path_query_array(authz.explain_access('fileshare', 'user', 'frank', 'can_share', 'doc', 'design_spec'),
                                     '$.trace[*] ? (@.rule_type == "temporal_gate")')) e),
        'share_rate:gate_passed:12/20 share_spread:gate_denied:11/10');   -- 11 share events + this one; 10 distinct grantees + this one
    -- another document is unaffected (object scope), and a revoke is not a new person
    PERFORM _test_assert('fs_share_spread_per_document', authz.grant('fileshare', 'user', 'alice', 'user', 'p10', 'viewer', 'doc', 'budget')::text, 'true');
    PERFORM _test_assert('fs_share_revoke_still_fine', authz.revoke('fileshare', 'user', 'frank', 'user', 'p1', 'viewer', 'doc', 'design_spec')::text, 'true');
    PERFORM _test_assert_true('fs_describe_renders_record_as',
        position('# grant requires can_share (revoke requires owner), recorded as share' in authz.describe_model('fileshare')) > 0,
        authz.describe_model('fileshare'));
END;
$$;

-- Relation constraints: exactly one owner (handover as one batch), at most 10 editors
DO $$
DECLARE v_err text; v_state text; v_res jsonb; u record;
BEGIN
    BEGIN PERFORM authz.write_tuple('fileshare', 'user', 'gina', 'owner', 'doc', 'design_spec');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('fs_owner_cap', v_state || ' ' || v_err, 'ZA001 relation owner on doc:design_spec is full: 1 of 1 active direct assignments (max_direct)');
    v_state := NULL;
    BEGIN PERFORM authz.revoke('fileshare', 'user', 'frank', 'user', 'frank', 'owner', 'doc', 'design_spec');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('fs_owner_floor', v_state, 'ZA002');
    -- the handover: the owner revokes himself and grants the successor in one batch (and it is a share event)
    v_res := authz.apply_grants('fileshare', 'user', 'frank',
        p_grants  => '[{"user_type":"user","user_id":"gina","relation":"owner","object_type":"doc","object_id":"design_spec"}]',
        p_revokes => '[{"user_type":"user","user_id":"frank","relation":"owner","object_type":"doc","object_id":"design_spec"}]');
    PERFORM _test_assert('fs_owner_handover', v_res::text, '{"granted": 1, "revoked": 1}');
    PERFORM _test_assert('fs_owner_is_gina',
        authz.check_access('fileshare', 'user', 'gina', 'can_change_owner', 'doc', 'design_spec')::text || '/' ||
        authz.check_access('fileshare', 'user', 'frank', 'can_change_owner', 'doc', 'design_spec')::text, 'true/false');
    PERFORM _test_assert('fs_owner_handover_recorded',
        (SELECT string_agg((payload->>'op') || ':' || (payload->>'relation') || ':' || (payload->>'user_id'), ',' ORDER BY seq)
           FROM authz.list_events('fileshare', p_action => 'share', p_subject_type => 'user', p_subject_id => 'frank')
          WHERE payload->>'relation' = 'owner'), 'revoke:owner:frank,grant:owner:gina');
    -- editors: 10 direct at most; the group counts as one assignment, its members as effective editors
    PERFORM authz.write_tuple('fileshare', 'user', 'e' || g, 'editor', 'doc', 'budget') FROM generate_series(1, 9) g;
    PERFORM authz.write_tuple('fileshare', 'group', 'engineering', 'editor', 'doc', 'budget', 'member');
    v_state := NULL;
    BEGIN PERFORM authz.write_tuple('fileshare', 'user', 'e11', 'editor', 'doc', 'budget');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('fs_editor_cap', v_state, 'ZA001');
    SELECT * INTO u FROM authz.relation_usage('fileshare', 'doc', 'budget', 'editor');
    PERFORM _test_assert('fs_editor_usage',
        u.direct_count::text || '/' || u.max_direct::text || ' effective ' || u.effective_count::text || '/' || u.max_effective::text || ' headroom ' || u.effective_headroom::text,
        '10/10 effective 10/50 headroom 40');   -- e1..e9 + charlie (the group's member)
    PERFORM _test_assert_true('fs_describe_renders_constraints',
        position('# constraint: min_direct 1, max_direct 1' in authz.describe_model('fileshare')) > 0
        AND position('# constraint: max_direct 10, max_effective 50' in authz.describe_model('fileshare')) > 0,
        authz.describe_model('fileshare'));
    -- hand it back so the seed state holds for the demo
    PERFORM authz.apply_grants('fileshare', 'user', 'gina',
        p_grants  => '[{"user_type":"user","user_id":"frank","relation":"owner","object_type":"doc","object_id":"design_spec"}]',
        p_revokes => '[{"user_type":"user","user_id":"gina","relation":"owner","object_type":"doc","object_id":"design_spec"}]');
END;
$$;

SELECT _test_report('fileshare model checks');
