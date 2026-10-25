-- Tests for grant rules + authz.grant / authz.revoke (migration 0017):
-- sharing as a first-class, fail-closed API. Own store.

CREATE OR REPLACE FUNCTION _test_setup_grant() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_grant', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_grant');
    PERFORM authz.model_register_type('test_grant', 'user');
    PERFORM authz.model_register_type('test_grant', 'team');
    PERFORM authz.model_register_type('test_grant', 'document');
    PERFORM authz.model_register_relation('test_grant', r)
       FROM unnest(ARRAY['member','owner','editor','viewer','can_view','can_share_view','can_share_edit','office_only']) r;
    PERFORM authz.model_add_rule('test_grant', 'team', 'member', 'direct');
    PERFORM authz.model_add_type_restriction('test_grant', 'team', 'member', 'user');
    PERFORM authz.model_add_rule('test_grant', 'document', r, 'direct') FROM unnest(ARRAY['owner','editor','viewer']) r;
    PERFORM authz.model_add_type_restriction('test_grant', 'document', r, 'user') FROM unnest(ARRAY['owner','editor','viewer']) r;
    PERFORM authz.model_add_type_restriction('test_grant', 'document', 'viewer', 'team', p_allowed_user_relation => 'member');
    PERFORM authz.model_add_rule('test_grant', 'document', 'can_view', 'computed', r) FROM unnest(ARRAY['viewer','editor','owner']) r;
    PERFORM authz.model_add_rule('test_grant', 'document', 'can_share_view', 'computed', r) FROM unnest(ARRAY['editor','owner']) r;
    PERFORM authz.model_add_rule('test_grant', 'document', 'can_share_edit', 'computed', 'owner');
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view');
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'editor', 'can_share_edit', p_requires_revoke => 'owner');
    PERFORM authz.write_tuple('test_grant', 'user', 'alice', 'owner',  'document', 'plan');
    PERFORM authz.write_tuple('test_grant', 'user', 'bob',   'editor', 'document', 'plan');
END;
$$;

SELECT _test_setup_grant();

-- ga_01: an editor may share view access; the tuple is written and attributed to the actor
DO $$
BEGIN
    PERFORM _test_assert('ga_01_editor_grants_view', authz.grant('test_grant', 'user', 'bob', 'user', 'carol', 'viewer', 'document', 'plan')::text, 'true');
    PERFORM _test_assert('ga_01_carol_can_view', authz.check_access('test_grant', 'user', 'carol', 'can_view', 'document', 'plan')::text, 'true');
    PERFORM _test_assert('ga_01_audit_attributed_to_actor',
        (SELECT performed_by FROM authz.audit_list_object('test_grant', 'document', 'plan') WHERE user_id = 'carol' AND action = 'INSERT' LIMIT 1), 'user:bob');
    PERFORM _test_assert('ga_01_regrant_is_noop', authz.grant('test_grant', 'user', 'bob', 'user', 'carol', 'viewer', 'document', 'plan')::text, 'false');
END;
$$;

-- ga_02: an editor may NOT make someone an editor; nothing is written; the message names the missing right
DO $$
DECLARE v_err text; v_state text;
BEGIN
    BEGIN PERFORM authz.grant('test_grant', 'user', 'bob', 'user', 'dave', 'editor', 'document', 'plan');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('ga_02_refused_message', v_err, 'grant refused: user:bob is not allowed can_share_edit on document:plan');
    PERFORM _test_assert('ga_02_sqlstate_insufficient_privilege', v_state, '42501');
    PERFORM _test_assert('ga_02_nothing_written', authz.check_access('test_grant', 'user', 'dave', 'can_view', 'document', 'plan')::text, 'false');
END;
$$;

-- ga_03: the owner may; a viewer (no sharing right at all) may not even share view
DO $$
DECLARE v_err text;
BEGIN
    PERFORM _test_assert('ga_03_owner_grants_editor', authz.grant('test_grant', 'user', 'alice', 'user', 'dave', 'editor', 'document', 'plan')::text, 'true');
    BEGIN PERFORM authz.grant('test_grant', 'user', 'carol', 'user', 'erin', 'viewer', 'document', 'plan');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ga_03_viewer_cannot_share', v_err LIKE 'grant refused: user:carol is not allowed can_share_view%', coalesce(v_err, 'no error'));
END;
$$;

-- ga_04: no grant rule → refused outright, even for the owner (fail-closed by construction)
DO $$
DECLARE v_err text; v_state text;
BEGIN
    BEGIN PERFORM authz.grant('test_grant', 'user', 'alice', 'user', 'frank', 'owner', 'document', 'plan');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert_true('ga_04_no_rule_refused', v_err LIKE 'grant: no grant rule for document.owner%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('ga_04_sqlstate_check_violation', v_state, '23514');
END;
$$;

-- ga_05: revoke uses requires_revoke — an editor may revoke a viewer (same as grant) but only the owner may revoke an editor
DO $$
DECLARE v_err text;
BEGIN
    PERFORM _test_assert('ga_05_editor_revokes_viewer', authz.revoke('test_grant', 'user', 'bob', 'user', 'carol', 'viewer', 'document', 'plan')::text, 'true');
    PERFORM _test_assert('ga_05_revoke_again_false', authz.revoke('test_grant', 'user', 'bob', 'user', 'carol', 'viewer', 'document', 'plan')::text, 'false');
    BEGIN PERFORM authz.revoke('test_grant', 'user', 'bob', 'user', 'dave', 'editor', 'document', 'plan');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('ga_05_editor_cannot_revoke_editor', v_err, 'revoke refused: user:bob is not allowed owner on document:plan');
    PERFORM _test_assert('ga_05_owner_revokes_editor', authz.revoke('test_grant', 'user', 'alice', 'user', 'dave', 'editor', 'document', 'plan')::text, 'true');
    PERFORM _test_assert('ga_05_revoke_attributed',
        (SELECT performed_by FROM authz.audit_list_object('test_grant', 'document', 'plan') WHERE user_id = 'dave' AND action = 'DELETE' LIMIT 1), 'user:alice');
END;
$$;

-- ga_06: userset grantee and expiry pass through; type restrictions still apply
DO $$
DECLARE v_err text;
BEGIN
    PERFORM authz.write_tuple('test_grant', 'user', 'gina', 'member', 'team', 'mkt');
    PERFORM _test_assert('ga_06_share_with_team',
        authz.grant('test_grant', 'user', 'bob', 'team', 'mkt', 'viewer', 'document', 'plan',
                           p_user_relation => 'member', p_expires_at => now() + interval '1 hour')::text, 'true');
    PERFORM _test_assert('ga_06_member_can_view', authz.check_access('test_grant', 'user', 'gina', 'can_view', 'document', 'plan')::text, 'true');
    PERFORM _test_assert('ga_06_expiry_kept',
        (SELECT (t.expires_at IS NOT NULL)::text FROM authz.tuples t JOIN authz.types ut ON ut.id = t.user_type
          WHERE t.store_id = authz._s('test_grant') AND ut.name = 'team' AND t.user_id = 'mkt' AND t.object_id = 'plan'), 'true');
    -- team may not hold editor (no facet): the grant is refused by write_tuple's restriction check
    BEGIN PERFORM authz.grant('test_grant', 'user', 'alice', 'team', 'mkt', 'editor', 'document', 'plan', p_user_relation => 'member');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ga_06_restriction_still_enforced', v_err IS NOT NULL, 'editor granted to a team');
END;
$$;

-- ga_07: object wildcard refused; self-grant allowed by default
DO $$
DECLARE v_err text;
BEGIN
    BEGIN PERFORM authz.grant('test_grant', 'user', 'alice', 'user', 'zed', 'viewer', 'document', '*');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ga_07_object_wildcard_refused', v_err LIKE '%object wildcards cannot be granted%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('ga_07_self_grant_allowed', authz.grant('test_grant', 'user', 'bob', 'user', 'bob', 'viewer', 'document', 'plan')::text, 'true');
END;
$$;

-- ga_08: a conditional sharing right — the refusal names the missing context; with context it goes through
DO $$
DECLARE v_err text;
BEGIN
    PERFORM authz.create_condition_sql('test_grant', 'office_only', $c$ ($1->>'client_ip')::inet <<= '10.0.0.0/8'::cidr $c$, '{"request": ["client_ip"]}');
    PERFORM authz.model_add_type_restriction('test_grant', 'document', 'editor', 'user', p_condition => 'office_only');
    PERFORM authz.write_tuple('test_grant', 'user', 'hank', 'editor', 'document', 'memo', p_condition => 'office_only');
    BEGIN PERFORM authz.grant('test_grant', 'user', 'hank', 'user', 'ivy', 'viewer', 'document', 'memo');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('ga_08_missing_context_named', v_err,
        'grant refused: user:hank is not allowed can_share_view on document:memo (missing request context: request.client_ip)');
    PERFORM _test_assert('ga_08_with_context_allowed',
        authz.grant('test_grant', 'user', 'hank', 'user', 'ivy', 'viewer', 'document', 'memo', p_request_context => '{"client_ip": "10.1.2.3"}')::text, 'true');
    v_err := NULL;
    BEGIN PERFORM authz.grant('test_grant', 'user', 'hank', 'user', 'jo', 'viewer', 'document', 'memo', p_request_context => '{"client_ip": "8.8.8.8"}');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('ga_08_off_network_refused', v_err, 'grant refused: user:hank is not allowed can_share_view on document:memo');
END;
$$;

-- ga_09: rule management — self-requirement rejected, upsert changes in place and is audited, drop
DO $$
DECLARE v_err text; v_id1 int; v_id2 int;
BEGIN
    BEGIN PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'viewer');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ga_09_self_requirement_rejected', v_err LIKE '%cannot require itself%', coalesce(v_err, 'no error'));
    v_id1 := authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view');          -- unchanged: no-op
    v_id2 := authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_edit');          -- changed in place
    PERFORM _test_assert('ga_09_upsert_same_id', (v_id1 = v_id2)::text, 'true');
    PERFORM _test_assert('ga_09_audit_rows', (SELECT count(*) FROM authz.grant_rules_audit WHERE grant_rule_id = v_id1)::text, '3');   -- INSERT, DELETE, INSERT
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view');
    PERFORM _test_assert('ga_09_drop', authz.model_drop_grant_rule('test_grant', 'document', 'editor')::text, 'true');
    PERFORM _test_assert('ga_09_drop_again_false', authz.model_drop_grant_rule('test_grant', 'document', 'editor')::text, 'false');
    BEGIN PERFORM authz.grant('test_grant', 'user', 'alice', 'user', 'kim', 'editor', 'document', 'plan');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ga_09_dropped_rule_refuses', v_err LIKE '%no grant rule for document.editor%', coalesce(v_err, 'no error'));
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'editor', 'can_share_edit', p_requires_revoke => 'owner');
END;
$$;

-- ga_10: describe renders the rules; export carries them; a store without rules hashes as before
DO $$
DECLARE v_desc text; v_exp jsonb;
BEGIN
    v_desc := authz.describe_model('test_grant');
    PERFORM _test_assert_true('ga_10_describe_viewer', position('# grant requires can_share_view' in v_desc) > 0, v_desc);
    PERFORM _test_assert_true('ga_10_describe_editor', position('# grant requires can_share_edit (revoke requires owner)' in v_desc) > 0, v_desc);
    v_exp := authz.export_model('test_grant');
    PERFORM _test_assert('ga_10_export_count', jsonb_array_length(v_exp->'grant_rules')::text, '2');
    PERFORM _test_assert('ga_10_export_shape',
        (SELECT x::text FROM jsonb_array_elements(v_exp->'grant_rules') x WHERE x->>'relation' = 'editor'),
        '{"relation": "editor", "requires": "can_share_edit", "object_type": "document", "requires_revoke": "owner"}');
    PERFORM _test_assert('ga_10_checksum_neutral_when_empty',
        (authz._model_checksum('{"format": 1, "types": [], "grant_rules": []}'::jsonb) = authz._model_checksum('{"format": 1, "types": []}'::jsonb))::text, 'true');
END;
$$;

-- ga_11: the registry round-trips grant rules (publish → apply on a fresh store; stale rule removed)
DO $$
DECLARE v_ver int; v_desc text;
BEGIN
    BEGIN PERFORM authz.delete_store('test_grant_t2', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_grant_t2');
    v_ver := authz.publish_model('test_grant_model', 'test_grant');
    PERFORM authz.apply_model('test_grant_t2', 'test_grant_model', v_ver);
    PERFORM _test_assert('ga_11_applied_rules', (SELECT count(*) FROM authz.grant_rules WHERE store_id = authz._s('test_grant_t2'))::text, '2');
    PERFORM _test_assert('ga_11_in_sync', (SELECT in_sync::text FROM authz.model_status('test_grant_t2')), 'true');
    PERFORM _test_assert('ga_11_re_apply_quiet', (SELECT count(*) FROM authz.grant_rules_audit WHERE store_id = authz._s('test_grant_t2'))::text, '2');
    -- v2 drops the editor rule → apply removes it on the target
    PERFORM authz.model_drop_grant_rule('test_grant', 'document', 'editor');
    v_ver := authz.publish_model('test_grant_model', 'test_grant');
    PERFORM authz.apply_model('test_grant_t2', 'test_grant_model', v_ver);
    PERFORM _test_assert('ga_11_stale_rule_removed', (SELECT count(*) FROM authz.grant_rules WHERE store_id = authz._s('test_grant_t2'))::text, '1');
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'editor', 'can_share_edit', p_requires_revoke => 'owner');
END;
$$;

-- ga_12: model_remove_type takes the type's grant rules with it; delete_store cascades
DO $$
DECLARE v_sid int;
BEGIN
    PERFORM authz.model_register_type('test_grant', 'note');
    PERFORM authz.model_add_rule('test_grant', 'note', 'viewer', 'direct');
    PERFORM authz.model_add_type_restriction('test_grant', 'note', 'viewer', 'user');
    PERFORM authz.model_add_rule('test_grant', 'note', 'can_share_view', 'computed', 'viewer');
    PERFORM authz.model_add_grant_rule('test_grant', 'note', 'viewer', 'can_share_view');
    PERFORM authz.model_remove_type('test_grant', 'note');
    PERFORM _test_assert('ga_12_rules_gone_with_type',
        (SELECT count(*) FROM authz.grant_rules g JOIN authz.types t ON t.id = g.object_type WHERE g.store_id = authz._s('test_grant') AND t.name = 'note')::text, '0');
    v_sid := authz._s('test_grant_t2');
    PERFORM authz.delete_store('test_grant_t2', p_purge_audit => true);
    PERFORM _test_assert('ga_12_delete_store_cascades', (SELECT count(*) FROM authz.grant_rules_audit WHERE store_id = v_sid)::text, '0');
END;
$$;

-- ga_13: grant_options renders the dialog — per relation, can_grant / can_revoke and who may hold it
DO $$
DECLARE v_row record; n int;
BEGIN
    -- bob is an editor: may grant+revoke viewer, neither for editor (requires owner to revoke)
    SELECT count(*) INTO n FROM authz.grant_options('test_grant', 'user', 'bob', 'document', 'plan');
    PERFORM _test_assert('ga_13_one_row_per_rule', n::text, '2');
    SELECT * INTO v_row FROM authz.grant_options('test_grant', 'user', 'bob', 'document', 'plan') WHERE relation = 'viewer';
    PERFORM _test_assert('ga_13_bob_viewer', v_row.can_grant::text || '/' || v_row.can_revoke::text || '/' || v_row.requires || '/' || v_row.requires_revoke, 'true/true/can_share_view/can_share_view');
    PERFORM _test_assert('ga_13_viewer_grantee_types', array_to_string(v_row.grantee_types, ','), 'team#member,user');
    SELECT * INTO v_row FROM authz.grant_options('test_grant', 'user', 'bob', 'document', 'plan') WHERE relation = 'editor';
    PERFORM _test_assert('ga_13_bob_editor', v_row.can_grant::text || '/' || v_row.can_revoke::text || '/' || v_row.requires_revoke, 'false/false/owner');
    -- alice owns it: everything
    SELECT bool_and(can_grant AND can_revoke) INTO v_row FROM authz.grant_options('test_grant', 'user', 'alice', 'document', 'plan');
    PERFORM _test_assert('ga_13_owner_all', v_row.bool_and::text, 'true');
    -- predicates agree; unknown rule / wildcard object → false, not an error
    PERFORM _test_assert('ga_13_can_grant', authz.can_grant('test_grant', 'user', 'bob', 'viewer', 'document', 'plan')::text, 'true');
    PERFORM _test_assert('ga_13_can_revoke_editor_false', authz.can_revoke('test_grant', 'user', 'bob', 'editor', 'document', 'plan')::text, 'false');
    PERFORM _test_assert('ga_13_no_rule_false', authz.can_grant('test_grant', 'user', 'alice', 'owner', 'document', 'plan')::text, 'false');
    PERFORM _test_assert('ga_13_wildcard_false', authz.can_grant('test_grant', 'user', 'alice', 'viewer', 'document', '*')::text, 'false');
    -- conditional sharing right: context decides
    PERFORM _test_assert('ga_13_ctx_missing', authz.can_grant('test_grant', 'user', 'hank', 'viewer', 'document', 'memo')::text, 'false');
    PERFORM _test_assert('ga_13_ctx_given', authz.can_grant('test_grant', 'user', 'hank', 'viewer', 'document', 'memo', '{"client_ip": "10.1.2.3"}')::text, 'true');
    -- batch: many (actor, object) pairs, rows carry the request index and identity
    SELECT count(*) INTO n FROM authz.grant_options_batch('test_grant', '[
        {"actor_type": "user", "actor_id": "bob",   "object_type": "document", "object_id": "plan"},
        {"actor_type": "user", "actor_id": "alice", "object_type": "document", "object_id": "plan"},
        {"actor_type": "user", "actor_id": "hank",  "object_type": "document", "object_id": "memo", "context": {"client_ip": "10.1.2.3"}}]');
    PERFORM _test_assert('ga_13_batch_rows', n::text, '6');
    PERFORM _test_assert('ga_13_batch_identity',
        (SELECT idx::text || '/' || actor_id || '/' || can_grant::text FROM authz.grant_options_batch('test_grant', '[
            {"actor_type": "user", "actor_id": "bob",  "object_type": "document", "object_id": "plan"},
            {"actor_type": "user", "actor_id": "hank", "object_type": "document", "object_id": "memo", "context": {"client_ip": "10.1.2.3"}}]')
          WHERE idx = 1 AND relation = 'viewer'), '1/hank/true');
    -- rules by name, for "which of my documents can I share" via list_objects on requires
    SELECT count(*) INTO n FROM authz.list_grant_rules('test_grant');
    PERFORM _test_assert('ga_13_list_grant_rules', n::text, '2');
    SELECT count(*) INTO n FROM authz.list_objects('test_grant', 'user', 'bob', 'can_share_view', 'document');
    PERFORM _test_assert('ga_13_shareable_objects', n::text, '1');
END;
$$;

-- ga_14: apply_grants — one transaction, all-or-nothing, counts only real changes
DO $$
DECLARE v_res jsonb; v_err text; v_state text;
BEGIN
    v_res := authz.apply_grants('test_grant', 'user', 'alice',
        p_grants  => '[{"user_type":"user","user_id":"liz","relation":"viewer","object_type":"document","object_id":"plan"},
                       {"user_type":"user","user_id":"max","relation":"editor","object_type":"document","object_id":"plan","expires_at":"2030-01-01T00:00:00Z"},
                       {"user_type":"user","user_id":"bob","relation":"editor","object_type":"document","object_id":"plan"}]',
        p_revokes => '[{"user_type":"user","user_id":"bob","relation":"viewer","object_type":"document","object_id":"plan"}]');
    PERFORM _test_assert('ga_14_counts', v_res::text, '{"granted": 2, "revoked": 1}');   -- bob already editor: 0
    PERFORM _test_assert('ga_14_liz_can_view', authz.check_access('test_grant', 'user', 'liz', 'can_view', 'document', 'plan')::text, 'true');
    -- bob (editor) tries to add a viewer AND an editor in one batch: the editor entry is refused → nothing written
    BEGIN
        PERFORM authz.apply_grants('test_grant', 'user', 'bob',
            p_grants => '[{"user_type":"user","user_id":"nia","relation":"viewer","object_type":"document","object_id":"plan"},
                          {"user_type":"user","user_id":"omar","relation":"editor","object_type":"document","object_id":"plan"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('ga_14_refused_names_entry', v_err, 'apply_grants: grant entry 2: grant refused: user:bob is not allowed can_share_edit on document:plan');
    PERFORM _test_assert('ga_14_sqlstate_kept', v_state, '42501');
    PERFORM _test_assert('ga_14_all_or_nothing', authz.check_access('test_grant', 'user', 'nia', 'can_view', 'document', 'plan')::text, 'false');
    -- per-entry context overrides the batch context
    v_res := authz.apply_grants('test_grant', 'user', 'hank',
        p_grants => '[{"user_type":"user","user_id":"pia","relation":"viewer","object_type":"document","object_id":"memo","context":{"client_ip":"10.9.9.9"}}]',
        p_context => '{"client_ip": "8.8.8.8"}');
    PERFORM _test_assert('ga_14_entry_context_wins', v_res->>'granted', '1');
    PERFORM _test_assert('ga_14_audit_by_actor',
        (SELECT performed_by FROM authz.audit_list_object('test_grant', 'document', 'plan') WHERE user_id = 'liz' AND action = 'INSERT' LIMIT 1), 'user:alice');
END;
$$;

-- ga_15: sharing as an action (record_as, migration 0027) — grants and revokes are events of the actor,
-- gates on the required relation then bound sharing with no PEP code
DO $$
DECLARE v_n integer; v_ev record; v_err text; v_state text;
BEGIN
    PERFORM authz.model_register_relation('test_grant', 'share', NULL, '{"kind": "permission"}');
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view', p_record_as => 'share');
    PERFORM _test_assert('ga_15_rule_lists_record_as',
        (SELECT record_as FROM authz.list_grant_rules('test_grant') WHERE object_type = 'document' AND relation = 'viewer'), 'share');
    PERFORM _test_assert_true('ga_15_describe', authz.describe_model('test_grant') LIKE '%# grant requires can_share_view, recorded as share%', authz.describe_model('test_grant'));
    PERFORM _test_assert('ga_15_export',
        (SELECT x->>'record_as' FROM jsonb_array_elements(authz.export_model('test_grant')->'grant_rules') x WHERE x->>'relation' = 'viewer'), 'share');
    PERFORM _test_assert('ga_15_export_absent_when_unset',
        (SELECT (x ? 'record_as')::text FROM jsonb_array_elements(authz.export_model('test_grant')->'grant_rules') x WHERE x->>'relation' = 'editor'), 'false');

    SELECT count(*) INTO v_n FROM authz.list_events('test_grant', p_action => 'share');
    PERFORM _test_assert('ga_15_no_events_yet', v_n::text, '0');
    PERFORM _test_assert('ga_15_grant', authz.grant('test_grant', 'user', 'bob', 'user', 'rick', 'viewer', 'document', 'plan')::text, 'true');
    SELECT * INTO v_ev FROM authz.list_events('test_grant', p_action => 'share');
    PERFORM _test_assert('ga_15_event_for_actor', v_ev.subject_type || ':' || v_ev.subject_id || ' ' || v_ev.action || ' ' || v_ev.object_type || ':' || v_ev.object_id || ' ' || v_ev.kind, 'user:bob share document:plan request');
    PERFORM _test_assert('ga_15_event_payload', v_ev.payload::text, '{"op": "grant", "user_id": "rick", "relation": "viewer", "user_type": "user"}');
    -- a no-op grant is not an action
    PERFORM _test_assert('ga_15_regrant_noop', authz.grant('test_grant', 'user', 'bob', 'user', 'rick', 'viewer', 'document', 'plan')::text, 'false');
    SELECT count(*) INTO v_n FROM authz.list_events('test_grant', p_action => 'share');
    PERFORM _test_assert('ga_15_noop_not_recorded', v_n::text, '1');
    -- revoke records op revoke; a rule without record_as records nothing (editor)
    PERFORM _test_assert('ga_15_revoke', authz.revoke('test_grant', 'user', 'alice', 'user', 'rick', 'viewer', 'document', 'plan')::text, 'true');
    PERFORM _test_assert('ga_15_revoke_recorded',
        (SELECT payload->>'op' FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'alice')), 'revoke');
    PERFORM authz.grant('test_grant', 'user', 'alice', 'user', 'rick', 'editor', 'document', 'plan');
    SELECT count(*) INTO v_n FROM authz.list_events('test_grant');
    PERFORM _test_assert('ga_15_unrecorded_rule_silent', v_n::text, '2');
    -- apply_grants: one event per effective entry
    PERFORM authz.apply_grants('test_grant', 'user', 'alice',
        p_grants => '[{"user_type":"user","user_id":"sam","relation":"viewer","object_type":"document","object_id":"plan"},
                      {"user_type":"user","user_id":"tom","relation":"viewer","object_type":"document","object_id":"plan","expires_at":"2099-01-01T00:00:00Z"}]');
    SELECT count(*) INTO v_n FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'alice');
    PERFORM _test_assert('ga_15_apply_grants_recorded', v_n::text, '3');
    PERFORM _test_assert('ga_15_expiry_in_payload',
        (SELECT ((payload->>'expires_at')::timestamptz = '2099-01-01T00:00:00Z'::timestamptz)::text FROM authz.list_events('test_grant', p_action => 'share') WHERE payload->>'user_id' = 'tom'), 'true');

    -- a gate on the required relation bounds sharing: at most 3 shares an hour, this one included
    PERFORM authz.add_gate('test_grant', 'document', 'can_share_view', 'share_rate',
        '{"all_of": [{"count_within": {"window": "1h", "action": "share", "max": 3, "plus": 1}}]}');
    -- alice has 3 share events: the 4th grant is refused by the gate, not written, not recorded
    BEGIN PERFORM authz.grant('test_grant', 'user', 'alice', 'user', 'uma', 'viewer', 'document', 'plan');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert_true('ga_15_gate_vetoes_4th_share', v_err LIKE 'grant refused: user:alice is not allowed can_share_view%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('ga_15_gate_sqlstate', v_state, '42501');
    PERFORM _test_assert('ga_15_vetoed_not_written', authz.check_access('test_grant', 'user', 'uma', 'can_view', 'document', 'plan')::text, 'false');
    -- bob has 1 share event: still within the gate
    PERFORM _test_assert('ga_15_other_actor_unaffected', authz.grant('test_grant', 'user', 'bob', 'user', 'uma', 'viewer', 'document', 'plan')::text, 'true');
    PERFORM authz.drop_gate('test_grant', 'document', 'can_share_view', 'share_rate');

    -- a payload schema on the recorded action applies to the engine's payload too
    PERFORM authz.model_set_payload_schema('test_grant', 'share', '{"required": {"ticket": "string"}}');
    v_err := NULL;
    BEGIN PERFORM authz.grant('test_grant', 'user', 'bob', 'user', 'vic', 'viewer', 'document', 'plan');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ga_15_payload_schema_applies', v_err IS NOT NULL AND v_err LIKE '%ticket%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('ga_15_schema_failure_rolls_back_grant', authz.check_access('test_grant', 'user', 'vic', 'can_view', 'document', 'plan')::text, 'false');
    PERFORM authz.model_set_payload_schema('test_grant', 'share', '{"required": {"op": "string", "relation": "string"}, "additional": true}');
    PERFORM _test_assert('ga_15_matching_schema_ok', authz.grant('test_grant', 'user', 'bob', 'user', 'vic', 'viewer', 'document', 'plan')::text, 'true');
    PERFORM authz.model_set_payload_schema('test_grant', 'share', NULL);
    -- registry round trip keeps record_as
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view');   -- clears it
    PERFORM _test_assert('ga_15_clear_record_as',
        (SELECT coalesce(record_as, '-') FROM authz.list_grant_rules('test_grant') WHERE object_type = 'document' AND relation = 'viewer'), '-');
END;
$$;

-- ga_16 (review on 46d683d): a gate keeps its sequential meaning inside an apply_grants batch —
-- entry k's quota check sees the events of entries 1..k-1, so a batch cannot exceed what single calls enforce
DO $$
DECLARE v_err text; v_n integer; v_res jsonb;
BEGIN
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view', p_record_as => 'share');
    PERFORM authz.write_tuple('test_grant', 'user', 'gil', 'editor', 'document', 'memo');   -- gil may share memo
    PERFORM authz.add_gate('test_grant', 'document', 'can_share_view', 'one_share',
        '{"all_of": [{"count_within": {"window": "1h", "action": "share", "max": 1, "plus": 1}}]}');
    -- two grants in one batch: the second is vetoed by the first's event, nothing is written, nothing recorded
    BEGIN PERFORM authz.apply_grants('test_grant', 'user', 'gil',
        p_grants => '[{"user_type":"user","user_id":"h1","relation":"viewer","object_type":"document","object_id":"memo"},
                      {"user_type":"user","user_id":"h2","relation":"viewer","object_type":"document","object_id":"memo"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ga_16_batch_second_entry_vetoed', v_err LIKE 'apply_grants: grant entry 2: grant refused: user:gil is not allowed can_share_view%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('ga_16_nothing_written', authz.check_access('test_grant', 'user', 'h1', 'can_view', 'document', 'memo')::text, 'false');
    SELECT count(*) INTO v_n FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    PERFORM _test_assert('ga_16_nothing_recorded', v_n::text, '0');
    -- one grant passes and is recorded once; a no-op re-grant in a later batch records nothing and is not vetoed
    v_res := authz.apply_grants('test_grant', 'user', 'gil',
        p_grants => '[{"user_type":"user","user_id":"h1","relation":"viewer","object_type":"document","object_id":"memo"}]');
    PERFORM _test_assert('ga_16_single_passes', v_res->>'granted', '1');
    SELECT count(*) INTO v_n FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    PERFORM _test_assert('ga_16_recorded_once', v_n::text, '1');
    -- the quota is now used up: a further single grant is refused like the batch was (a no-op
    -- re-grant too — the gate decides before the write says whether anything would change)
    v_err := NULL;
    BEGIN PERFORM authz.grant('test_grant', 'user', 'gil', 'user', 'h3', 'viewer', 'document', 'memo');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ga_16_quota_used', v_err LIKE 'grant refused: user:gil is not allowed can_share_view%', coalesce(v_err, 'no error'));
    PERFORM authz.drop_gate('test_grant', 'document', 'can_share_view', 'one_share');
    -- a no-op re-grant in a batch records nothing
    v_res := authz.apply_grants('test_grant', 'user', 'gil',
        p_grants => '[{"user_type":"user","user_id":"h1","relation":"viewer","object_type":"document","object_id":"memo"}]');
    PERFORM _test_assert('ga_16_noop_batch_ok', v_res->>'granted', '0');
    SELECT count(*) INTO v_n FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    PERFORM _test_assert('ga_16_noop_not_recorded', v_n::text, '1');
    -- the events a batch records match what it changed: revoke h1 + grant h4 → two events, op revoke and op grant
    PERFORM authz.apply_grants('test_grant', 'user', 'gil',
        p_grants  => '[{"user_type":"user","user_id":"h4","relation":"viewer","object_type":"document","object_id":"memo"}]',
        p_revokes => '[{"user_type":"user","user_id":"h1","relation":"viewer","object_type":"document","object_id":"memo"}]');
    PERFORM _test_assert('ga_16_batch_events',
        (SELECT string_agg(payload->>'op' || ':' || (payload->>'user_id'), ',' ORDER BY seq)
           FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil')), 'grant:h1,revoke:h1,grant:h4');
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view');
END;
$$;

-- ga_18 (review on 144771d): the batch's events follow the simulated tuple state — same-holder replacements count
DO $$
DECLARE v_n integer; v_res jsonb; v_before integer;
BEGIN
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view', p_record_as => 'share');
    SELECT count(*) INTO v_before FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    -- revoke-and-regrant of the same holder: two changes, two events (revoke, grant)
    v_res := authz.apply_grants('test_grant', 'user', 'gil',
        p_revokes => '[{"user_type":"user","user_id":"h4","relation":"viewer","object_type":"document","object_id":"memo"}]',
        p_grants  => '[{"user_type":"user","user_id":"h4","relation":"viewer","object_type":"document","object_id":"memo"}]');
    PERFORM _test_assert('ga_18_regrant_applies', v_res::text, '{"granted": 1, "revoked": 1}');
    PERFORM _test_assert('ga_18_regrant_two_events',
        (SELECT string_agg(payload->>'op', ',' ORDER BY seq) FROM (SELECT * FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil') ORDER BY seq OFFSET v_before) e), 'revoke,grant');
    -- two grants on one holder: the first changes the expiry, the second restores it — two changes, two events
    SELECT count(*) INTO v_before FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    v_res := authz.apply_grants('test_grant', 'user', 'gil',
        p_grants => '[{"user_type":"user","user_id":"h4","relation":"viewer","object_type":"document","object_id":"memo","expires_at":"2099-01-01T00:00:00Z"},
                      {"user_type":"user","user_id":"h4","relation":"viewer","object_type":"document","object_id":"memo"}]');
    PERFORM _test_assert('ga_18_metadata_roundtrip_applies', v_res->>'granted', '2');
    SELECT count(*) INTO v_n FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    PERFORM _test_assert('ga_18_metadata_roundtrip_two_events', (v_n - v_before)::text, '2');
    PERFORM _test_assert('ga_18_final_state_no_expiry',
        (SELECT (expires_at IS NULL)::text FROM authz.tuples t WHERE t.store_id = authz._s('test_grant') AND t.object_id = 'memo' AND t.user_id = 'h4'), 'true');
    -- a grant identical to the simulated state is a no-op: grant with expiry twice → one change, one event
    SELECT count(*) INTO v_before FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    v_res := authz.apply_grants('test_grant', 'user', 'gil',
        p_grants => '[{"user_type":"user","user_id":"h4","relation":"viewer","object_type":"document","object_id":"memo","expires_at":"2099-01-01T00:00:00Z"},
                      {"user_type":"user","user_id":"h4","relation":"viewer","object_type":"document","object_id":"memo","expires_at":"2099-01-01T00:00:00Z"}]');
    PERFORM _test_assert('ga_18_duplicate_grant_one_change', v_res->>'granted', '1');
    SELECT count(*) INTO v_n FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    PERFORM _test_assert('ga_18_duplicate_grant_one_event', (v_n - v_before)::text, '1');
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view');
END;
$$;

-- ga_19 (review on f81b9c0): distinct tuple identities that a delimiter-joined key would merge
-- (team:eng#member vs the plain subject team:"eng|member") stay distinct in the simulated state
DO $$
DECLARE v_res jsonb; v_before integer; v_n integer;
BEGIN
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view', p_record_as => 'share');
    PERFORM authz.model_add_type_restriction('test_grant', 'document', 'viewer', 'team');   -- a team itself may view
    PERFORM authz.write_tuple('test_grant', 'user', 'eng|member', 'member', 'team', 'eng');
    SELECT count(*) INTO v_before FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    v_res := authz.apply_grants('test_grant', 'user', 'gil',
        p_grants => '[{"user_type":"team","user_id":"eng","user_relation":"member","relation":"viewer","object_type":"document","object_id":"memo"},
                      {"user_type":"team","user_id":"eng|member","relation":"viewer","object_type":"document","object_id":"memo"}]');
    PERFORM _test_assert('ga_19_both_granted', v_res->>'granted', '2');
    SELECT count(*) INTO v_n FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    PERFORM _test_assert('ga_19_two_events', (v_n - v_before)::text, '2');
    PERFORM _test_assert('ga_19_two_tuples',
        (SELECT string_agg(t.user_id || '#' || coalesce(ur.name, '-'), ',' ORDER BY t.user_id)
           FROM authz.tuples t LEFT JOIN authz.relations ur ON ur.id = t.user_relation
          WHERE t.store_id = authz._s('test_grant') AND t.object_id = 'memo' AND t.user_id IN ('eng', 'eng|member')), 'eng#member,eng|member#-');
    -- mixed: revoke the userset, re-grant the plain subject with an expiry (a metadata change) — two events
    SELECT count(*) INTO v_before FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    v_res := authz.apply_grants('test_grant', 'user', 'gil',
        p_revokes => '[{"user_type":"team","user_id":"eng","user_relation":"member","relation":"viewer","object_type":"document","object_id":"memo"}]',
        p_grants  => '[{"user_type":"team","user_id":"eng|member","relation":"viewer","object_type":"document","object_id":"memo","expires_at":"2099-01-01T00:00:00Z"}]');
    PERFORM _test_assert('ga_19_mixed_applies', v_res::text, '{"granted": 1, "revoked": 1}');
    SELECT count(*) INTO v_n FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    PERFORM _test_assert('ga_19_mixed_two_events', (v_n - v_before)::text, '2');
    PERFORM _test_assert('ga_19_mixed_state',
        (SELECT string_agg(t.user_id || '#' || coalesce(ur.name, '-') || ':' || CASE WHEN t.expires_at = '2099-01-01T00:00:00Z'::timestamptz THEN 'expiring' ELSE coalesce(t.expires_at::text, 'never') END, ',' ORDER BY t.user_id)
           FROM authz.tuples t LEFT JOIN authz.relations ur ON ur.id = t.user_relation
          WHERE t.store_id = authz._s('test_grant') AND t.object_id = 'memo' AND t.user_id IN ('eng', 'eng|member')), 'eng|member#-:expiring');
    -- two revokes of the formerly colliding identities in one batch — two revoke events, nothing left
    PERFORM authz.grant('test_grant', 'user', 'gil', 'team', 'eng', 'viewer', 'document', 'memo', p_user_relation => 'member');
    SELECT count(*) INTO v_before FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil');
    v_res := authz.apply_grants('test_grant', 'user', 'gil',
        p_revokes => '[{"user_type":"team","user_id":"eng","user_relation":"member","relation":"viewer","object_type":"document","object_id":"memo"},
                       {"user_type":"team","user_id":"eng|member","relation":"viewer","object_type":"document","object_id":"memo"}]');
    PERFORM _test_assert('ga_19_two_revokes', v_res->>'revoked', '2');
    PERFORM _test_assert('ga_19_two_revoke_events',
        (SELECT string_agg(payload->>'op' || ':' || (payload->>'user_id') || '#' || coalesce(payload->>'user_relation', '-'), ',' ORDER BY seq)
           FROM (SELECT * FROM authz.list_events('test_grant', p_action => 'share', p_subject_type => 'user', p_subject_id => 'gil') ORDER BY seq OFFSET v_before) e),
        'revoke:eng#member,revoke:eng|member#-');
    PERFORM _test_assert('ga_19_nothing_left',
        (SELECT count(*)::text FROM authz.tuples t WHERE t.store_id = authz._s('test_grant') AND t.object_id = 'memo' AND t.user_id IN ('eng', 'eng|member')), '0');
    PERFORM authz.model_add_grant_rule('test_grant', 'document', 'viewer', 'can_share_view');
END;
$$;

-- ga_17: no internal (underscore) engine function is executable by an application role —
-- the *_impl variants with their check-skipping flags are reachable only through the public API
DO $$
DECLARE v_bad text;
BEGIN
    SELECT string_agg(r.rolname || ':' || p.proname, ', ' ORDER BY 1) INTO v_bad
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN (VALUES ('authz_reader'),('authz_writer'),('authz_sharer'),('authz_admin'),('authz_recorder'),('authz_auditor'),('authz_contextual_reader')) r(rolname)
     WHERE n.nspname = 'authz' AND p.proname LIKE '\_%' AND p.proname NOT LIKE '\_test\_%'   -- the suites' own helpers
       AND has_function_privilege(r.rolname, p.oid, 'EXECUTE');
    PERFORM _test_assert('ga_17_no_internal_function_executable_by_app_roles', coalesce(v_bad, 'none'), 'none');
END;
$$;

DROP FUNCTION IF EXISTS _test_setup_grant();

SELECT _test_report('grant / revoke checks');
