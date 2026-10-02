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

DROP FUNCTION IF EXISTS _test_setup_grant();

SELECT _test_report('grant / revoke checks');
