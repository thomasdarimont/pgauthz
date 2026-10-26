-- Issuer bindings (migration 0023, engine/issuers*.sql): set/replace/delete
-- with validation, the audit trail, the revision pgauthzd polls, and the
-- role tiers.
SELECT _test_reset();

DO $$
DECLARE
    v_rev0 bigint := authz.issuer_bindings_revision();
    v_rev  bigint;
    v_row  record;
    v_err  text;
BEGIN
    DELETE FROM authz.issuer_bindings WHERE issuer LIKE 'https://test-issuer%';

    -- ib_01: a binding is created and read back
    v_rev := authz.set_issuer_binding('https://test-issuer/a', ARRAY['docs', 'tenant-.*'], ARRAY['app_.*'],
                 '{"docs-service": "app_docs"}', '{"docs-service": ["docs", "tenant-.*"]}', true, 'the docs IdP', 'alice');
    SELECT * INTO v_row FROM authz.list_issuer_bindings() WHERE issuer = 'https://test-issuer/a';
    PERFORM _test_assert('ib_01_set_and_list', v_row.stores::text || '|' || v_row.updated_by || '|' || v_row.enabled::text, '{docs,tenant-.*}|alice|true');
    PERFORM _test_assert('ib_02_revision_bumped', (v_rev > v_rev0)::text, 'true');
    PERFORM _test_assert('ib_03_revision_function', (authz.issuer_bindings_revision() = v_rev)::text, 'true');

    -- ib_04: a PUT replaces the whole row and bumps again
    v_rev0 := v_rev;
    v_rev := authz.set_issuer_binding('https://test-issuer/a', ARRAY['docs'], '{}', '{}', '{}', false, NULL, 'bob');
    SELECT * INTO v_row FROM authz.list_issuer_bindings() WHERE issuer = 'https://test-issuer/a';
    PERFORM _test_assert('ib_04_replace', v_row.stores::text || '|' || v_row.db_roles::text || '|' || v_row.enabled::text || '|' || v_row.updated_by, '{docs}|{}|false|bob');
    -- the replace keeps who created the row and when; updated_* move
    PERFORM _test_assert('ib_04b_created_kept', v_row.created_by || '|' || (v_row.created_at <= v_row.updated_at)::text, 'alice|true');
    PERFORM _test_assert('ib_05_revision_bumped_again', (v_rev > v_rev0)::text, 'true');

    -- ib_06: the audit trail has both changes, newest first, with the actor
    PERFORM _test_assert('ib_06_audit',
        (SELECT string_agg(action || ':' || performed_by || ':' || enabled::text, ',' ORDER BY seq)
           FROM authz.list_issuer_bindings_audit('https://test-issuer/a')), 'INSERT:alice:true,UPDATE:bob:false');

    -- ib_06b: the history pages by seq (newest first, then below the last seen), and counts
    PERFORM _test_assert('ib_06b_audit_paged',
        (SELECT string_agg(action, ',' ORDER BY seq DESC) FROM authz.list_issuer_bindings_audit('https://test-issuer/a', 1))
        || '|' || (SELECT string_agg(action, ',') FROM authz.list_issuer_bindings_audit('https://test-issuer/a', 10,
                      (SELECT max(seq) FROM authz.list_issuer_bindings_audit('https://test-issuer/a', 1))))
        || '|' || authz.count_issuer_bindings_audit('https://test-issuer/a')::text,
        'UPDATE|INSERT|2');

    -- ib_07..10: validation
    BEGIN
        PERFORM authz.set_issuer_binding('https://test-issuer/b', ARRAY['tenant-('], '{}', '{}', '{}');
        v_err := 'no error';
    EXCEPTION WHEN OTHERS THEN v_err := 'error';
    END;
    PERFORM _test_assert('ib_07_invalid_store_pattern_refused', v_err, 'error');
    BEGIN
        PERFORM authz.set_issuer_binding('https://test-issuer/b', ARRAY['docs'], '{}', '{}', '{"svc": ["hr"]}');
        v_err := 'no error';
    EXCEPTION WHEN invalid_parameter_value THEN v_err := SQLERRM;
    END;
    PERFORM _test_assert('ib_08_pep_client_outside_stores_refused', (v_err LIKE '%not covered by the stores binding%')::text, 'true');
    BEGIN
        PERFORM authz.set_issuer_binding('https://test-issuer/b', ARRAY['docs', 'tenant-.*'], '{}', '{}', '{"svc": ["tenant-1", "docs"]}');
        v_err := 'no error';
    EXCEPTION WHEN OTHERS THEN v_err := 'error';
    END;
    PERFORM _test_assert('ib_09_pep_client_plain_name_covered_by_pattern', v_err, 'no error');
    BEGIN
        PERFORM authz.set_issuer_binding('https://test-issuer/b', '{}', '{}', '{"svc": 5}', '{}');
        v_err := 'no error';
    EXCEPTION WHEN invalid_parameter_value THEN v_err := 'error';
    END;
    PERFORM _test_assert('ib_10_client_db_roles_shape', v_err, 'error');
    BEGIN
        PERFORM authz.set_issuer_binding('   ', '{}');
        v_err := 'no error';
    EXCEPTION WHEN invalid_parameter_value THEN v_err := 'error';
    END;
    PERFORM _test_assert('ib_11_empty_issuer_refused', v_err, 'error');

    -- ib_12: delete falls back to the environment; recorded; bumps
    v_rev0 := authz.issuer_bindings_revision();
    PERFORM _test_assert('ib_12_delete', authz.delete_issuer_binding('https://test-issuer/a', 'carol')::text, 'true');
    PERFORM _test_assert('ib_13_delete_gone', (SELECT count(*) FROM authz.list_issuer_bindings() WHERE issuer = 'https://test-issuer/a')::text, '0');
    PERFORM _test_assert('ib_14_delete_audited', (SELECT action || ':' || performed_by FROM authz.list_issuer_bindings_audit('https://test-issuer/a', 1)), 'DELETE:carol');
    PERFORM _test_assert('ib_15_delete_bumps', (authz.issuer_bindings_revision() > v_rev0)::text, 'true');
    PERFORM _test_assert('ib_16_delete_missing_false', authz.delete_issuer_binding('https://test-issuer/none')::text, 'false');

    -- ib_17: tiers — readers poll, auditors read history, admins write
    PERFORM _test_assert('ib_17_role_tiers',
        has_function_privilege('authz_reader', 'authz.list_issuer_bindings()', 'EXECUTE')::text || ','
        || has_function_privilege('authz_reader', 'authz.issuer_bindings_revision()', 'EXECUTE')::text || ','
        || has_function_privilege('authz_reader', 'authz.set_issuer_binding(text, text[], text[], jsonb, jsonb, boolean, text, text, text, text, text, text[], jsonb)', 'EXECUTE')::text || ','
        || has_function_privilege('authz_admin', 'authz.set_issuer_binding(text, text[], text[], jsonb, jsonb, boolean, text, text, text, text, text, text[], jsonb)', 'EXECUTE')::text || ','
        || has_function_privilege('authz_auditor', 'authz.list_issuer_bindings_audit(text, int, bigint)', 'EXECUTE')::text,
        'true,true,false,true,true');

    DELETE FROM authz.issuer_bindings WHERE issuer LIKE 'https://test-issuer%';
    DELETE FROM authz.issuer_bindings_audit WHERE issuer LIKE 'https://test-issuer%';
END;
$$;

-- Group issuers (ADR 0017, migration 0029): a row names a group instead of
-- patterns and carries its own anchor; its stores are the group's members
-- as they are now; the validation; a group with issuers is not deleted.
DO $$
DECLARE v_err text; v_row record; v_rev0 bigint; v_rev bigint;
BEGIN
    DELETE FROM authz.issuer_bindings WHERE issuer LIKE 'https://test-group-issuer%';
    PERFORM authz.delete_store('gi_store', p_purge_audit => true) FROM (SELECT 1) x WHERE EXISTS (SELECT 1 FROM authz.stores WHERE name = 'gi_store');
    DELETE FROM authz.store_groups WHERE name = 'gi_tenant';
    PERFORM authz.create_store_group('gi_tenant', 'group issuer test');
    PERFORM authz.create_store('gi_store');

    -- a group issuer with its anchor; the listing resolves the group's stores (none yet)
    PERFORM authz.set_issuer_binding('https://test-group-issuer/a', p_enabled => true, p_description => 'tenant idp', p_performed_by => 'user:tenant_admin',
        p_store_group => 'gi_tenant', p_jwks_url => 'https://idp.tenant/jwks', p_audience => 'authz-api', p_audiences => ARRAY['https://api.example'],
        p_admin => '[{"decide":{"store":"console"}},{"clients":["ci"],"decide":{"store":"console","subject_type":"service_account","subject_claim":"azp"}}]');
    SELECT * INTO v_row FROM authz.list_issuer_bindings() WHERE issuer = 'https://test-group-issuer/a';
    PERFORM _test_assert('gi_01_row', v_row.store_group || '|' || v_row.jwks_url || '|' || v_row.audience || '|' || v_row.audiences::text || '|' || v_row.stores::text || '|' || jsonb_array_length(v_row.admin)::text,
        'gi_tenant|https://idp.tenant/jwks|authz-api|{https://api.example}|{}|2');
    -- membership changes the reach and bumps the revision pgauthzd polls
    v_rev0 := authz.issuer_bindings_revision();
    PERFORM authz.set_store_group('gi_store', 'gi_tenant');
    SELECT * INTO v_row FROM authz.list_issuer_bindings() WHERE issuer = 'https://test-group-issuer/a';
    PERFORM _test_assert('gi_02_stores_follow_membership', v_row.stores::text, '{gi_store}');
    PERFORM _test_assert('gi_03_membership_bumps_revision', (authz.issuer_bindings_revision() > v_rev0)::text, 'true');
    -- the audit carries the anchor
    PERFORM _test_assert('gi_04_audit', (SELECT jwks_url || '|' || store_group FROM authz.issuer_bindings_audit WHERE issuer = 'https://test-group-issuer/a' ORDER BY seq DESC LIMIT 1), 'https://idp.tenant/jwks|gi_tenant');

    -- validation: patterns with a group, an anchor without a group, http, no audience, non-delegated admin rules, unknown group
    v_err := NULL; BEGIN PERFORM authz.set_issuer_binding('https://test-group-issuer/b', p_stores => ARRAY['x'], p_store_group => 'gi_tenant'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('gi_05_group_xor_patterns', v_err, 'a group issuer binds the group''s stores: stores must be empty when store_group is set');
    v_err := NULL; BEGIN PERFORM authz.set_issuer_binding('https://test-group-issuer/b', p_jwks_url => 'https://x/jwks', p_audience => 'a'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('gi_06_anchor_needs_group', (position('needs a store group' in v_err) > 0)::text, 'true');
    v_err := NULL; BEGIN PERFORM authz.set_issuer_binding('https://test-group-issuer/b', p_store_group => 'gi_tenant', p_jwks_url => 'http://x/jwks', p_audience => 'a'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('gi_07_https_only', v_err, 'jwks_url must be an https:// URL');
    v_err := NULL; BEGIN PERFORM authz.set_issuer_binding('https://test-group-issuer/b', p_store_group => 'gi_tenant', p_jwks_url => 'https://x/jwks'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('gi_08_anchor_needs_audience', (position('needs an audience' in v_err) > 0)::text, 'true');
    v_err := NULL; BEGIN PERFORM authz.set_issuer_binding('https://test-group-issuer/b', p_store_group => 'gi_tenant', p_admin => '[{"clients":["tf"],"scope":"platform"}]'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('gi_09_admin_delegates_only', (position('delegate only' in v_err) > 0)::text, 'true');
    v_err := NULL; BEGIN PERFORM authz.set_issuer_binding('https://test-group-issuer/b', p_store_group => 'gi_tenant', p_admin => '[{"decide":{"store":"console"},"capabilities":["test"]}]'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('gi_10_admin_no_caps', (position('no capabilities' in v_err) > 0)::text, 'true');
    v_err := NULL; BEGIN PERFORM authz.set_issuer_binding('https://test-group-issuer/b', p_store_group => 'gi_nope'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('gi_11_unknown_group', v_err, 'Unknown store group: gi_nope');
    -- a group with issuers is not deleted; without them it is
    PERFORM authz.set_store_group('gi_store', NULL);
    v_err := NULL; BEGIN PERFORM authz.delete_store_group('gi_tenant'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('gi_12_group_with_issuers_stays', v_err, 'store group gi_tenant still has 1 issuer(s): remove them first');
    PERFORM authz.delete_issuer_binding('https://test-group-issuer/a');
    PERFORM _test_assert('gi_13_group_deleted', authz.delete_store_group('gi_tenant')::text, 'true');
    PERFORM authz.delete_store('gi_store', p_purge_audit => true);
END;
$$;

SELECT _test_report('issuer bindings');
