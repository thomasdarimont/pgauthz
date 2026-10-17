-- Relation kinds (migration 0019): what a subject IS versus what it CAN DO.
-- The kind is a declaration; whether tuples may name a relation is decided by
-- its rules (a direct rule on the object type). A permission without a direct
-- rule refuses tuples; one with a direct rule (a directly granted capability,
-- `run: [agent]`) takes them. The kind travels with the model through the
-- registry and shows in describe_model.

SELECT _test_reset();

DO $$
BEGIN
    PERFORM authz.delete_store('test_kind', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
SELECT authz.create_store('test_kind');
SELECT authz.model_register_type('test_kind', 'user');
SELECT authz.model_register_type('test_kind', 'doc');
SELECT authz.model_register_relation('test_kind', 'viewer');
SELECT authz.model_register_relation('test_kind', 'editor', 'edits', '{"kind": "relation", "label": "Editor"}');
SELECT authz.model_register_relation('test_kind', 'can_read', NULL, '{"kind": "permission"}');
SELECT authz.model_register_relation('test_kind', 'can_write');
SELECT authz.model_register_relation('test_kind', 'can_download', NULL, '{"kind": "permission"}');  -- a directly granted capability
SELECT authz.model_add_rule('test_kind', 'doc', 'viewer', 'direct');
SELECT authz.model_add_rule('test_kind', 'doc', 'editor', 'direct');
SELECT authz.model_add_rule('test_kind', 'doc', 'can_read', 'computed', 'viewer');
SELECT authz.model_add_rule('test_kind', 'doc', 'can_read', 'computed', 'editor');
SELECT authz.model_add_rule('test_kind', 'doc', 'can_write', 'computed', 'editor');

DO $$
DECLARE
    v_err text;
    v_def jsonb;
    v_n   integer;
BEGIN
    -- declared and merged metadata
    PERFORM _test_assert('rk_01_declared_permission',
        (SELECT metadata->>'kind' FROM authz.relations r JOIN authz.stores s ON s.id=r.store_id WHERE s.name='test_kind' AND r.name='can_read'), 'permission');
    PERFORM _test_assert('rk_02_extra_keys_kept',
        (SELECT metadata->>'label' FROM authz.relations r JOIN authz.stores s ON s.id=r.store_id WHERE s.name='test_kind' AND r.name='editor'), 'Editor');
    PERFORM _test_assert('rk_03_default_is_relation',
        (SELECT COALESCE(metadata->>'kind','relation') FROM authz.relations r JOIN authz.stores s ON s.id=r.store_id WHERE s.name='test_kind' AND r.name='viewer'), 'relation');

    -- a derived-only permission takes no tuple
    BEGIN
        PERFORM authz.write_tuple('test_kind', 'user', 'alice', 'can_read', 'doc', 'd1');
        v_err := 'no error';
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rk_04_tuple_on_derived_permission_refused', v_err LIKE '%is a permission without a direct rule%', v_err);
    -- a permission with a direct rule is a directly granted capability: rule, restriction and tuple are fine
    PERFORM _test_assert_true('rk_05_direct_rule_on_permission_ok',
        authz.model_add_rule('test_kind', 'doc', 'can_download', 'direct') > 0, 'rule id');
    PERFORM _test_assert_true('rk_06_restriction_on_permission_ok',
        authz.model_add_type_restriction('test_kind', 'doc', 'can_download', 'user') > 0, 'restriction id');
    PERFORM _test_assert('rk_07_tuple_on_granted_permission_ok',
        authz.write_tuple('test_kind', 'user', 'alice', 'can_download', 'doc', 'd1')::text, 'true');
    PERFORM _test_assert('rk_07b_tuple_on_relation_ok',
        authz.write_tuple('test_kind', 'user', 'alice', 'viewer', 'doc', 'd1')::text, 'true');
    PERFORM _test_assert('rk_08_permission_resolves',
        authz.check_access('test_kind', 'user', 'alice', 'can_read', 'doc', 'd1')::text, 'true');

    -- the kind is a declaration: an assigned relation may be called a permission (and back)
    PERFORM _test_assert('rk_09_set_permission_on_assigned_ok',
        (authz.model_set_relation_metadata('test_kind', 'viewer', '{"kind": "permission"}'))->>'kind', 'permission');
    PERFORM authz.model_set_relation_metadata('test_kind', 'viewer', '{"kind": "relation"}');
    PERFORM _test_assert('rk_10_set_metadata_merges',
        (authz.model_set_relation_metadata('test_kind', 'editor', '{"docs_url": "https://x.test/editor", "label": null}'))::text,
        '{"kind": "relation", "docs_url": "https://x.test/editor"}');

    -- inference: can_write has rules but none direct → permission
    PERFORM _test_assert('rk_11_infer_reports',
        (SELECT string_agg(relation || '=' || inferred, ',' ORDER BY relation) FROM authz.infer_relation_kinds('test_kind')),
        'can_download=permission,can_read=permission,can_write=permission,editor=relation,viewer=relation');  -- can_download: declared, kept despite its direct rule
    SELECT count(*) INTO v_n FROM authz.infer_relation_kinds('test_kind', true) WHERE applied;
    PERFORM _test_assert('rk_12_infer_applies_only_undeclared', v_n::text, '1');  -- only can_write was undeclared (viewer was declared by rk_09; editor, can_read, can_download already were)
    PERFORM _test_assert('rk_13_inferred_permission',
        (SELECT metadata->>'kind' FROM authz.relations r JOIN authz.stores s ON s.id=r.store_id WHERE s.name='test_kind' AND r.name='can_write'), 'permission');

    -- export carries it; describe marks it; apply propagates it
    v_def := authz.export_model('test_kind');
    PERFORM _test_assert('rk_14_export_metadata',
        (SELECT x->'metadata'->>'kind' FROM jsonb_array_elements(v_def->'relations') x WHERE x->>'name' = 'can_write'), 'permission');
    PERFORM _test_assert_true('rk_15_describe_marks_permission',
        position('define can_read: viewer or editor  # permission' in authz.describe_model('test_kind')) > 0
        AND position('define viewer: [' in authz.describe_model('test_kind')) > 0, authz.describe_model('test_kind'));
    PERFORM authz.publish_model('test_kind_model', 'test_kind', 'kinds');
END $$;

DO $$
BEGIN
    PERFORM authz.delete_store('test_kind_copy', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
SELECT authz.create_store('test_kind_copy');
SELECT authz.apply_model('test_kind_copy', 'test_kind_model');
DO $$
DECLARE v_err text;
BEGIN
    PERFORM _test_assert('rk_16_apply_propagates_kind',
        (SELECT metadata->>'kind' FROM authz.relations r JOIN authz.stores s ON s.id=r.store_id WHERE s.name='test_kind_copy' AND r.name='can_read'), 'permission');
    BEGIN
        PERFORM authz.write_tuple('test_kind_copy', 'user', 'bob', 'can_read', 'doc', 'd1');
        v_err := 'no error';
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rk_17_guard_after_apply', v_err LIKE '%is a permission without a direct rule%', v_err);
    PERFORM _test_assert('rk_17b_granted_permission_after_apply',
        authz.write_tuple('test_kind_copy', 'user', 'bob', 'can_download', 'doc', 'd1')::text, 'true');
    -- the plan reports a metadata change as an update of the relation
    PERFORM authz.model_set_relation_metadata('test_kind_copy', 'editor', '{"label": "Changed"}');
    PERFORM _test_assert('rk_18_plan_reports_metadata_update',
        (authz.plan_model_apply('test_kind_copy', 'test_kind_model')->'changes'->'relations'->'update')::text, '["editor"]');

    -- ui_order is a number for tools to sort by; anything else is refused
    PERFORM _test_assert('rk_19_ui_order_set',
        (authz.model_set_relation_metadata('test_kind_copy', 'can_read', '{"ui_order": 10}'))->>'ui_order', '10');
    BEGIN
        PERFORM authz.model_set_relation_metadata('test_kind_copy', 'can_read', '{"ui_order": "first"}');
        v_err := 'no error';
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rk_20_ui_order_must_be_number', v_err LIKE '%invalid relation ui_order%', v_err);
END $$;

SELECT _test_report('relation kinds');
