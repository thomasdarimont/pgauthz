-- Console model checks: the capability matrix the console's BFF relies on.
-- Directory memberships arrive as contextual tuples (the console never writes
-- them), so the platform-admin cases below inject `user:X member
-- team:role_console_admin` the way the BFF does. Uses the shared helpers
-- (tests/sql/tests_helpers.sql); run via tests/test.sh after model.sql + seed.sql.

-- The store name is the psql variable :cs (default console): test.sh loads
-- this fixture as console_test so a test run never touches the console store
-- a running console uses.
\if :{?cs} \else \set cs console \endif
SELECT set_config('test.cs', :'cs', false);

SELECT _test_reset();

DO $$
DECLARE
    -- what the console derives from carol's token when she holds console_admin
    carol_admin jsonb := '[{"user_type":"user","user_id":"carol","relation":"member","object_type":"team","object_id":"role_console_admin"}]';
    dan_issuer_admin jsonb := '[{"user_type":"user","user_id":"dan","relation":"issuer_admin","object_type":"platform","object_id":"default"}]';
    -- bob's token carries the authz_writer realm role (keycloak/terraform/users.tf)
    bob_writer  jsonb := '[{"user_type":"user","user_id":"bob","relation":"member","object_type":"team","object_id":"role_authz_writer"}]';
BEGIN
    -- ── store:demo — explicit roles ─────────────────────────────────────────
    PERFORM _test_assert('cs_01_owner_can_view',          authz.check_access(current_setting('test.cs'),'user','alice','can_view',          'store','demo')::text, 'true');
    PERFORM _test_assert('cs_02_owner_can_edit_model',    authz.check_access(current_setting('test.cs'),'user','alice','can_edit_model',    'store','demo')::text, 'true');
    PERFORM _test_assert('cs_03_owner_can_publish',       authz.check_access(current_setting('test.cs'),'user','alice','can_publish',       'store','demo')::text, 'true');
    PERFORM _test_assert('cs_04_owner_can_grant',         authz.check_access(current_setting('test.cs'),'user','alice','can_grant',         'store','demo')::text, 'true');
    PERFORM _test_assert('cs_05_owner_can_manage_access', authz.check_access(current_setting('test.cs'),'user','alice','can_manage_access', 'store','demo')::text, 'true');
    PERFORM _test_assert('cs_06_tester_can_run_tests',    authz.check_access(current_setting('test.cs'),'user','bob',  'can_run_tests',     'store','demo')::text, 'true');
    PERFORM _test_assert('cs_07_tester_cannot_edit',      authz.check_access(current_setting('test.cs'),'user','bob',  'can_edit_model',    'store','demo')::text, 'false');
    PERFORM _test_assert('cs_08_tester_cannot_manage',    authz.check_access(current_setting('test.cs'),'user','bob',  'can_manage_access', 'store','demo')::text, 'false');
    PERFORM _test_assert('cs_09_viewer_can_view',         authz.check_access(current_setting('test.cs'),'user','carol','can_view',          'store','demo')::text, 'true');
    PERFORM _test_assert('cs_10_viewer_cannot_test',      authz.check_access(current_setting('test.cs'),'user','carol','can_run_tests',     'store','demo')::text, 'false');
    -- the test policy: a tester is limited to their own access, redacted trees, no enumeration, no history
    PERFORM _test_assert('cs_36_tester_not_others',       authz.check_access(current_setting('test.cs'),'user','bob',  'can_test_others',       'store','demo')::text, 'false');
    PERFORM _test_assert('cs_37_tester_not_full_explain', authz.check_access(current_setting('test.cs'),'user','bob',  'can_test_explain_full', 'store','demo')::text, 'false');
    PERFORM _test_assert('cs_38_tester_not_search',       authz.check_access(current_setting('test.cs'),'user','bob',  'can_test_search',       'store','demo')::text, 'false');
    PERFORM _test_assert('cs_39_tester_not_history',      authz.check_access(current_setting('test.cs'),'user','bob',  'can_test_history',      'store','demo')::text, 'false');
    PERFORM _test_assert('cs_40_owner_tests_others',      authz.check_access(current_setting('test.cs'),'user','alice','can_test_others',       'store','demo')::text, 'true');
    PERFORM _test_assert('cs_41_owner_search',            authz.check_access(current_setting('test.cs'),'user','alice','can_test_search',       'store','demo')::text, 'true');
    PERFORM _test_assert('cs_42_auditor_history',         authz.check_access(current_setting('test.cs'),'user','eva',  'can_test_history',      'store','demo')::text, 'true');
    PERFORM _test_assert('cs_43_author_full_explain',     authz.check_access(current_setting('test.cs'),'user','bob',  'can_test_explain_full', 'store','todo')::text, 'true');
    PERFORM _test_assert('cs_11_auditor_can_view_audit',  authz.check_access(current_setting('test.cs'),'user','eva',  'can_view_audit',    'store','demo')::text, 'true');
    PERFORM _test_assert('cs_12_auditor_can_view_decisions', authz.check_access(current_setting('test.cs'),'user','eva','can_view_decisions','store','demo')::text, 'true');
    PERFORM _test_assert('cs_13_auditor_cannot_grant',    authz.check_access(current_setting('test.cs'),'user','eva',  'can_grant',         'store','demo')::text, 'false');
    PERFORM _test_assert('cs_14_stranger_cannot_view',    authz.check_access(current_setting('test.cs'),'user','frank','can_view',          'store','demo')::text, 'false');

    -- ── store:todo — author vs publisher ────────────────────────────────────
    PERFORM _test_assert('cs_15_author_can_edit',         authz.check_access(current_setting('test.cs'),'user','bob',  'can_edit_model',    'store','todo')::text, 'true');
    PERFORM _test_assert('cs_16_author_can_test',         authz.check_access(current_setting('test.cs'),'user','bob',  'can_run_tests',     'store','todo')::text, 'true');
    PERFORM _test_assert('cs_17_author_cannot_publish',   authz.check_access(current_setting('test.cs'),'user','bob',  'can_publish',       'store','todo')::text, 'false');
    PERFORM _test_assert('cs_18_publisher_can_rollout',   authz.check_access(current_setting('test.cs'),'user','alice','can_rollout',       'store','todo')::text, 'true');

    -- ── team membership from the token (contextual tuples) ──────────────────
    PERFORM _test_assert('cs_19_team_sharer_via_token',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','bob','can_grant','store','gdrive', NULL, bob_writer)::text, 'true');
    PERFORM _test_assert('cs_20_team_sharer_needs_token',
        authz.check_access(current_setting('test.cs'),'user','bob','can_grant','store','gdrive')::text, 'false');

    -- ── issuer admin: the issuers' bindings, nothing else of the platform ──
    PERFORM _test_assert('cs_50_issuer_admin_manage_issuers',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','dan','can_manage_issuers','platform','default', NULL, dan_issuer_admin)::text, 'true');
    PERFORM _test_assert('cs_51_issuer_admin_no_health',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','dan','can_view_health','platform','default', NULL, dan_issuer_admin)::text, 'false');
    PERFORM _test_assert('cs_52_issuer_admin_no_manage_access',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','dan','can_manage_access','platform','default', NULL, dan_issuer_admin)::text, 'false');
    PERFORM _test_assert('cs_53_issuer_admin_no_store_view',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','dan','can_view','store','gdrive', NULL, dan_issuer_admin)::text, 'false');

    -- ── platform admin: sees every store and reassigns owners, nothing more ──
    PERFORM _test_assert('cs_21_platform_admin_manage_issuers',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','carol','can_manage_issuers','platform','default', NULL, carol_admin)::text, 'true');
    PERFORM _test_assert('cs_22_platform_admin_can_view_store',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','carol','can_view','store','gdrive', NULL, carol_admin)::text, 'true');
    PERFORM _test_assert('cs_23_platform_admin_can_manage_access',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','carol','can_manage_access','store','gdrive', NULL, carol_admin)::text, 'true');
    PERFORM _test_assert('cs_24_platform_admin_cannot_edit_model',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','carol','can_edit_model','store','gdrive', NULL, carol_admin)::text, 'false');
    PERFORM _test_assert('cs_25_platform_admin_cannot_grant',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','carol','can_grant','store','gdrive', NULL, carol_admin)::text, 'false');
    PERFORM _test_assert('cs_26_platform_admin_owns_console_store',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','carol','can_edit_model','store',current_setting('test.cs'), NULL, carol_admin)::text, 'true');
    PERFORM _test_assert('cs_27_platform_admin_registry_publish',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','carol','can_publish','registry','default', NULL, carol_admin)::text, 'true');
    PERFORM _test_assert('cs_28_no_admin_without_token',
        authz.check_access(current_setting('test.cs'),'user','carol','can_manage_issuers','platform','default')::text, 'false');

    -- ── publish / apply are attributed to the person (authz.performed_by) ──
    PERFORM set_config('authz.performed_by', 'user:alice', true);
    PERFORM authz.publish_model('console_access', current_setting('test.cs'), 'console model test');
    PERFORM authz.apply_model(current_setting('test.cs'), 'console_access');
    PERFORM _test_assert('cs_34_publish_created_by_person',
        (SELECT created_by FROM authz.list_model_versions('console_access') ORDER BY version DESC LIMIT 1), 'user:alice');
    PERFORM _test_assert('cs_35_apply_applied_by_person',
        (SELECT applied_by FROM authz.model_status(current_setting('test.cs'))), 'user:alice');
    PERFORM set_config('authz.performed_by', '', true);

    -- ── personas via realm-role teams (contextual tuples, as the console sends them) ──
    PERFORM _test_assert('cs_50_support_tests_others',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','support','can_test_others','store','demo', NULL,
            '[{"user_type":"user","user_id":"support","relation":"member","object_type":"team","object_id":"role_console_support"}]')::text, 'true');
    PERFORM _test_assert('cs_51_support_cannot_edit',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','support','can_edit_model','store','demo', NULL,
            '[{"user_type":"user","user_id":"support","relation":"member","object_type":"team","object_id":"role_console_support"}]')::text, 'false');
    PERFORM _test_assert('cs_52_app_dev_own_access_only',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','app-dev','can_test_others','store','demo', NULL,
            '[{"user_type":"user","user_id":"app-dev","relation":"member","object_type":"team","object_id":"role_console_app_dev"}]')::text, 'false');
    PERFORM _test_assert('cs_53_iam_dev_publishes',
        authz.check_access_with_contextual_tuples_jsonb(current_setting('test.cs'),'user','iam-dev','can_publish','registry','default', NULL,
            '[{"user_type":"user","user_id":"iam-dev","relation":"member","object_type":"team","object_id":"role_console_iam_dev"}]')::text, 'true');

    -- ── namespaces: an app team owns a slice of a shared store ──────────────
    PERFORM authz.write_tuple(current_setting('test.cs'), 'store', 'demo', 'store', 'namespace', 'demo/hr');
    PERFORM authz.write_tuple(current_setting('test.cs'), 'namespace', 'demo/hr', 'namespace', 'store', 'demo');
    PERFORM authz.write_tuple(current_setting('test.cs'), 'user', 'frank', 'author', 'namespace', 'demo/hr');
    PERFORM _test_assert('cs_44_ns_author_edits_namespace', authz.check_access(current_setting('test.cs'),'user','frank','can_edit_model','namespace','demo/hr')::text, 'true');
    PERFORM _test_assert('cs_45_ns_author_not_store',       authz.check_access(current_setting('test.cs'),'user','frank','can_edit_model','store','demo')::text, 'false');
    PERFORM _test_assert('cs_46_ns_author_opens_store',     authz.check_access(current_setting('test.cs'),'user','frank','can_view','store','demo')::text, 'true');
    PERFORM _test_assert('cs_47_ns_author_grants_in_ns',    authz.check_access(current_setting('test.cs'),'user','frank','can_grant','namespace','demo/hr')::text, 'true');
    PERFORM _test_assert('cs_48_store_owner_edits_ns',      authz.check_access(current_setting('test.cs'),'user','alice','can_edit_model','namespace','demo/hr')::text, 'true');
    PERFORM _test_assert('cs_49_other_ns_closed',           authz.check_access(current_setting('test.cs'),'user','frank','can_edit_model','namespace','demo/billing')::text, 'false');

    -- ── registry ────────────────────────────────────────────────────────────
    PERFORM _test_assert('cs_29_registry_viewer',         authz.check_access(current_setting('test.cs'),'user','bob',  'can_view',    'registry','default')::text, 'true');
    PERFORM _test_assert('cs_30_registry_viewer_no_publish', authz.check_access(current_setting('test.cs'),'user','bob','can_publish','registry','default')::text, 'false');
    PERFORM _test_assert('cs_31_registry_publisher',      authz.check_access(current_setting('test.cs'),'user','alice','can_publish', 'registry','default')::text, 'true');

    -- ── the stores a person can see (what the home screen lists) ────────────
    PERFORM _test_assert('cs_32_alice_visible_stores',
        (SELECT string_agg(object_id, ',' ORDER BY object_id) FROM authz.list_objects(current_setting('test.cs'),'user','alice','can_view','store')), 'demo,gdrive,todo');
    PERFORM _test_assert('cs_33_bob_visible_stores',
        (SELECT string_agg(object_id, ',' ORDER BY object_id) FROM authz.list_objects(current_setting('test.cs'),'user','bob','can_view','store')), 'demo,todo');
END;
$$;

SELECT _test_report('console model');
