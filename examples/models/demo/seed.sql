-- Sample relationship tuples using explicit write_tuple() parameters.

DO $$
BEGIN
    -- Teams
    PERFORM authz.write_tuple('demo', 'internal_user', 'alice', 'member', 'team', 'payroll_team');
    PERFORM authz.write_tuple('demo', 'internal_user', 'eva',   'member', 'team', 'accounting_team');
    PERFORM authz.write_tuple('demo', 'internal_user', 'frank', 'member', 'team', 'tax_team');

    -- Client org
    PERFORM authz.write_tuple('demo', 'client_user', 'carol', 'member', 'client_org', 'acme');
    PERFORM authz.write_tuple('demo', 'client_user', 'dave',  'member', 'client_org', 'acme');

    -- Engagement
    PERFORM authz.write_tuple('demo', 'internal_user', 'bob',   'advisor',   'engagement', 'eng_42');
    PERFORM authz.write_tuple('demo', 'internal_user', 'julia', 'assistant', 'engagement', 'eng_42');
    PERFORM authz.write_tuple('demo', 'client_org',    'acme',  'client',    'engagement', 'eng_42');

    -- Assignments (linked to engagement)
    PERFORM authz.write_tuple('demo', 'engagement', 'eng_42', 'parent_engagement', 'assignment', 'eng_42_payroll');
    PERFORM authz.write_tuple('demo', 'engagement', 'eng_42', 'parent_engagement', 'assignment', 'eng_42_accounting');
    PERFORM authz.write_tuple('demo', 'engagement', 'eng_42', 'parent_engagement', 'assignment', 'eng_42_tax');

    -- Assignment roles (via team usersets)
    PERFORM authz.write_tuple('demo', 'team', 'payroll_team',    'payroll_clerk', 'assignment', 'eng_42_payroll',    'member');
    PERFORM authz.write_tuple('demo', 'team', 'accounting_team', 'accountant',    'assignment', 'eng_42_accounting', 'member');
    PERFORM authz.write_tuple('demo', 'team', 'tax_team',        'tax_clerk',     'assignment', 'eng_42_tax',        'member');

    -- Internal data spaces (dual parent links — see setup invariant in model.fga)
    PERFORM authz.write_tuple('demo', 'assignment',  'eng_42_payroll',    'parent_assignment', 'internal_data_space', 'eng_42_payroll_internal');
    PERFORM authz.write_tuple('demo', 'assignment',  'eng_42_accounting', 'parent_assignment', 'internal_data_space', 'eng_42_accounting_internal');
    PERFORM authz.write_tuple('demo', 'assignment',  'eng_42_tax',        'parent_assignment', 'internal_data_space', 'eng_42_tax_internal');
    PERFORM authz.write_tuple('demo', 'engagement',  'eng_42',            'parent_engagement', 'internal_data_space', 'eng_42_payroll_internal');
    PERFORM authz.write_tuple('demo', 'engagement',  'eng_42',            'parent_engagement', 'internal_data_space', 'eng_42_accounting_internal');
    PERFORM authz.write_tuple('demo', 'engagement',  'eng_42',            'parent_engagement', 'internal_data_space', 'eng_42_tax_internal');

    -- Client data space
    PERFORM authz.write_tuple('demo', 'engagement',    'eng_42', 'parent_engagement',       'client_data_space', 'eng_42_client');
    PERFORM authz.write_tuple('demo', 'client_org',    'acme',   'client_org',              'client_data_space', 'eng_42_client');
    PERFORM authz.write_tuple('demo', 'internal_user', 'julia',  'direct_internal_manager', 'client_data_space', 'eng_42_client');

    -- Documents in internal spaces
    PERFORM authz.write_tuple('demo', 'internal_data_space', 'eng_42_payroll_internal',    'in_internal_space', 'document', 'doc_payroll_001');
    PERFORM authz.write_tuple('demo', 'internal_data_space', 'eng_42_accounting_internal', 'in_internal_space', 'document', 'doc_acc_001');
    PERFORM authz.write_tuple('demo', 'internal_data_space', 'eng_42_tax_internal',        'in_internal_space', 'document', 'doc_tax_001');

    -- Documents in client space
    PERFORM authz.write_tuple('demo', 'client_data_space', 'eng_42_client', 'in_client_space', 'document', 'doc_client_001');
    PERFORM authz.write_tuple('demo', 'client_data_space', 'eng_42_client', 'in_client_space', 'document', 'doc_client_002');

    -- Explicit per-document exception
    PERFORM authz.write_tuple('demo', 'client_user', 'carol', 'viewer', 'document', 'doc_client_private_001');

    -- Compliance auditor: one privileged (object wildcard) tuple grants
    -- viewer — and thereby can_read — on EVERY document, including ones
    -- created later. Requires allow_object_wildcard on the viewer rule.
    PERFORM authz.write_tuple('demo', 'internal_user', 'nadia_auditor', 'viewer', 'document', '*');

    -- App-as-a-service: the document service (Keycloak client "app-dms", accessed
    -- via client_credentials) reads every document. Its subject is the service
    -- account; subject_type=service_account and db_role=app_dms are hardcoded on
    -- the client (see keycloak/terraform/client.app-dms.tf).
    PERFORM authz.write_tuple('demo', 'service_account', 'service-account-app-dms', 'viewer', 'document', '*');

    -- Upload request
    PERFORM authz.write_tuple('demo', 'client_data_space', 'eng_42_client', 'in_client_space',  'upload_request', 'req_2026_001');
    PERFORM authz.write_tuple('demo', 'client_org',        'acme',          'requested_from',   'upload_request', 'req_2026_001', 'member');
    PERFORM authz.write_tuple('demo', 'internal_user',     'bob',           'created_by',       'upload_request', 'req_2026_001');

    -- Folders (nested containers). A grant on a folder inherits DOWN through its
    -- subfolders and to the documents inside them. Structure:
    --   workpapers (bob = owner)
    --     ├─ wp_payroll        (team:payroll_team#member = viewer)
    --     │    └─ wp_payroll_q1
    --     │         └─ doc_folder_payroll_q1_001
    --     └─ wp_tax            (frank = editor)
    --          └─ doc_folder_tax_001
    PERFORM authz.write_tuple('demo', 'folder', 'workpapers',    'parent', 'folder', 'wp_payroll');
    PERFORM authz.write_tuple('demo', 'folder', 'wp_payroll',    'parent', 'folder', 'wp_payroll_q1');
    PERFORM authz.write_tuple('demo', 'folder', 'workpapers',    'parent', 'folder', 'wp_tax');
    PERFORM authz.write_tuple('demo', 'folder', 'wp_payroll_q1', 'parent_folder', 'document', 'doc_folder_payroll_q1_001');
    PERFORM authz.write_tuple('demo', 'folder', 'wp_tax',        'parent_folder', 'document', 'doc_folder_tax_001');

    -- Folder grants (inherit down the tree)
    PERFORM authz.write_tuple('demo', 'internal_user', 'bob',   'owner',  'folder', 'workpapers');                    -- owns the whole tree
    PERFORM authz.write_tuple('demo', 'team',          'payroll_team', 'viewer', 'folder', 'wp_payroll', 'member');  -- payroll team views the payroll subtree
    PERFORM authz.write_tuple('demo', 'internal_user', 'frank', 'editor', 'folder', 'wp_tax');                       -- frank edits (and may share) the tax subtree

    -- Conditional grant (ABAC): a time-boxed share. Bob may view this document
    -- only while the grant window is open — the check must supply a request
    -- context with `current_time`, and without it the condition fails closed.
    PERFORM authz.create_condition_sql('demo',
        'non_expired_grant',
        $cond$
            ($1->>'current_time')::timestamptz
            < ($2->>'grant_time')::timestamptz + ($2->>'grant_duration')::interval
        $cond$,
        '{"request": ["current_time"], "stored": ["grant_time", "grant_duration"]}'::jsonb
    );
    PERFORM authz.write_tuple('demo',
        'internal_user', 'bob', 'viewer', 'document', 'doc_timeboxed_001',
        p_condition => 'non_expired_grant',
        p_condition_context => '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb
    );
END;
$$;
