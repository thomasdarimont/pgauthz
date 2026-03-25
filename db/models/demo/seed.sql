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

    -- Upload request
    PERFORM authz.write_tuple('demo', 'client_data_space', 'eng_42_client', 'in_client_space',  'upload_request', 'req_2026_001');
    PERFORM authz.write_tuple('demo', 'client_org',        'acme',          'requested_from',   'upload_request', 'req_2026_001', 'member');
    PERFORM authz.write_tuple('demo', 'internal_user',     'bob',           'created_by',       'upload_request', 'req_2026_001');
END;
$$;
