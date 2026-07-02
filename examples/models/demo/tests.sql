-- Authorization checks — same test cases as checks.json for the OpenFGA setup.
-- Runs each check and compares against expected result.

DO $$
DECLARE
    pass_count int := 0;
    fail_count int := 0;
    total      int := 0;
    result     boolean;
    rec        record;
BEGIN
    CREATE TEMP TABLE test_checks (
        id          serial,
        description text,
        user_type   text,
        user_id     text,
        relation    text,
        object_type text,
        object_id   text,
        expected    boolean
    );

    INSERT INTO test_checks (description, user_type, user_id, relation, object_type, object_id, expected) VALUES
    ('Alice (payroll_team) can read payroll doc',              'internal_user', 'alice', 'can_read',            'document',          'doc_payroll_001',         true),
    ('Alice can edit payroll doc',                             'internal_user', 'alice', 'can_edit',             'document',          'doc_payroll_001',         true),
    ('Alice cannot read tax doc (wrong team)',                 'internal_user', 'alice', 'can_read',             'document',          'doc_tax_001',             false),
    ('Carol (client org) can read client-space doc',           'client_user',   'carol', 'can_read',             'document',          'doc_client_001',          true),
    ('Carol cannot edit client-space doc',                     'client_user',   'carol', 'can_edit',             'document',          'doc_client_001',          false),
    ('Carol can submit the upload request',                    'client_user',   'carol', 'can_submit',           'upload_request',    'req_2026_001',            true),
    ('Bob (advisor) can manage access on engagement',          'internal_user', 'bob',   'can_manage_access',    'engagement',        'eng_42',                  true),
    ('Julia can manage sharing on client space',               'internal_user', 'julia', 'can_manage_sharing',   'client_data_space', 'eng_42_client',           true),
    ('Bob (advisor/collaborator) can read payroll doc',        'internal_user', 'bob',   'can_read',             'document',          'doc_payroll_001',         true),
    ('Bob (advisor) can edit payroll doc',                     'internal_user', 'bob',   'can_edit',             'document',          'doc_payroll_001',         true),
    ('Julia (assistant/collaborator) can read payroll doc',    'internal_user', 'julia', 'can_read',             'document',          'doc_payroll_001',         true),
    ('Julia (assistant, not advisor) cannot edit payroll doc', 'internal_user', 'julia', 'can_edit',             'document',          'doc_payroll_001',         false),
    ('Eva (accounting_team) can read accounting doc',          'internal_user', 'eva',   'can_read',             'document',          'doc_acc_001',             true),
    ('Eva cannot read payroll doc',                            'internal_user', 'eva',   'can_read',             'document',          'doc_payroll_001',         false),
    ('Frank (tax_team) can edit tax doc',                      'internal_user', 'frank', 'can_edit',             'document',          'doc_tax_001',             true),
    ('Dave (client org) can read client-space doc',            'client_user',   'dave',  'can_read',             'document',          'doc_client_001',          true),
    ('Dave cannot read private doc (only carol)',              'client_user',   'dave',  'can_read',             'document',          'doc_client_private_001',  false),
    ('Nadia (auditor, doc:*) can read payroll doc',            'internal_user', 'nadia_auditor', 'can_read',     'document',          'doc_payroll_001',         true),
    ('Nadia (auditor, doc:*) can read private client doc',     'internal_user', 'nadia_auditor', 'can_read',     'document',          'doc_client_private_001',  true),
    ('Nadia (auditor) cannot edit documents',                  'internal_user', 'nadia_auditor', 'can_edit',     'document',          'doc_payroll_001',         false),
    ('Carol can read private doc via viewer',         'client_user',   'carol', 'can_read',             'document',          'doc_client_private_001',  true),

    -- Folders: inheritance down the tree (workpapers → wp_payroll → wp_payroll_q1 → doc)
    ('Bob (folder owner) reads a doc 3 levels deep',            'internal_user', 'bob',   'can_read',          'document', 'doc_folder_payroll_q1_001', true),
    ('Bob (folder owner) edits a doc 3 levels deep',            'internal_user', 'bob',   'can_edit',          'document', 'doc_folder_payroll_q1_001', true),
    ('Bob (root owner) reads a doc in the tax subtree',         'internal_user', 'bob',   'can_read',          'document', 'doc_folder_tax_001',        true),
    ('Bob can share the root folder',                           'internal_user', 'bob',   'can_share',         'folder',   'workpapers',                true),
    ('Bob (owner) can manage access on a nested folder',        'internal_user', 'bob',   'can_manage_access', 'folder',   'wp_payroll_q1',             true),
    ('Alice (team viewer) reads the folder doc via inheritance','internal_user', 'alice', 'can_read',          'document', 'doc_folder_payroll_q1_001', true),
    ('Alice (folder viewer) cannot edit the folder doc',        'internal_user', 'alice', 'can_edit',          'document', 'doc_folder_payroll_q1_001', false),
    ('Alice (viewer) cannot share the folder',                  'internal_user', 'alice', 'can_share',         'folder',   'wp_payroll',                false),
    ('Alice cannot read a doc in the tax subtree',              'internal_user', 'alice', 'can_read',          'document', 'doc_folder_tax_001',        false),
    ('Frank (folder editor) edits the tax folder doc',          'internal_user', 'frank', 'can_edit',          'document', 'doc_folder_tax_001',        true),
    ('Frank (folder editor) can share the tax folder',          'internal_user', 'frank', 'can_share',         'folder',   'wp_tax',                    true),
    ('Frank (editor, not owner) cannot manage access',          'internal_user', 'frank', 'can_manage_access', 'folder',   'wp_tax',                    false),
    ('Eva (no folder grant) cannot read the folder doc',        'internal_user', 'eva',   'can_read',          'document', 'doc_folder_payroll_q1_001', false);

    FOR rec IN SELECT * FROM test_checks ORDER BY id LOOP
        total := total + 1;
        result := authz.check_access(
            'demo',
            rec.user_type, rec.user_id,
            rec.relation,
            rec.object_type, rec.object_id
        );

        IF result = rec.expected THEN
            pass_count := pass_count + 1;
            RAISE NOTICE '    PASS  %', rec.description;
        ELSE
            fail_count := fail_count + 1;
            RAISE NOTICE '    FAIL  %  (expected=%, got=%)', rec.description, rec.expected, result;
        END IF;
    END LOOP;

    RAISE NOTICE '';
    RAISE NOTICE '==> % passed, % failed (of % checks)', pass_count, fail_count, total;

    DROP TABLE test_checks;

    IF fail_count > 0 THEN
        RAISE EXCEPTION '% checks failed', fail_count;
    END IF;
END;
$$;
