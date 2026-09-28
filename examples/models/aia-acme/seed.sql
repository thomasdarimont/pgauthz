-- ============================================================================
-- ACME Customer Collaboration — Seed Data (appendix A.5 entities + extras)
-- ============================================================================
--
-- Appendix A.5 (verbatim from the book):
--   Employees: alice (Engineering, on call, manager carol), bob (Engineering,
--              manager carol, in team doc-q3-employee-readers), carol
--              (Engineering, no manager), dan (Legal, no manager)
--   Customers: kate, jack — CustCo, both in team custco-readers
--   Teams:     doc-q3-employee-readers ("Q3 Plan Employee Readers"),
--              custco-readers ("CustCo Readers")
--   Document:  q3-plan — owner alice, classification confidential,
--              delegatable, employee readers = doc-q3-employee-readers,
--              customer readers = custco-readers
--
-- Extras that exercise the chapter-9 patterns the appendix leaves out:
--   team:legal with dan as member, reviewer of classification:legal (§9.5.2)
--   document:nda-custco — owner carol, classification legal, not delegatable
--   document:legal-review — restricted workspace (§9.7.2 override), owner dan,
--     bob on its readers team (so the override has something to subtract)
--   document:board-deck — share_locked (§9.7.2), owner alice
--   eve — employee, direct-view template link on q3-plan (§9.7.1)
--   frank — contractor employee, temporary editor on q3-plan (§9.7.2), expires
--
-- The global constraint (§9.6) is ONE tuple: employee:* managed_device
-- document:* under the managed_device condition.

DO $$
BEGIN
    -- Employees: the management chain (subject = manager, object = report)
    PERFORM authz.write_tuple('aia_acme', 'employee', 'carol', 'manager', 'employee', 'alice');
    PERFORM authz.write_tuple('aia_acme', 'employee', 'carol', 'manager', 'employee', 'bob');

    -- Teams (Employee in [Team] / Customer in [Team])
    PERFORM authz.write_tuple('aia_acme', 'employee', 'bob',  'employee_member', 'team', 'doc-q3-employee-readers');
    PERFORM authz.write_tuple('aia_acme', 'employee', 'dan',  'employee_member', 'team', 'legal');
    PERFORM authz.write_tuple('aia_acme', 'customer', 'kate', 'customer_member', 'team', 'custco-readers');
    PERFORM authz.write_tuple('aia_acme', 'customer', 'jack', 'customer_member', 'team', 'custco-readers');

    -- Classification "Legal" is reviewed by the legal team (§9.5.2): one tuple
    -- covers every document classified legal, now and later.
    PERFORM authz.write_tuple('aia_acme', 'team', 'legal', 'reviewer', 'classification', 'legal', p_user_relation => 'employee_member');

    -- document:q3-plan (appendix A.5.4)
    PERFORM authz.write_tuple('aia_acme', 'employee', 'alice', 'owner', 'document', 'q3-plan');
    PERFORM authz.write_tuple('aia_acme', 'classification', 'confidential', 'classification', 'document', 'q3-plan');
    PERFORM authz.write_tuple('aia_acme', 'employee', '*', 'delegatable', 'document', 'q3-plan');   -- delegatable: true
    PERFORM authz.write_tuple('aia_acme', 'team', 'doc-q3-employee-readers', 'employee_readers', 'document', 'q3-plan', p_user_relation => 'employee_member');
    PERFORM authz.write_tuple('aia_acme', 'team', 'custco-readers', 'customer_readers', 'document', 'q3-plan', p_user_relation => 'customer_member');
    -- §9.7.1 template link "eve-view-q3-plan": direct per-principal grant
    PERFORM authz.write_tuple('aia_acme', 'employee', 'eve', 'employee_viewer', 'document', 'q3-plan');
    -- §9.7.2 override: contractor frank may edit for a week (server-time expiry)
    PERFORM authz.write_tuple('aia_acme', 'employee', 'frank', 'editor', 'document', 'q3-plan',
        p_expires_at => now() + interval '7 days');

    -- document:nda-custco — a Legal document (§9.5.2 membership permission)
    PERFORM authz.write_tuple('aia_acme', 'employee', 'carol', 'owner', 'document', 'nda-custco');
    PERFORM authz.write_tuple('aia_acme', 'classification', 'legal', 'classification', 'document', 'nda-custco');

    -- document:legal-review — the restricted workspace override (§9.7.2):
    -- readers exist, but only the owner may view.
    PERFORM authz.write_tuple('aia_acme', 'employee', 'dan', 'owner', 'document', 'legal-review');
    PERFORM authz.write_tuple('aia_acme', 'team', 'doc-q3-employee-readers', 'employee_readers', 'document', 'legal-review', p_user_relation => 'employee_member');
    PERFORM authz.write_tuple('aia_acme', 'employee', '*', 'restricted', 'document', 'legal-review');

    -- document:board-deck — sharing locked for everyone, owner included (§9.7.2)
    PERFORM authz.write_tuple('aia_acme', 'employee', 'alice', 'owner', 'document', 'board-deck');
    PERFORM authz.write_tuple('aia_acme', 'employee', '*', 'delegatable', 'document', 'board-deck');
    PERFORM authz.write_tuple('aia_acme', 'employee', '*', 'share_locked', 'document', 'board-deck');

    -- The global constraint (§9.6 / A.4.4), once for every document:
    -- an employee reaches ANY document only from a managed device.
    PERFORM authz.write_tuple('aia_acme', 'employee', '*', 'managed_device', 'document', '*',
        p_condition => 'managed_device');
    -- ... and non-owners edit only during business hours (§9.1).
    PERFORM authz.write_tuple('aia_acme', 'employee', '*', 'business_hours', 'document', '*',
        p_condition => 'business_hours');
END;
$$;
