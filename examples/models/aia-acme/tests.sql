-- Authorization checks for the ACME model: appendix A.6's four is-authorized
-- calls, then the chapter-9 patterns (manager of owner, legal membership,
-- delegatable sharing, template link, overrides, the global device
-- constraint, and the fail-closed behaviour on missing context). Uses the
-- shared test helpers (tests/sql/tests_helpers.sql); run via tests/test.sh
-- after model.sql + seed.sql.

SELECT _test_reset();

DO $$
DECLARE
    managed   constant jsonb := '{"device": {"managed": true},  "time": {"hour": 14, "weekday": "Wednesday"}}';
    unmanaged constant jsonb := '{"device": {"managed": false}, "time": {"hour": 14, "weekday": "Wednesday"}}';
    late      constant jsonb := '{"device": {"managed": true},  "time": {"hour": 22, "weekday": "Wednesday"}}';
    weekend   constant jsonb := '{"device": {"managed": true},  "time": {"hour": 11, "weekday": "Saturday"}}';
    notime    constant jsonb := '{"device": {"managed": true}}';
    v jsonb; n int; r record;
BEGIN
    -- ── Appendix A.6: the book's own evaluations ────────────────────────────
    -- A.6.1 owner actions: alice owns q3-plan → every action (managed device)
    FOR r IN SELECT unnest(ARRAY['view', 'edit', 'share']) AS a LOOP
        PERFORM _test_assert('acme_A61_owner_' || r.a,
            authz.check_access_with_context('aia_acme', 'employee', 'alice', r.a, 'document', 'q3-plan', managed)::text, 'true');
    END LOOP;
    -- A.6.2 customer viewing: kate is in custco-readers; NO context needed (the
    -- device forbid scopes employees only)
    PERFORM _test_assert('acme_A62_customer_view_no_context',
        authz.check_access('aia_acme', 'customer', 'kate', 'view', 'document', 'q3-plan')::text, 'true');
    -- A.6.3 employee sharing: bob is a reader and q3-plan is delegatable
    PERFORM _test_assert('acme_A63_reader_shares_delegatable',
        authz.check_access_with_context('aia_acme', 'employee', 'bob', 'share', 'document', 'q3-plan', managed)::text, 'true');
    -- A.6.4 unmanaged device: the global forbid wins over the readers permit
    PERFORM _test_assert('acme_A64_unmanaged_denied',
        authz.check_access_with_context('aia_acme', 'employee', 'bob', 'view', 'document', 'q3-plan', unmanaged)::text, 'false');

    -- ── Chapter 9 patterns ──────────────────────────────────────────────────
    -- 9.3.1 readers team: bob views, but cannot edit (reader only)
    PERFORM _test_assert('acme_931_reader_views',
        authz.check_access_with_context('aia_acme', 'employee', 'bob', 'view', 'document', 'q3-plan', managed)::text, 'true');
    PERFORM _test_assert('acme_931_reader_cannot_edit',
        authz.check_access_with_context('aia_acme', 'employee', 'bob', 'edit', 'document', 'q3-plan', managed)::text, 'false');
    -- 9.3.3 manager of owner: carol manages alice → view + edit, but not share
    PERFORM _test_assert('acme_933_manager_views',
        authz.check_access_with_context('aia_acme', 'employee', 'carol', 'view', 'document', 'q3-plan', managed)::text, 'true');
    PERFORM _test_assert('acme_933_manager_edits',
        authz.check_access_with_context('aia_acme', 'employee', 'carol', 'edit', 'document', 'q3-plan', managed)::text, 'true');
    PERFORM _test_assert('acme_933_manager_cannot_share',
        authz.check_access_with_context('aia_acme', 'employee', 'carol', 'share', 'document', 'q3-plan', managed)::text, 'false');
    -- 9.5.2 membership: dan (team:legal) views/edits the Legal doc, not q3-plan
    PERFORM _test_assert('acme_952_legal_views_legal_doc',
        authz.check_access_with_context('aia_acme', 'employee', 'dan', 'view', 'document', 'nda-custco', managed)::text, 'true');
    PERFORM _test_assert('acme_952_legal_edits_legal_doc',
        authz.check_access_with_context('aia_acme', 'employee', 'dan', 'edit', 'document', 'nda-custco', managed)::text, 'true');
    PERFORM _test_assert('acme_952_legal_not_confidential',
        authz.check_access_with_context('aia_acme', 'employee', 'dan', 'view', 'document', 'q3-plan', managed)::text, 'false');
    -- 9.5.1 delegatable vs discretionary: a reader of a NON-delegatable doc cannot share
    PERFORM authz.write_tuple('aia_acme', 'employee', 'bob', 'employee_viewer', 'document', 'nda-custco');
    PERFORM _test_assert('acme_951_viewer_of_nondelegatable_cannot_share',
        authz.check_access_with_context('aia_acme', 'employee', 'bob', 'share', 'document', 'nda-custco', managed)::text, 'false');
    PERFORM authz.delete_tuple('aia_acme', 'employee', 'bob', 'employee_viewer', 'document', 'nda-custco');
    -- customers never edit or share (schema appliesTo: Employee only)
    PERFORM _test_assert('acme_customer_cannot_edit',
        authz.check_access_with_context('aia_acme', 'customer', 'kate', 'edit', 'document', 'q3-plan', managed)::text, 'false');
    PERFORM _test_assert('acme_customer_cannot_share',
        authz.check_access_with_context('aia_acme', 'customer', 'kate', 'share', 'document', 'q3-plan', managed)::text, 'false');
    -- a customer outside the readers team sees nothing
    PERFORM _test_assert('acme_customer_stranger_denied',
        authz.check_access('aia_acme', 'customer', 'mallory', 'view', 'document', 'q3-plan')::text, 'false');
    -- 9.7.1 template link: eve's direct grant views (device rule still applies)
    PERFORM _test_assert('acme_971_template_link_views',
        authz.check_access_with_context('aia_acme', 'employee', 'eve', 'view', 'document', 'q3-plan', managed)::text, 'true');
    PERFORM _test_assert('acme_971_template_link_unmanaged_denied',
        authz.check_access_with_context('aia_acme', 'employee', 'eve', 'view', 'document', 'q3-plan', unmanaged)::text, 'false');
    -- 9.7.2 overrides
    --   temporary editor (expires_at): frank edits now, and the grant carries an expiry
    PERFORM _test_assert('acme_972_temporary_editor',
        authz.check_access_with_context('aia_acme', 'employee', 'frank', 'edit', 'document', 'q3-plan', managed)::text, 'true');
    PERFORM _test_assert_true('acme_972_temporary_editor_expires',
        (SELECT t.expires_at IS NOT NULL FROM authz.tuples t
          WHERE t.store_id = authz._s('aia_acme') AND t.user_id = 'frank'
            AND t.relation = authz._r('aia_acme', 'editor') AND t.object_id = 'q3-plan'));
    --   restricted workspace: bob is on its readers team but only the owner views
    PERFORM _test_assert('acme_972_restricted_reader_denied',
        authz.check_access_with_context('aia_acme', 'employee', 'bob', 'view', 'document', 'legal-review', managed)::text, 'false');
    PERFORM _test_assert('acme_972_restricted_owner_views',
        authz.check_access_with_context('aia_acme', 'employee', 'dan', 'view', 'document', 'legal-review', managed)::text, 'true');
    --   share lock: even the owner cannot share board-deck, but still edits it
    PERFORM _test_assert('acme_972_share_locked_owner_denied',
        authz.check_access_with_context('aia_acme', 'employee', 'alice', 'share', 'document', 'board-deck', managed)::text, 'false');
    PERFORM _test_assert('acme_972_share_locked_owner_still_edits',
        authz.check_access_with_context('aia_acme', 'employee', 'alice', 'edit', 'document', 'board-deck', managed)::text, 'true');

    -- ── Off-hours tightening (§9.1): only the owner edits outside business hours ──
    PERFORM _test_assert('acme_91_owner_edits_late',
        authz.check_access_with_context('aia_acme', 'employee', 'alice', 'edit', 'document', 'q3-plan', late)::text, 'true');
    PERFORM _test_assert('acme_91_manager_cannot_edit_late',
        authz.check_access_with_context('aia_acme', 'employee', 'carol', 'edit', 'document', 'q3-plan', late)::text, 'false');
    PERFORM _test_assert('acme_91_manager_cannot_edit_weekend',
        authz.check_access_with_context('aia_acme', 'employee', 'carol', 'edit', 'document', 'q3-plan', weekend)::text, 'false');
    PERFORM _test_assert('acme_91_legal_cannot_edit_late',
        authz.check_access_with_context('aia_acme', 'employee', 'dan', 'edit', 'document', 'nda-custco', late)::text, 'false');
    PERFORM _test_assert('acme_91_temporary_editor_cannot_edit_late',
        authz.check_access_with_context('aia_acme', 'employee', 'frank', 'edit', 'document', 'q3-plan', late)::text, 'false');
    -- viewing and sharing are not tightened
    PERFORM _test_assert('acme_91_manager_still_views_late',
        authz.check_access_with_context('aia_acme', 'employee', 'carol', 'view', 'document', 'q3-plan', late)::text, 'true');
    PERFORM _test_assert('acme_91_reader_still_shares_late',
        authz.check_access_with_context('aia_acme', 'employee', 'bob', 'share', 'document', 'q3-plan', late)::text, 'true');
    -- no time in the context: the owner path needs none; a manager's edit is conditional on it
    PERFORM _test_assert('acme_91_owner_edits_without_time',
        authz.check_access_with_context('aia_acme', 'employee', 'alice', 'edit', 'document', 'q3-plan', notime)::text, 'true');
    v := authz.check_access_detailed('aia_acme', 'employee', 'carol', 'edit', 'document', 'q3-plan', notime);
    PERFORM _test_assert('acme_91_manager_without_time_is_conditional', v ->> 'state', 'conditional');
    PERFORM _test_assert_true('acme_91_manager_without_time_names_time',
        (v -> 'missing_context')::text LIKE '%time%', v::text);

    -- ── The global constraint and missing context (§9.6) ───────────────────
    -- No context at all: an employee is denied (fail-closed) and the detailed
    -- decision says WHY — conditional, missing the `device` key.
    PERFORM _test_assert('acme_96_no_context_denied',
        authz.check_access('aia_acme', 'employee', 'alice', 'view', 'document', 'q3-plan')::text, 'false');
    v := authz.check_access_detailed('aia_acme', 'employee', 'alice', 'view', 'document', 'q3-plan');
    PERFORM _test_assert('acme_96_no_context_is_conditional', v ->> 'state', 'conditional');
    PERFORM _test_assert_true('acme_96_no_context_names_device',
        (v -> 'missing_context')::text LIKE '%device%', v::text);
    -- explain names the device constraint on an unmanaged denial
    v := authz.explain_access('aia_acme', 'employee', 'bob', 'view', 'document', 'q3-plan', unmanaged);
    PERFORM _test_assert('acme_96_explain_denies', v -> 'decision' ->> 'allowed', 'false');
    PERFORM _test_assert_true('acme_96_explain_mentions_condition', v::text LIKE '%managed_device%', 'trace lacks managed_device');

    -- ── Enumeration honours the same rules ─────────────────────────────────
    -- bob (managed): q3-plan yes; legal-review subtracted by the override
    SELECT count(*) INTO n FROM authz.list_objects('aia_acme', 'employee', 'bob', 'view', 'document', managed) WHERE object_id = 'q3-plan';
    PERFORM _test_assert('acme_list_objects_bob_sees_q3', n::text, '1');
    SELECT count(*) INTO n FROM authz.list_objects('aia_acme', 'employee', 'bob', 'view', 'document', managed) WHERE object_id = 'legal-review';
    PERFORM _test_assert('acme_list_objects_bob_not_restricted', n::text, '0');
    -- bob (unmanaged): nothing
    SELECT count(*) INTO n FROM authz.list_objects('aia_acme', 'employee', 'bob', 'view', 'document', unmanaged);
    PERFORM _test_assert('acme_list_objects_unmanaged_empty', n::text, '0');
    -- who may view q3-plan? alice (owner), bob (reader), carol (manager), eve (link) — dan/frank not
    PERFORM _test_assert('acme_list_subjects_q3_employees',
        (SELECT string_agg(subject_id, ',' ORDER BY subject_id)
           FROM authz.list_subjects('aia_acme', 'employee', 'view', 'document', 'q3-plan', managed)), 'alice,bob,carol,eve');
    PERFORM _test_assert('acme_list_subjects_q3_customers',
        (SELECT string_agg(subject_id, ',' ORDER BY subject_id)
           FROM authz.list_subjects('aia_acme', 'customer', 'view', 'document', 'q3-plan')), 'jack,kate');
END;
$$;

SELECT _test_report('ACME model checks');
