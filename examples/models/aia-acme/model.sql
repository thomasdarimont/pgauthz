-- ============================================================================
-- ACME "Customer Collaboration" — the Cedar example from *Authorization in
-- Action* (Windley; chapter 9 + appendix A), re-modelled as a pgauthz store
-- ============================================================================
--
-- The book expresses ACME's rules as Cedar policies over an entity store that
-- is itself a relationship graph (§9.4). pgauthz IS that graph, so most of the
-- policy text becomes model rules and the data becomes tuples. What Cedar
-- keeps as entity ATTRIBUTES (owner, manager, readers teams, classification,
-- delegatable) becomes RELATIONS here; what Cedar keeps as request CONTEXT
-- (device posture) becomes a CONDITION on a wildcard tuple; Cedar's `forbid`
-- becomes an intersection (a required relation) rather than a subtraction —
-- see the notes on each rule and README.md in this directory for the
-- policy-by-policy table.
--
-- Cedar schema (chapter 9.2.1)              pgauthz model
-- ------------------------------------      -----------------------------------
-- entity Employee in [Team]                 type employee
--   manager: Employee                         define manager: [employee]
-- entity Customer in [Team]                 type customer
-- entity Team                               type team
--                                             define employee_member: [employee]
--                                             define customer_member: [customer]
-- entity Document                           type document
--   owner: Employee                           define owner: [employee]
--   employee_readers_team: Team               define employee_readers: [team#employee_member]
--   customer_readers_team: Team               define customer_readers: [team#customer_member]
--   classification: String                    define classification: [classification]
--   delegatable: Bool                         define delegatable: [employee:*]     (flag tuple)
-- context.device.managed: Bool              define managed_device: [employee:*]  (conditional
--                                                 object-wildcard tuple, condition managed_device)
-- context.time.{hour, weekday}              define business_hours: [employee:*]  (same idiom,
--                                                 condition business_hours; §9.1 "stricter outside
--                                                 business hours": only owners edit off-hours)
-- action doc:view / doc:edit / doc:share    define view / edit / share
--
-- OpenFGA-DSL rendering of the model (authz.describe_model('aia_acme')):
--
--   type employee
--     relations
--       define manager: [employee]                 # subject = the manager
--   type customer
--   type team
--     relations
--       define employee_member: [employee]
--       define customer_member: [customer]
--   type classification                            # e.g. classification:legal
--     relations
--       define reviewer: [team#employee_member]    # "team:legal reviews Legal docs"
--   type document
--     relations
--       define owner: [employee]
--       define employee_readers: [team#employee_member]
--       define customer_readers: [team#customer_member]
--       define employee_viewer: [employee]         # template: direct-view (9.7.1)
--       define customer_viewer: [customer]
--       define editor: [employee]                  # override: temporary edit rights (9.7.2)
--       define classification: [classification]
--       define delegatable: [employee:*]           # flag: the doc may be shared onward
--       define restricted: [employee:*]            # override: owner-only workspace (9.7.2)
--       define share_locked: [employee:*]          # override: no sharing at all (9.7.2)
--       define managed_device: [employee:*]        # global constraint (9.6): request context
--       define business_hours: [employee:*]        # global constraint (9.1): request context
--       define owner_manager: manager from owner
--       define reviewer: reviewer from classification
--       define employee_reach: owner_manager or employee_readers or reviewer or employee_viewer
--       define employee_can_view: owner or (employee_reach but not restricted)
--       define employee_can_edit: owner or owner_manager or reviewer or editor
--       define employee_can_share: owner or (delegatable and employee_readers)
--       define view:  customer_readers or customer_viewer or (employee_can_view and managed_device)
--       define edit:  (owner and managed_device) or (employee_can_edit and managed_device and business_hours)
--       define share: (employee_can_share and managed_device) but not share_locked

DO $$
BEGIN
    PERFORM authz.delete_store('aia_acme', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN
    NULL;  -- store did not exist yet
END $$;
SELECT authz.create_store('aia_acme', 'ACME Customer Collaboration (Authorization in Action, ch. 9)');

DO $$
BEGIN
    -- ── Types (Cedar entity types; classification is a reified attribute) ──
    PERFORM authz.model_register_type('aia_acme', 'employee');
    PERFORM authz.model_register_type('aia_acme', 'customer');
    PERFORM authz.model_register_type('aia_acme', 'team');
    PERFORM authz.model_register_type('aia_acme', 'classification');
    PERFORM authz.model_register_type('aia_acme', 'document');

    -- ── Relations (the store-wide vocabulary; Cedar attributes + actions) ──
    PERFORM authz.model_register_relation('aia_acme', 'manager',            'employee.manager: the subject is the manager of the object employee');
    PERFORM authz.model_register_relation('aia_acme', 'employee_member',    'Employee in [Team]');
    PERFORM authz.model_register_relation('aia_acme', 'customer_member',    'Customer in [Team]');
    PERFORM authz.model_register_relation('aia_acme', 'reviewer',           'a team that may view/edit every document of a classification (§9.5.2)');
    PERFORM authz.model_register_relation('aia_acme', 'owner',              'Document.owner');
    PERFORM authz.model_register_relation('aia_acme', 'employee_readers',   'Document.employee_readers_team (its members)');
    PERFORM authz.model_register_relation('aia_acme', 'customer_readers',   'Document.customer_readers_team (its members)');
    PERFORM authz.model_register_relation('aia_acme', 'employee_viewer',    'direct-view template link for an employee (§9.7.1)');
    PERFORM authz.model_register_relation('aia_acme', 'customer_viewer',    'direct-view template link for a customer (§9.7.1)');
    PERFORM authz.model_register_relation('aia_acme', 'editor',             'override: temporary editing rights, use expires_at (§9.7.2)');
    PERFORM authz.model_register_relation('aia_acme', 'classification',     'Document.classification, reified as an object');
    PERFORM authz.model_register_relation('aia_acme', 'delegatable',        'Document.delegatable = true (flag tuple employee:*)');
    PERFORM authz.model_register_relation('aia_acme', 'restricted',         'override: viewing limited to the owner (§9.7.2 legal-review workspace)');
    PERFORM authz.model_register_relation('aia_acme', 'share_locked',       'override: no sharing, even by the owner (§9.7.2)');
    PERFORM authz.model_register_relation('aia_acme', 'managed_device',     'global constraint: request context device.managed = true (§9.6)');
    PERFORM authz.model_register_relation('aia_acme', 'business_hours',     'global constraint: request context time is Mon-Fri 09-17 (§9.1: only owners edit off-hours)');
    PERFORM authz.model_register_relation('aia_acme', 'owner_manager',      'the manager of the document owner (§9.3.3)');
    PERFORM authz.model_register_relation('aia_acme', 'employee_reach',     'every non-owner way an employee reaches a document');
    PERFORM authz.model_register_relation('aia_acme', 'employee_can_view',  'employee view rights before the device constraint');
    PERFORM authz.model_register_relation('aia_acme', 'employee_can_edit',  'employee edit rights before the device constraint');
    PERFORM authz.model_register_relation('aia_acme', 'employee_can_share', 'employee share rights before the device constraint');
    PERFORM authz.model_register_relation('aia_acme', 'view',               'action doc:view');
    PERFORM authz.model_register_relation('aia_acme', 'edit',               'action doc:edit');
    PERFORM authz.model_register_relation('aia_acme', 'share',              'action doc:share');

    -- ── Type restrictions (Cedar's typed attributes / appliesTo) ──
    PERFORM authz.model_add_type_restriction('aia_acme', 'employee', 'manager', 'employee');
    PERFORM authz.model_add_type_restriction('aia_acme', 'team', 'employee_member', 'employee');
    PERFORM authz.model_add_type_restriction('aia_acme', 'team', 'customer_member', 'customer');
    PERFORM authz.model_add_type_restriction('aia_acme', 'classification', 'reviewer', 'team', p_allowed_user_relation => 'employee_member');
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'owner', 'employee');
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'employee_readers', 'team', p_allowed_user_relation => 'employee_member');
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'customer_readers', 'team', p_allowed_user_relation => 'customer_member');
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'employee_viewer', 'employee');
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'customer_viewer', 'customer');
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'editor', 'employee');
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'classification', 'classification');
    -- Flags and the device constraint are "any employee" wildcard tuples.
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'delegatable',    'employee', p_allow_wildcard => true);
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'restricted',     'employee', p_allow_wildcard => true);
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'share_locked',   'employee', p_allow_wildcard => true);
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'managed_device', 'employee', p_allow_wildcard => true);
    PERFORM authz.model_add_type_restriction('aia_acme', 'document', 'business_hours', 'employee', p_allow_wildcard => true);

    -- ── Direct relations (the edges the entity store holds) ──
    PERFORM authz.model_add_rule('aia_acme', 'employee', 'manager', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'team', 'employee_member', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'team', 'customer_member', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'classification', 'reviewer', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'owner', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_readers', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'customer_readers', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_viewer', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'customer_viewer', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'editor', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'classification', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'delegatable', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'restricted', 'direct');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'share_locked', 'direct');
    -- The global constraint is ONE tuple for every document (object wildcard,
    -- §"Object Wildcards"): employee:* managed_device document:* with the
    -- condition below. Opt the rule into object wildcards.
    PERFORM authz.model_add_rule('aia_acme', 'document', 'managed_device', 'direct', p_allow_object_wildcard => true);
    PERFORM authz.model_add_rule('aia_acme', 'document', 'business_hours', 'direct', p_allow_object_wildcard => true);

    -- ── Cedar: resource.owner.manager == principal  (§9.3.3, 9.5.3) ──
    -- Attribute traversal in Cedar; a tuple-to-userset hop here: follow the
    -- document's `owner` edge, then that employee's `manager`.
    PERFORM authz.model_add_rule('aia_acme', 'document', 'owner_manager', 'ttu',
        p_tupleset_relation => 'owner', p_tupleset_computed => 'manager');

    -- ── Cedar: principal in Team::"team:legal" && resource.classification == "Legal" (§9.5.2) ──
    -- The classification is an object; the legal team is its `reviewer` (one
    -- tuple); every document with that classification inherits via TTU.
    PERFORM authz.model_add_rule('aia_acme', 'document', 'reviewer', 'ttu',
        p_tupleset_relation => 'classification', p_tupleset_computed => 'reviewer');

    -- ── employee_reach: every non-owner path an employee has to a document ──
    -- principal in resource.employee_readers_team (§9.3.1) | manager of owner |
    -- legal reviewer (§9.5.2) | direct-view template link (§9.7.1)
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_reach', 'computed', p_computed_relation => 'owner_manager');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_reach', 'computed', p_computed_relation => 'employee_readers');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_reach', 'computed', p_computed_relation => 'reviewer');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_reach', 'computed', p_computed_relation => 'employee_viewer');

    -- ── employee_can_view: owner (§9.3.2) OR (employee_reach BUT NOT restricted) ──
    -- The §9.7.2 override "forbid view unless owner" for a workspace is the
    -- `restricted` flag: it subtracts every non-owner path, never the owner.
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_can_view', 'computed', p_computed_relation => 'owner');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_can_view', 'computed', p_computed_relation => 'employee_reach',
        p_group_id => 1, p_group_op => 'exclusion');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_can_view', 'computed', p_computed_relation => 'restricted',
        p_group_id => 1, p_group_op => 'exclusion', p_negated => true);

    -- ── employee_can_edit: owner OR manager of owner OR legal reviewer OR editor override (§9.3.2, 9.3.3, 9.5.4, 9.7.2) ──
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_can_edit', 'computed', p_computed_relation => 'owner');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_can_edit', 'computed', p_computed_relation => 'owner_manager');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_can_edit', 'computed', p_computed_relation => 'reviewer');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_can_edit', 'computed', p_computed_relation => 'editor');

    -- ── employee_can_share: owner OR (delegatable AND employee_readers) (§9.3.2, 9.5.1) ──
    -- "resource.delegatable == true && principal in resource.employee_readers_team"
    -- is an intersection of the flag tuple and the readers userset.
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_can_share', 'computed', p_computed_relation => 'owner');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_can_share', 'computed', p_computed_relation => 'delegatable',
        p_group_id => 1, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'employee_can_share', 'computed', p_computed_relation => 'employee_readers',
        p_group_id => 1, p_group_op => 'intersection');

    -- ── The actions, with the global constraint (§9.6) ──
    -- Cedar: forbid(principal is Employee, action, resource is Document)
    --        when { context.device.managed == false };
    -- A forbid that overrides every permit for employees = every employee path
    -- must ALSO satisfy managed_device (intersection). Customers are not in
    -- the forbid's scope, so their paths carry no device requirement.
    --
    -- Missing context: Cedar's forbid would error and be skipped (fail-OPEN
    -- unless the request is schema-validated); here the condition cannot hold,
    -- so employees are DENIED and check_access_detailed reports the decision
    -- as `conditional` with the missing key — fail-closed, and the PEP can see
    -- exactly which context it forgot to send.

    -- view: customer_readers OR customer_viewer OR (employee_can_view AND managed_device)
    PERFORM authz.model_add_rule('aia_acme', 'document', 'view', 'computed', p_computed_relation => 'customer_readers');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'view', 'computed', p_computed_relation => 'customer_viewer');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'view', 'computed', p_computed_relation => 'employee_can_view',
        p_group_id => 1, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'view', 'computed', p_computed_relation => 'managed_device',
        p_group_id => 1, p_group_op => 'intersection');

    -- edit: (owner AND managed_device) OR (employee_can_edit AND managed_device AND business_hours)
    -- §9.1's "stricter constraints outside business hours", pinned down as:
    -- off-hours, only the owner edits; managers, legal reviewers and temporary
    -- editors wait for Monday 09:00. Viewing and sharing are unchanged, so the
    -- appendix-A evaluations (which send no time context) still hold. A second
    -- conditional wildcard tuple carries the rule; groups are OR'd.
    PERFORM authz.model_add_rule('aia_acme', 'document', 'edit', 'computed', p_computed_relation => 'owner',
        p_group_id => 1, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'edit', 'computed', p_computed_relation => 'managed_device',
        p_group_id => 1, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'edit', 'computed', p_computed_relation => 'employee_can_edit',
        p_group_id => 2, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'edit', 'computed', p_computed_relation => 'managed_device',
        p_group_id => 2, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'edit', 'computed', p_computed_relation => 'business_hours',
        p_group_id => 2, p_group_op => 'intersection');

    -- share: (employee_can_share AND managed_device) BUT NOT share_locked
    -- (§9.7.2 override: a customer with stricter requirements forbids all
    -- sharing, even by owners — the flag subtracts from every path.)
    -- An exclusion group ANDs its base rules, so this is one group.
    PERFORM authz.model_add_rule('aia_acme', 'document', 'share', 'computed', p_computed_relation => 'employee_can_share',
        p_group_id => 1, p_group_op => 'exclusion');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'share', 'computed', p_computed_relation => 'managed_device',
        p_group_id => 1, p_group_op => 'exclusion');
    PERFORM authz.model_add_rule('aia_acme', 'document', 'share', 'computed', p_computed_relation => 'share_locked',
        p_group_id => 1, p_group_op => 'exclusion', p_negated => true);

    -- ── The global constraint's condition (Cedar: context.device.managed) ──
    -- Evaluated against the request context the PEP sends — the same shape as
    -- the book's request payload (§9.8): {"device": {"managed": true}, ...}.
    PERFORM authz.create_condition_sql('aia_acme', 'managed_device',
        $cond$ COALESCE(($1 #>> '{device,managed}')::boolean, false) $cond$,
        '{"request": ["device"]}'::jsonb);
    -- Business hours from the same request context: {"time": {"hour": 14, "weekday": "Wednesday"}}.
    -- The PEP supplies the time (a trust decision, see MODEL_DESIGN §8); absent
    -- time fails closed for the paths that need it.
    PERFORM authz.create_condition_sql('aia_acme', 'business_hours',
        $cond$ ($1 #>> '{time,hour}')::int BETWEEN 9 AND 17
               AND ($1 #>> '{time,weekday}') NOT IN ('Saturday', 'Sunday') $cond$,
        '{"request": ["time"]}'::jsonb);
END;
$$;
