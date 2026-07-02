-- Model definition: types, relations, partitions, and resolution rules.
-- Equivalent of model.fga encoded as data.

----------------------------------------------------------------------
-- Demo store.
-- Dropped first so this file is idempotent — re-running it (e.g.
-- test.sh standalone, without a preceding init.sh) resets the demo
-- store from scratch instead of failing on the existing store. The
-- audit history is purged since the demo store is a fixture, not
-- production data.
----------------------------------------------------------------------
DO $$
BEGIN
    PERFORM authz.delete_store('demo', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN
    NULL;  -- store did not exist yet
END $$;
SELECT authz.create_store('demo');

----------------------------------------------------------------------
-- Types, relations, partitions, and model rules.
-- Wrapped in a DO block so the store ID is resolved once.
----------------------------------------------------------------------
DO $$
DECLARE
    s smallint := authz._s('demo');

    -- Type shortcuts
    t_team              smallint;
    t_client_org        smallint;
    t_engagement        smallint;
    t_assignment        smallint;
    t_int_ds            smallint;  -- internal_data_space
    t_cli_ds            smallint;  -- client_data_space
    t_document          smallint;
    t_upload_req        smallint;  -- upload_request
    t_folder            smallint;

    -- Relation shortcuts
    r_member                      smallint;
    r_advisor                     smallint;
    r_assistant                   smallint;
    r_client                      smallint;
    r_internal_collaborator       smallint;
    r_can_view                    smallint;
    r_can_manage_access           smallint;
    r_can_manage_client_collab    smallint;  -- can_manage_client_collaboration
    r_parent_engagement           smallint;
    r_accountant                  smallint;
    r_payroll_clerk               smallint;
    r_tax_clerk                   smallint;
    r_can_edit                    smallint;
    r_can_approve                 smallint;
    r_parent_assignment           smallint;
    r_viewer                      smallint;
    r_editor                      smallint;
    r_client_org                  smallint;
    r_direct_client_user          smallint;
    r_direct_internal_manager     smallint;
    r_client_member               smallint;
    r_can_upload                  smallint;
    r_can_manage_sharing          smallint;
    r_in_internal_space           smallint;
    r_in_client_space             smallint;
    r_can_read                    smallint;
    r_can_share_with_client       smallint;
    r_can_delete                  smallint;
    r_requested_from              smallint;
    r_created_by                  smallint;
    r_can_submit                  smallint;
    r_can_manage                  smallint;
    r_parent                      smallint;
    r_owner                       smallint;
    r_parent_folder               smallint;
    r_can_share                   smallint;
BEGIN

    ----------------------------------------------------------------------
    -- Types (explicit IDs for partition definitions)
    ----------------------------------------------------------------------
    INSERT INTO authz.types (id, store_id, name, description) OVERRIDING SYSTEM VALUE VALUES
        (1,  s, 'internal_user',       'An internal staff member (accountant, clerk, advisor) working in the back office.'),
        (2,  s, 'client_user',         'An external customer user who collaborates via the front office.'),
        (3,  s, 'team',                'A group of internal users (payroll, tax, accounting) used to grant roles in bulk.'),
        (4,  s, 'client_org',          'A customer organization whose members are the client users on an engagement.'),
        (5,  s, 'engagement',          'A client engagement — the top-level unit of work linking an internal team to a customer org.'),
        (6,  s, 'assignment',          'A work assignment within an engagement (e.g. payroll, tax) that scopes internal roles.'),
        (7,  s, 'internal_data_space', 'An internal workspace holding the documents a team works on for an assignment.'),
        (8,  s, 'client_data_space',   'A shared space where documents are exchanged with the customer (front office).'),
        (9,  s, 'document',            'A file under access control; read/edit/share is governed by its spaces and engagement.'),
        (10, s, 'upload_request',      'A request asking a customer to upload a document into a client data space.'),
        (11, s, 'service_account',     'A non-human application identity (e.g. the app-dms client) acting via client_credentials.'),
        (12, s, 'folder',              'A nestable container for documents; permissions granted on a folder inherit to its subfolders and their documents.');

    PERFORM setval(pg_get_serial_sequence('authz.types', 'id'), max(id)) FROM authz.types;

    ----------------------------------------------------------------------
    -- Logical-grouping labels (advisory key:value; a type may carry several,
    -- including multiple values for one key). Used by tooling (e.g. the
    -- playground) to cluster/hide types by domain. No access-control meaning.
    --
    -- The demo models two use-cases of one domain: sharing data with an
    -- external customer (frontoffice) and working on the customer's documents
    -- internally (backoffice). Types that bridge both carry both scopes.
    ----------------------------------------------------------------------
    PERFORM authz.model_set_type_labels('demo', 'internal_user',       ARRAY['area:backoffice']);
    PERFORM authz.model_set_type_labels('demo', 'client_user',         ARRAY['area:frontoffice']);
    PERFORM authz.model_set_type_labels('demo', 'team',                ARRAY['area:backoffice']);
    PERFORM authz.model_set_type_labels('demo', 'client_org',          ARRAY['area:frontoffice','area:backoffice']);
    PERFORM authz.model_set_type_labels('demo', 'engagement',          ARRAY['area:frontoffice','area:backoffice']);
    PERFORM authz.model_set_type_labels('demo', 'assignment',          ARRAY['area:backoffice']);
    PERFORM authz.model_set_type_labels('demo', 'internal_data_space', ARRAY['area:backoffice']);
    PERFORM authz.model_set_type_labels('demo', 'client_data_space',   ARRAY['area:frontoffice']);
    PERFORM authz.model_set_type_labels('demo', 'document',            ARRAY['area:frontoffice','area:backoffice']);
    PERFORM authz.model_set_type_labels('demo', 'upload_request',      ARRAY['area:frontoffice','area:backoffice']);
    PERFORM authz.model_set_type_labels('demo', 'service_account',     ARRAY['area:backoffice']);
    PERFORM authz.model_set_type_labels('demo', 'folder',              ARRAY['area:backoffice']);

    ----------------------------------------------------------------------
    -- Namespace assignments (optional).
    -- Types with a namespace are restricted: only DB roles listed in
    -- authz.namespace_access (with the appropriate can_read/can_write flag)
    -- can read or write tuples for that type.
    -- Types with namespace = NULL remain unrestricted.
    --
    -- Example: assign namespaces per domain, then grant roles per app:
    --   UPDATE authz.types SET namespace = 'hr'       WHERE store_id = s AND name IN ('engagement', 'assignment');
    --   UPDATE authz.types SET namespace = 'documents' WHERE store_id = s AND name IN ('document', 'upload_request');
    --   INSERT INTO authz.namespace_access VALUES (s, 'hr', 'app_hr', true, true);
    --   INSERT INTO authz.namespace_access VALUES (s, 'documents', 'app_dms', true, true);
    ----------------------------------------------------------------------

    ----------------------------------------------------------------------
    -- Create partitions for each object type.
    -- Each partition holds tuples where this type is the object.
    -- (internal_user and client_user are user-only types, rarely objects,
    -- so they stay in tuples_default)
    ----------------------------------------------------------------------
    PERFORM authz._ensure_tuple_partition(s, 'team');
    PERFORM authz._ensure_tuple_partition(s, 'client_org');
    PERFORM authz._ensure_tuple_partition(s, 'engagement');
    PERFORM authz._ensure_tuple_partition(s, 'assignment');
    PERFORM authz._ensure_tuple_partition(s, 'internal_data_space');
    PERFORM authz._ensure_tuple_partition(s, 'client_data_space');
    PERFORM authz._ensure_tuple_partition(s, 'upload_request');
    PERFORM authz._ensure_tuple_partition(s, 'folder');

    -- High-volume types get hash sub-partitioning on object_id.
    -- This splits the partition into smaller physical tables, reducing
    -- index size and lock contention under concurrent writes.
    -- Modulus 8 is a good starting point for millions of objects.
    PERFORM authz._ensure_tuple_partition(s, 'document', 8);

    ----------------------------------------------------------------------
    -- Relations
    ----------------------------------------------------------------------
    INSERT INTO authz.relations (id, store_id, name) OVERRIDING SYSTEM VALUE VALUES
        (1,  s, 'member'),
        (2,  s, 'advisor'),
        (3,  s, 'assistant'),
        (4,  s, 'client'),
        (5,  s, 'internal_collaborator'),
        (6,  s, 'can_view'),
        (7,  s, 'can_manage_access'),
        (8,  s, 'can_manage_client_collaboration'),
        (9,  s, 'parent_engagement'),
        (10, s, 'accountant'),
        (11, s, 'payroll_clerk'),
        (12, s, 'tax_clerk'),
        (13, s, 'can_edit'),
        (14, s, 'can_approve'),
        (15, s, 'parent_assignment'),
        (16, s, 'viewer'),
        (17, s, 'editor'),
        (18, s, 'client_org'),
        (19, s, 'direct_client_user'),
        (20, s, 'direct_internal_manager'),
        (21, s, 'client_member'),
        (22, s, 'can_upload'),
        (23, s, 'can_manage_sharing'),
        (24, s, 'in_internal_space'),
        (25, s, 'in_client_space'),
        (26, s, 'can_read'),
        (27, s, 'can_share_with_client'),
        (28, s, 'can_delete'),
        (29, s, 'requested_from'),
        (30, s, 'created_by'),
        (31, s, 'can_submit'),
        (32, s, 'can_manage'),
        (33, s, 'parent'),          -- folder nesting (folder → folder)
        (34, s, 'owner'),           -- folder owner (full control)
        (35, s, 'parent_folder'),   -- document → containing folder
        (36, s, 'can_share');       -- may grant others access to a folder

    PERFORM setval(pg_get_serial_sequence('authz.relations', 'id'), max(id)) FROM authz.relations;

    -- Resolve type/relation IDs into variables for readability.
    t_team       := authz._t(s, 'team');
    t_client_org := authz._t(s, 'client_org');
    t_engagement := authz._t(s, 'engagement');
    t_assignment := authz._t(s, 'assignment');
    t_int_ds     := authz._t(s, 'internal_data_space');
    t_cli_ds     := authz._t(s, 'client_data_space');
    t_document   := authz._t(s, 'document');
    t_upload_req := authz._t(s, 'upload_request');
    t_folder     := authz._t(s, 'folder');

    r_member                   := authz._r(s, 'member');
    r_advisor                  := authz._r(s, 'advisor');
    r_assistant                := authz._r(s, 'assistant');
    r_client                   := authz._r(s, 'client');
    r_internal_collaborator    := authz._r(s, 'internal_collaborator');
    r_can_view                 := authz._r(s, 'can_view');
    r_can_manage_access        := authz._r(s, 'can_manage_access');
    r_can_manage_client_collab := authz._r(s, 'can_manage_client_collaboration');
    r_parent_engagement        := authz._r(s, 'parent_engagement');
    r_accountant               := authz._r(s, 'accountant');
    r_payroll_clerk            := authz._r(s, 'payroll_clerk');
    r_tax_clerk                := authz._r(s, 'tax_clerk');
    r_can_edit                 := authz._r(s, 'can_edit');
    r_can_approve              := authz._r(s, 'can_approve');
    r_parent_assignment        := authz._r(s, 'parent_assignment');
    r_viewer            := authz._r(s, 'viewer');
    r_editor            := authz._r(s, 'editor');
    r_client_org               := authz._r(s, 'client_org');
    r_direct_client_user       := authz._r(s, 'direct_client_user');
    r_direct_internal_manager  := authz._r(s, 'direct_internal_manager');
    r_client_member            := authz._r(s, 'client_member');
    r_can_upload               := authz._r(s, 'can_upload');
    r_can_manage_sharing       := authz._r(s, 'can_manage_sharing');
    r_in_internal_space        := authz._r(s, 'in_internal_space');
    r_in_client_space          := authz._r(s, 'in_client_space');
    r_can_read                 := authz._r(s, 'can_read');
    r_can_share_with_client    := authz._r(s, 'can_share_with_client');
    r_can_delete               := authz._r(s, 'can_delete');
    r_requested_from           := authz._r(s, 'requested_from');
    r_created_by               := authz._r(s, 'created_by');
    r_can_submit               := authz._r(s, 'can_submit');
    r_can_manage               := authz._r(s, 'can_manage');
    r_parent                   := authz._r(s, 'parent');
    r_owner                    := authz._r(s, 'owner');
    r_parent_folder            := authz._r(s, 'parent_folder');
    r_can_share                := authz._r(s, 'can_share');

    ----------------------------------------------------------------------
    -- Model rules
    -- Helpers (_direct, _computed, _ttu) are defined in
    -- engine/core_internal.sql which is loaded before this file.
    ----------------------------------------------------------------------
    INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed) VALUES

    -- type team
    (s, t_team, r_member, authz._rel_direct(), NULL, NULL, NULL),

    -- type client_org
    (s, t_client_org, r_member, authz._rel_direct(), NULL, NULL, NULL),

    -- type engagement
    (s, t_engagement, r_advisor,                     authz._rel_direct(),   NULL, NULL, NULL),
    (s, t_engagement, r_assistant,                   authz._rel_direct(),   NULL, NULL, NULL),
    (s, t_engagement, r_client,                      authz._rel_direct(),   NULL, NULL, NULL),
    (s, t_engagement, r_internal_collaborator,       authz._rel_computed(), r_advisor,    NULL, NULL),
    (s, t_engagement, r_internal_collaborator,       authz._rel_computed(), r_assistant,  NULL, NULL),
    (s, t_engagement, r_can_view,                    authz._rel_computed(), r_internal_collaborator, NULL, NULL),
    (s, t_engagement, r_can_view,                    authz._rel_computed(), r_client,     NULL, NULL),
    (s, t_engagement, r_can_manage_access,           authz._rel_computed(), r_advisor,    NULL, NULL),
    (s, t_engagement, r_can_manage_client_collab,    authz._rel_computed(), r_advisor,    NULL, NULL),
    (s, t_engagement, r_can_manage_client_collab,    authz._rel_computed(), r_assistant,  NULL, NULL),

    -- type assignment
    (s, t_assignment, r_parent_engagement, authz._rel_direct(), NULL, NULL, NULL),
    (s, t_assignment, r_accountant,        authz._rel_direct(), NULL, NULL, NULL),
    (s, t_assignment, r_payroll_clerk,     authz._rel_direct(), NULL, NULL, NULL),
    (s, t_assignment, r_tax_clerk,         authz._rel_direct(), NULL, NULL, NULL),
    (s, t_assignment, r_assistant,         authz._rel_direct(), NULL, NULL, NULL),
    (s, t_assignment, r_can_view,  authz._rel_computed(), r_accountant,    NULL, NULL),
    (s, t_assignment, r_can_view,  authz._rel_computed(), r_payroll_clerk, NULL, NULL),
    (s, t_assignment, r_can_view,  authz._rel_computed(), r_tax_clerk,     NULL, NULL),
    (s, t_assignment, r_can_view,  authz._rel_computed(), r_assistant,     NULL, NULL),
    (s, t_assignment, r_can_view,  authz._rel_ttu(),      NULL, r_parent_engagement, r_internal_collaborator),
    (s, t_assignment, r_can_edit,  authz._rel_computed(), r_accountant,    NULL, NULL),
    (s, t_assignment, r_can_edit,  authz._rel_computed(), r_payroll_clerk, NULL, NULL),
    (s, t_assignment, r_can_edit,  authz._rel_computed(), r_tax_clerk,     NULL, NULL),
    (s, t_assignment, r_can_approve, authz._rel_computed(), r_accountant,    NULL, NULL),
    (s, t_assignment, r_can_approve, authz._rel_computed(), r_payroll_clerk, NULL, NULL),
    (s, t_assignment, r_can_approve, authz._rel_computed(), r_tax_clerk,     NULL, NULL),
    (s, t_assignment, r_can_manage_access, authz._rel_ttu(), NULL, r_parent_engagement, r_can_manage_access),

    -- type internal_data_space
    (s, t_int_ds, r_parent_engagement, authz._rel_direct(), NULL, NULL, NULL),
    (s, t_int_ds, r_parent_assignment, authz._rel_direct(), NULL, NULL, NULL),
    (s, t_int_ds, r_viewer,     authz._rel_direct(), NULL, NULL, NULL),
    (s, t_int_ds, r_editor,     authz._rel_direct(), NULL, NULL, NULL),
    (s, t_int_ds, r_can_view,  authz._rel_computed(), r_viewer, NULL, NULL),
    (s, t_int_ds, r_can_view,  authz._rel_ttu(),      NULL, r_parent_assignment, r_can_view),
    (s, t_int_ds, r_can_view,  authz._rel_ttu(),      NULL, r_parent_engagement, r_internal_collaborator),
    (s, t_int_ds, r_can_edit,  authz._rel_computed(), r_editor, NULL, NULL),
    (s, t_int_ds, r_can_edit,  authz._rel_ttu(),      NULL, r_parent_assignment, r_can_edit),
    (s, t_int_ds, r_can_edit,  authz._rel_ttu(),      NULL, r_parent_engagement, r_advisor),
    (s, t_int_ds, r_can_manage_access, authz._rel_ttu(), NULL, r_parent_engagement, r_can_manage_access),

    -- type client_data_space
    (s, t_cli_ds, r_parent_engagement,       authz._rel_direct(), NULL, NULL, NULL),
    (s, t_cli_ds, r_client_org,              authz._rel_direct(), NULL, NULL, NULL),
    (s, t_cli_ds, r_direct_client_user,      authz._rel_direct(), NULL, NULL, NULL),
    (s, t_cli_ds, r_direct_internal_manager, authz._rel_direct(), NULL, NULL, NULL),
    (s, t_cli_ds, r_client_member, authz._rel_computed(), r_direct_client_user, NULL, NULL),
    (s, t_cli_ds, r_client_member, authz._rel_ttu(),      NULL, r_client_org, r_member),
    (s, t_cli_ds, r_can_view,      authz._rel_computed(), r_client_member, NULL, NULL),
    (s, t_cli_ds, r_can_upload,    authz._rel_computed(), r_client_member, NULL, NULL),
    (s, t_cli_ds, r_can_manage_sharing, authz._rel_computed(), r_direct_internal_manager, NULL, NULL),
    (s, t_cli_ds, r_can_manage_sharing, authz._rel_ttu(),      NULL, r_parent_engagement, r_can_manage_client_collab),
    (s, t_cli_ds, r_can_manage_access,  authz._rel_ttu(),      NULL, r_parent_engagement, r_can_manage_access),

    -- type document
    (s, t_document, r_in_internal_space, authz._rel_direct(), NULL, NULL, NULL),
    (s, t_document, r_in_client_space,   authz._rel_direct(), NULL, NULL, NULL),
    (s, t_document, r_viewer,   authz._rel_direct(), NULL, NULL, NULL),
    (s, t_document, r_editor,   authz._rel_direct(), NULL, NULL, NULL),
    (s, t_document, r_can_read,  authz._rel_computed(), r_viewer, NULL, NULL),
    (s, t_document, r_can_read,  authz._rel_ttu(),      NULL, r_in_internal_space, r_can_view),
    (s, t_document, r_can_read,  authz._rel_ttu(),      NULL, r_in_client_space,   r_can_view),
    (s, t_document, r_can_edit,  authz._rel_computed(), r_editor, NULL, NULL),
    (s, t_document, r_can_edit,  authz._rel_ttu(),      NULL, r_in_internal_space, r_can_edit),
    (s, t_document, r_can_share_with_client, authz._rel_ttu(), NULL, r_in_client_space, r_can_manage_sharing),
    (s, t_document, r_can_delete, authz._rel_ttu(), NULL, r_in_internal_space, r_can_manage_access),
    -- Folder containment (additive): a document may also live in a folder and
    -- inherit view/edit/delete from it (and, recursively, its parent folders).
    (s, t_document, r_parent_folder, authz._rel_direct(), NULL, NULL, NULL),
    (s, t_document, r_can_read,   authz._rel_ttu(), NULL, r_parent_folder, r_can_view),
    (s, t_document, r_can_edit,   authz._rel_ttu(), NULL, r_parent_folder, r_can_edit),
    (s, t_document, r_can_delete, authz._rel_ttu(), NULL, r_parent_folder, r_can_manage_access),

    -- type folder
    -- Nestable document container. Permissions granted on a folder inherit DOWN to
    -- its subfolders (via `parent`) and to the documents inside them (via a
    -- document's `parent_folder`). Recursive: can_* pulls from the parent's can_*.
    (s, t_folder, r_parent, authz._rel_direct(), NULL, NULL, NULL),
    (s, t_folder, r_owner,  authz._rel_direct(), NULL, NULL, NULL),
    (s, t_folder, r_editor, authz._rel_direct(), NULL, NULL, NULL),
    (s, t_folder, r_viewer, authz._rel_direct(), NULL, NULL, NULL),
    -- can_view: viewer or editor or owner or can_view from parent
    (s, t_folder, r_can_view, authz._rel_computed(), r_viewer, NULL, NULL),
    (s, t_folder, r_can_view, authz._rel_computed(), r_editor, NULL, NULL),
    (s, t_folder, r_can_view, authz._rel_computed(), r_owner,  NULL, NULL),
    (s, t_folder, r_can_view, authz._rel_ttu(),      NULL, r_parent, r_can_view),
    -- can_edit: editor or owner or can_edit from parent
    (s, t_folder, r_can_edit, authz._rel_computed(), r_editor, NULL, NULL),
    (s, t_folder, r_can_edit, authz._rel_computed(), r_owner,  NULL, NULL),
    (s, t_folder, r_can_edit, authz._rel_ttu(),      NULL, r_parent, r_can_edit),
    -- can_manage_access: owner or can_manage_access from parent
    (s, t_folder, r_can_manage_access, authz._rel_computed(), r_owner, NULL, NULL),
    (s, t_folder, r_can_manage_access, authz._rel_ttu(),      NULL, r_parent, r_can_manage_access),
    -- can_share: owner or editor or can_share from parent (invite collaborators)
    (s, t_folder, r_can_share, authz._rel_computed(), r_owner,  NULL, NULL),
    (s, t_folder, r_can_share, authz._rel_computed(), r_editor, NULL, NULL),
    (s, t_folder, r_can_share, authz._rel_ttu(),      NULL, r_parent, r_can_share),

    -- type upload_request
    (s, t_upload_req, r_in_client_space, authz._rel_direct(), NULL, NULL, NULL),
    (s, t_upload_req, r_requested_from,  authz._rel_direct(), NULL, NULL, NULL),
    (s, t_upload_req, r_created_by,      authz._rel_direct(), NULL, NULL, NULL),
    (s, t_upload_req, r_can_view,   authz._rel_computed(), r_requested_from, NULL, NULL),
    (s, t_upload_req, r_can_view,   authz._rel_computed(), r_created_by,     NULL, NULL),
    (s, t_upload_req, r_can_view,   authz._rel_ttu(),      NULL, r_in_client_space, r_can_manage_sharing),
    (s, t_upload_req, r_can_submit, authz._rel_computed(), r_requested_from, NULL, NULL),
    (s, t_upload_req, r_can_manage, authz._rel_computed(), r_created_by,     NULL, NULL),
    (s, t_upload_req, r_can_manage, authz._rel_ttu(),      NULL, r_in_client_space, r_can_manage_sharing)
    ;

    ----------------------------------------------------------------------
    -- Type restrictions: the subject types each DIRECT relation accepts.
    -- Without these, a direct relation accepts ANY subject type (describe_model
    -- renders it as `[any]`). Declaring them explicitly mirrors OpenFGA, where
    -- every directly-assignable relation must list its allowed types — e.g.
    -- `define payroll_clerk: [internal_user, team#member]`.
    --
    --   * object-reference relations (parent_*, in_*, *_space, client/client_org)
    --     point at exactly one object type;
    --   * role relations accept a concrete user type and/or a userset
    --     (team#member, client_org#member) — the latter is how the seed grants
    --     assignment roles and upload requests in bulk.
    ----------------------------------------------------------------------
    -- team / client_org membership
    PERFORM authz.model_add_type_restriction('demo', 'team',       'member', 'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'client_org', 'member', 'client_user');

    -- engagement: internal staff, plus the customer org as the "client"
    PERFORM authz.model_add_type_restriction('demo', 'engagement', 'advisor',   'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'engagement', 'assistant', 'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'engagement', 'client',    'client_org');

    -- assignment: linked to its engagement; roles granted to a user or a team
    PERFORM authz.model_add_type_restriction('demo', 'assignment', 'parent_engagement', 'engagement');
    PERFORM authz.model_add_type_restriction('demo', 'assignment', 'accountant',    'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'assignment', 'accountant',    'team', 'member');
    PERFORM authz.model_add_type_restriction('demo', 'assignment', 'payroll_clerk', 'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'assignment', 'payroll_clerk', 'team', 'member');
    PERFORM authz.model_add_type_restriction('demo', 'assignment', 'tax_clerk',     'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'assignment', 'tax_clerk',     'team', 'member');
    PERFORM authz.model_add_type_restriction('demo', 'assignment', 'assistant',     'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'assignment', 'assistant',     'team', 'member');

    -- internal_data_space: linked to assignment + engagement; viewer/editor are internal
    PERFORM authz.model_add_type_restriction('demo', 'internal_data_space', 'parent_engagement', 'engagement');
    PERFORM authz.model_add_type_restriction('demo', 'internal_data_space', 'parent_assignment', 'assignment');
    PERFORM authz.model_add_type_restriction('demo', 'internal_data_space', 'viewer', 'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'internal_data_space', 'viewer', 'team', 'member');
    PERFORM authz.model_add_type_restriction('demo', 'internal_data_space', 'editor', 'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'internal_data_space', 'editor', 'team', 'member');

    -- client_data_space: linked to engagement; client org/users + an internal manager
    PERFORM authz.model_add_type_restriction('demo', 'client_data_space', 'parent_engagement',       'engagement');
    PERFORM authz.model_add_type_restriction('demo', 'client_data_space', 'client_org',              'client_org');
    PERFORM authz.model_add_type_restriction('demo', 'client_data_space', 'direct_client_user',      'client_user');
    PERFORM authz.model_add_type_restriction('demo', 'client_data_space', 'direct_internal_manager', 'internal_user');

    -- document: spaces point at data spaces; viewer also accepts a customer user
    -- and the document service account (the object wildcard document:* is enabled
    -- separately on the viewer rule below).
    PERFORM authz.model_add_type_restriction('demo', 'document', 'in_internal_space', 'internal_data_space');
    PERFORM authz.model_add_type_restriction('demo', 'document', 'in_client_space',   'client_data_space');
    PERFORM authz.model_add_type_restriction('demo', 'document', 'viewer', 'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'document', 'viewer', 'client_user');
    PERFORM authz.model_add_type_restriction('demo', 'document', 'viewer', 'service_account');
    PERFORM authz.model_add_type_restriction('demo', 'document', 'editor', 'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'document', 'parent_folder', 'folder');

    -- folder: nests into another folder; owner/editor/viewer granted to a user or team
    PERFORM authz.model_add_type_restriction('demo', 'folder', 'parent', 'folder');
    PERFORM authz.model_add_type_restriction('demo', 'folder', 'owner',  'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'folder', 'owner',  'team', 'member');
    PERFORM authz.model_add_type_restriction('demo', 'folder', 'editor', 'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'folder', 'editor', 'team', 'member');
    PERFORM authz.model_add_type_restriction('demo', 'folder', 'viewer', 'internal_user');
    PERFORM authz.model_add_type_restriction('demo', 'folder', 'viewer', 'team', 'member');

    -- upload_request: linked to a client space; requested from a customer, created by staff
    PERFORM authz.model_add_type_restriction('demo', 'upload_request', 'in_client_space', 'client_data_space');
    PERFORM authz.model_add_type_restriction('demo', 'upload_request', 'requested_from',  'client_user');
    PERFORM authz.model_add_type_restriction('demo', 'upload_request', 'requested_from',  'client_org', 'member');
    PERFORM authz.model_add_type_restriction('demo', 'upload_request', 'created_by',      'internal_user');

    -- Privileged grants (object wildcards): mark the document viewer
    -- direct rule so a single tuple like
    --   write_tuple('demo', 'internal_user', '<auditor>', 'viewer', 'document', '*')
    -- can grant read on EVERY document (compliance auditor use case).
    -- model_add_rule upserts the flag onto the direct rule added above.
    PERFORM authz.model_add_rule('demo', 'document', 'viewer', 'direct',
        p_allow_object_wildcard => true);

END;
$$;
