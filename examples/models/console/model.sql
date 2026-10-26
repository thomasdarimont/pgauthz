-- ============================================================================
-- Console — the authorization model of the pgauthz management console
-- ============================================================================
--
-- The console (console/) is a backend-for-frontend that lets people manage
-- pgauthz stores: design and edit models, test decisions, publish and roll out
-- registry versions, share objects, read the audit trail. Who may do what in
-- the console is itself a pgauthz question, answered by THIS store. The
-- console asks it before every screen and every action ("may alice edit the
-- model of store:demo?"), then performs the action in the managed store.
--
-- Subjects are the people who log in through the identity provider; their
-- directory memberships (realm roles, groups, organization) arrive as
-- contextual tuples on every console check ("user:alice member
-- team:role_console_admin"), so a store can be shared with a team that only
-- exists in the IdP. Explicit tuples (an owner, a tester) are written by the
-- console's Access tab.
--
-- OpenFGA DSL equivalent:
--
--   type user
--
--   type team
--     relations
--       define member: [user]
--
--   type platform                          # one object: platform:default
--     relations
--       define admin: [user, team#member]
--       define issuer_admin: [user, team#member]   # manages the trusted issuers' bindings, nothing else
--       define can_manage_issuers: admin or issuer_admin
--       define can_view_health: admin
--       define can_create_store: admin
--       define can_view_all_stores: admin
--       define can_manage_access: admin        # who else is a platform admin
--
--   type registry                          # one object: registry:default
--     relations
--       define platform: [platform]
--       define publisher: [user, team#member]
--       define viewer: [user, team#member]
--       define can_publish: publisher or admin from platform
--       define can_view: viewer or publisher or admin from platform
--
--   type store                             # one object per managed store
--     relations
--       define platform: [platform]
--       define owner: [user, team#member]
--       define author: [user, team#member]
--       define publisher: [user, team#member]
--       define sharer: [user, team#member]
--       define tester: [user, team#member]
--       define supporter: [user, team#member]   # support: looks up other people's access, never edits
--       define auditor: [user, team#member]
--       define exporter: [user, team#member]    # may export the store's tuples (every export is recorded)
--       define viewer: [user, team#member]
--       define can_view: viewer or tester or supporter or sharer or author or publisher
--                        or auditor or exporter or owner or admin from platform
--       define can_run_tests: tester or supporter or author or publisher or owner
--       # the test policy: what a tester may ask beyond their own access
--       define can_test_others: supporter or author or publisher or owner      # subjects other than yourself
--       define can_test_explain_full: supporter or author or publisher or owner # unredacted resolution trees
--       define can_test_search: author or publisher or owner       # list_objects / list_subjects
--       define can_test_history: auditor or author or publisher or owner  # point-in-time checks
--       define can_edit_model: author or owner
--       define can_publish: publisher or owner
--       define can_rollout: publisher or owner
--       define can_grant: sharer or owner
--       define can_view_audit: auditor or owner
--       define can_export: exporter or owner     # export tuples: sensitive, dedicated role, recorded
--       define can_view_decisions: auditor or publisher or owner
--       define can_manage_access: owner or admin from platform
--       define namespace: [namespace]            # the store's namespaces (link, see below)
--
--   type namespace                         # one object per namespace of a store: namespace:<store>/<name>
--     relations                            # app teams own a namespace inside a shared store
--       define store: [store]
--       define author: [user, team#member]
--       define viewer: [user, team#member]
--       define can_view: viewer or author or can_view from store
--       define can_edit_model: author or can_edit_model from store
--       define can_grant: author or can_grant from store
--
-- A namespace role reaches the store through the two link tuples the console
-- writes when the first role is granted (namespace:X/ns store store:X and
-- store:X namespace namespace:X/ns): the store's can_view includes
-- `can_view from namespace`, so a namespace author can open the store, and
-- the console checks every model or data change against the namespace of
-- the type it touches (store-wide changes still need the store role).
--
-- The platform admin reaches every store through the `platform` tuple
-- (store:X platform platform:default): they can see it and reassign its
-- owners, but editing, publishing or sharing still needs a store role —
-- ownership is transferable, never implicit.
-- ============================================================================

-- The store name is the psql variable :cs (default console): test.sh loads
-- this fixture as console_test so a test run never touches the console store
-- a running console uses.
\if :{?cs} \else \set cs console \endif
SELECT authz.delete_store(:'cs', p_purge_audit => true)
 WHERE EXISTS (SELECT 1 FROM authz.stores WHERE name = :'cs');
SELECT authz.create_store(:'cs', 'pgauthz management console: who may manage which store');

----------------------------------------------------------------------
-- Types
----------------------------------------------------------------------
SELECT authz.model_register_type(:'cs', 'user',     p_description => 'a person logged in through the IdP (id = preferred_username)');
SELECT authz.model_register_type(:'cs', 'service_account', p_description => 'a technical user: an OAuth client (id = client id / azp) calling the admin API — a CI pipeline, a Terraform runner');
SELECT authz.model_register_type(:'cs', 'team',     p_description => 'a directory group: realm role, group or organization, as contextual tuples');
SELECT authz.model_register_type(:'cs', 'platform', p_description => 'the console deployment itself (platform:default)');
SELECT authz.model_register_type(:'cs', 'registry', p_description => 'the model registry (registry:default)');
SELECT authz.model_register_type(:'cs', 'group',    p_description => 'a store group (ADR 0017): a named set of stores sharing administration, trust and models (id = group name; group:default is the platform''s own)');
SELECT authz.model_register_type(:'cs', 'store',    p_description => 'a managed pgauthz store (id = store name)');
SELECT authz.model_register_type(:'cs', 'namespace', p_description => 'a namespace of a managed store (id = <store>/<namespace>)');

----------------------------------------------------------------------
-- Relations
----------------------------------------------------------------------
SELECT authz.model_register_relation(:'cs', r) FROM unnest(ARRAY[
    'member', 'admin', 'issuer_admin', 'platform', 'group',
    'owner', 'author', 'publisher', 'sharer', 'tester', 'supporter', 'auditor', 'exporter', 'viewer',
    'can_manage_issuers', 'can_view_health', 'can_create_store', 'can_view_all_stores',
    'can_view', 'can_run_tests', 'can_edit_model', 'can_publish', 'can_rollout',
    'can_grant', 'can_view_audit', 'can_export', 'can_view_decisions', 'can_manage_access',
    'can_test_others', 'can_test_explain_full', 'can_test_search', 'can_test_history',
    'store', 'namespace'
]) AS r;

----------------------------------------------------------------------
-- team
----------------------------------------------------------------------
SELECT authz.model_add_rule(:'cs', 'team', 'member', 'direct');
SELECT authz.model_add_type_restriction(:'cs', 'team', 'member', 'user');
SELECT authz.model_add_type_restriction(:'cs', 'team', 'member', 'service_account');

----------------------------------------------------------------------
-- platform
----------------------------------------------------------------------
SELECT authz.model_add_rule(:'cs', 'platform', 'admin', 'direct');
-- The engine owns "a store keeps at least one owner" / "the platform keeps at
-- least one admin" (relation floors, migration 0026): a revocation that would
-- leave none is refused (SQLSTATE ZA002); offboarding a person is not.
SELECT authz.model_set_relation_constraint(:'cs', 'platform', 'admin', p_min_direct => 1);
SELECT authz.model_add_type_restriction(:'cs', 'platform', 'admin', 'user');
SELECT authz.model_add_type_restriction(:'cs', 'platform', 'admin', 'service_account');
SELECT authz.model_add_type_restriction(:'cs', 'platform', 'admin', 'team', 'member');
SELECT authz.model_add_rule(:'cs', 'platform', r, 'computed', 'admin')
  FROM unnest(ARRAY['can_manage_issuers', 'can_view_health', 'can_create_store', 'can_view_all_stores', 'can_manage_access']) AS r;
-- issuer_admin: the identity providers' bindings only (Platform → Issuers),
-- delegable without the rest of platform administration.
SELECT authz.model_add_rule(:'cs', 'platform', 'issuer_admin', 'direct');
SELECT authz.model_add_type_restriction(:'cs', 'platform', 'issuer_admin', 'user');
SELECT authz.model_add_type_restriction(:'cs', 'platform', 'issuer_admin', 'service_account');
SELECT authz.model_add_type_restriction(:'cs', 'platform', 'issuer_admin', 'team', 'member');
SELECT authz.model_add_rule(:'cs', 'platform', 'can_manage_issuers', 'computed', 'issuer_admin');

----------------------------------------------------------------------
-- group (ADR 0017): one level below the platform — a group admin reaches
-- every store of the group the way a platform admin reaches every group.
-- Link tuples (group:X platform platform:default, store:Y group group:X)
-- mirror the engine's membership; the console writes them.
----------------------------------------------------------------------
SELECT authz.model_add_rule(:'cs', 'group', 'platform', 'direct');
SELECT authz.model_add_type_restriction(:'cs', 'group', 'platform', 'platform');
SELECT authz.model_add_rule(:'cs', 'group', 'admin', 'direct');
SELECT authz.model_add_type_restriction(:'cs', 'group', 'admin', 'user');
SELECT authz.model_add_type_restriction(:'cs', 'group', 'admin', 'service_account');
SELECT authz.model_add_type_restriction(:'cs', 'group', 'admin', 'team', 'member');
SELECT authz.model_add_rule(:'cs', 'group', 'issuer_admin', 'direct');
SELECT authz.model_add_type_restriction(:'cs', 'group', 'issuer_admin', 'user');
SELECT authz.model_add_type_restriction(:'cs', 'group', 'issuer_admin', 'service_account');
SELECT authz.model_add_type_restriction(:'cs', 'group', 'issuer_admin', 'team', 'member');
-- a group admin, or the platform admin above it, manages the group
SELECT authz.model_add_rule(:'cs', 'group', r, 'computed', 'admin')
  FROM unnest(ARRAY['can_view', 'can_create_store', 'can_manage_access', 'can_manage_issuers']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', r, 'ttu', NULL, 'platform', 'admin')
  FROM unnest(ARRAY['can_view', 'can_create_store', 'can_manage_access', 'can_manage_issuers']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_manage_issuers', 'computed', 'issuer_admin');
-- Every store role exists on the group too (ADR 0017): a role on
-- group:X is that role on every store of the group — a team may test all
-- stores of groups A and B and view one store of group C. The group's
-- capabilities mirror the store's, computed from the same roles, and each
-- store capability is also "… from group".
SELECT authz.model_add_rule(:'cs', 'group', r, 'direct')
  FROM unnest(ARRAY['author', 'publisher', 'sharer', 'tester', 'supporter', 'auditor', 'exporter', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'group', r, 'user')
  FROM unnest(ARRAY['author', 'publisher', 'sharer', 'tester', 'supporter', 'auditor', 'exporter', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'group', r, 'service_account')
  FROM unnest(ARRAY['author', 'publisher', 'sharer', 'tester', 'supporter', 'auditor', 'exporter', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'group', r, 'team', 'member')
  FROM unnest(ARRAY['author', 'publisher', 'sharer', 'tester', 'supporter', 'auditor', 'exporter', 'viewer']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_view', 'computed', r)
  FROM unnest(ARRAY['viewer', 'tester', 'supporter', 'sharer', 'author', 'publisher', 'auditor', 'exporter']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_run_tests', 'computed', r)
  FROM unnest(ARRAY['tester', 'supporter', 'author', 'publisher', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_test_others', 'computed', r)
  FROM unnest(ARRAY['supporter', 'author', 'publisher', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_test_explain_full', 'computed', r)
  FROM unnest(ARRAY['supporter', 'author', 'publisher', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_test_search', 'computed', r)
  FROM unnest(ARRAY['author', 'publisher', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_test_history', 'computed', r)
  FROM unnest(ARRAY['auditor', 'author', 'publisher', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_edit_model', 'computed', r)
  FROM unnest(ARRAY['author', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_publish', 'computed', r)
  FROM unnest(ARRAY['publisher', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_rollout', 'computed', r)
  FROM unnest(ARRAY['publisher', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_grant', 'computed', r)
  FROM unnest(ARRAY['sharer', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_view_audit', 'computed', r)
  FROM unnest(ARRAY['auditor', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_export', 'computed', r)
  FROM unnest(ARRAY['exporter', 'admin']) AS r;
SELECT authz.model_add_rule(:'cs', 'group', 'can_view_decisions', 'computed', r)
  FROM unnest(ARRAY['auditor', 'publisher', 'admin']) AS r;

----------------------------------------------------------------------
-- registry
----------------------------------------------------------------------
SELECT authz.model_add_rule(:'cs', 'registry', 'platform', 'direct');
SELECT authz.model_add_type_restriction(:'cs', 'registry', 'platform', 'platform');
SELECT authz.model_add_rule(:'cs', 'registry', r, 'direct') FROM unnest(ARRAY['publisher', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'registry', r, 'user') FROM unnest(ARRAY['publisher', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'registry', r, 'service_account') FROM unnest(ARRAY['publisher', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'registry', r, 'team', 'member') FROM unnest(ARRAY['publisher', 'viewer']) AS r;

SELECT authz.model_add_rule(:'cs', 'registry', 'can_publish', 'computed', 'publisher');
SELECT authz.model_add_rule(:'cs', 'registry', 'can_publish', 'ttu', NULL, 'platform', 'admin');
SELECT authz.model_add_rule(:'cs', 'registry', 'can_view', 'computed', 'viewer');
SELECT authz.model_add_rule(:'cs', 'registry', 'can_view', 'computed', 'publisher');
SELECT authz.model_add_rule(:'cs', 'registry', 'can_view', 'ttu', NULL, 'platform', 'admin');

----------------------------------------------------------------------
-- store
----------------------------------------------------------------------
SELECT authz.model_add_rule(:'cs', 'store', 'platform', 'direct');
SELECT authz.model_add_type_restriction(:'cs', 'store', 'platform', 'platform');
-- the store's group (ADR 0017): its admins see and administer the store
SELECT authz.model_add_rule(:'cs', 'store', 'group', 'direct');
SELECT authz.model_add_type_restriction(:'cs', 'store', 'group', 'group');

SELECT authz.model_add_rule(:'cs', 'store', r, 'direct')
  FROM unnest(ARRAY['owner', 'author', 'publisher', 'sharer', 'tester', 'supporter', 'auditor', 'exporter', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'store', r, 'user')
  FROM unnest(ARRAY['owner', 'author', 'publisher', 'sharer', 'tester', 'supporter', 'auditor', 'exporter', 'viewer']) AS r;
-- technical users (service_account:<client id>) hold store roles like people:
-- pgauthzd's admin gate asks this store for them (delegated admin rules)
SELECT authz.model_add_type_restriction(:'cs', 'store', r, 'service_account')
  FROM unnest(ARRAY['owner', 'author', 'publisher', 'sharer', 'tester', 'supporter', 'auditor', 'exporter', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'store', r, 'team', 'member')
  FROM unnest(ARRAY['owner', 'author', 'publisher', 'sharer', 'tester', 'supporter', 'auditor', 'exporter', 'viewer']) AS r;
-- A store keeps at least one owner (relation floor, migration 0026): the
-- engine refuses the revocation of the last one; the console maps it to its
-- "add another owner first" answer.
SELECT authz.model_set_relation_constraint(:'cs', 'store', 'owner', p_min_direct => 1);

-- can_view: every store role sees the store, and so does the platform admin.
SELECT authz.model_add_rule(:'cs', 'store', 'can_view', 'computed', r)
  FROM unnest(ARRAY['viewer', 'tester', 'supporter', 'sharer', 'author', 'publisher', 'auditor', 'exporter', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_view', 'ttu', NULL, 'platform', 'admin');
SELECT authz.model_add_rule(:'cs', 'store', 'can_view', 'ttu', NULL, 'group', 'admin');
-- namespace roles open the store (link tuples written by the console)
SELECT authz.model_add_rule(:'cs', 'store', 'namespace', 'direct');
SELECT authz.model_add_type_restriction(:'cs', 'store', 'namespace', 'namespace');
SELECT authz.model_add_rule(:'cs', 'store', 'can_view', 'ttu', NULL, 'namespace', 'can_view');

SELECT authz.model_add_rule(:'cs', 'store', 'can_run_tests', 'computed', r)
  FROM unnest(ARRAY['tester', 'supporter', 'author', 'publisher', 'owner']) AS r;
-- The test policy (enforced by the console before every test): a plain
-- tester asks about their own access, sees redacted trees, cannot enumerate
-- and cannot replay history. Model owners and publishers may; auditors may
-- replay history (together with can_run_tests).
SELECT authz.model_add_rule(:'cs', 'store', 'can_test_others', 'computed', r)
  FROM unnest(ARRAY['supporter', 'author', 'publisher', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_test_explain_full', 'computed', r)
  FROM unnest(ARRAY['supporter', 'author', 'publisher', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_test_search', 'computed', r)
  FROM unnest(ARRAY['author', 'publisher', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_test_history', 'computed', r)
  FROM unnest(ARRAY['auditor', 'author', 'publisher', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_edit_model', 'computed', r)
  FROM unnest(ARRAY['author', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_publish', 'computed', r)
  FROM unnest(ARRAY['publisher', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_rollout', 'computed', r)
  FROM unnest(ARRAY['publisher', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_grant', 'computed', r)
  FROM unnest(ARRAY['sharer', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_view_audit', 'computed', r)
  FROM unnest(ARRAY['auditor', 'owner']) AS r;
-- can_export: the store's tuples leave the system — a dedicated role, and
-- the console records every export in its action log (who, when, format, rows).
SELECT authz.model_add_rule(:'cs', 'store', 'can_export', 'computed', r)
  FROM unnest(ARRAY['exporter', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_view_decisions', 'computed', r)
  FROM unnest(ARRAY['auditor', 'publisher', 'owner']) AS r;
SELECT authz.model_add_rule(:'cs', 'store', 'can_manage_access', 'computed', 'owner');
SELECT authz.model_add_rule(:'cs', 'store', 'can_manage_access', 'ttu', NULL, 'platform', 'admin');
SELECT authz.model_add_rule(:'cs', 'store', 'can_manage_access', 'ttu', NULL, 'group', 'admin');
-- … and every store capability is also the group's (ADR 0017): a role on
-- the group reaches each of its stores
SELECT authz.model_add_rule(:'cs', 'store', c, 'ttu', NULL, 'group', c)
  FROM unnest(ARRAY['can_view', 'can_run_tests', 'can_test_others', 'can_test_explain_full', 'can_test_search', 'can_test_history',
                    'can_edit_model', 'can_publish', 'can_rollout', 'can_grant', 'can_view_audit', 'can_export', 'can_view_decisions']) AS c;

----------------------------------------------------------------------
-- namespace: an application team's slice of a shared store
----------------------------------------------------------------------
SELECT authz.model_add_rule(:'cs', 'namespace', 'store', 'direct');
SELECT authz.model_add_type_restriction(:'cs', 'namespace', 'store', 'store');
SELECT authz.model_add_rule(:'cs', 'namespace', r, 'direct') FROM unnest(ARRAY['author', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'namespace', r, 'user') FROM unnest(ARRAY['author', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'namespace', r, 'service_account') FROM unnest(ARRAY['author', 'viewer']) AS r;
SELECT authz.model_add_type_restriction(:'cs', 'namespace', r, 'team', 'member') FROM unnest(ARRAY['author', 'viewer']) AS r;
SELECT authz.model_add_rule(:'cs', 'namespace', 'can_view', 'computed', r) FROM unnest(ARRAY['viewer', 'author']) AS r;
SELECT authz.model_add_rule(:'cs', 'namespace', 'can_view', 'ttu', NULL, 'store', 'can_view');
SELECT authz.model_add_rule(:'cs', 'namespace', 'can_edit_model', 'computed', 'author');
SELECT authz.model_add_rule(:'cs', 'namespace', 'can_edit_model', 'ttu', NULL, 'store', 'can_edit_model');
SELECT authz.model_add_rule(:'cs', 'namespace', 'can_grant', 'computed', 'author');
SELECT authz.model_add_rule(:'cs', 'namespace', 'can_grant', 'ttu', NULL, 'store', 'can_grant');

-- Relation kinds (migration 0019), declared: what a subject CAN DO (permissions)
-- versus what it IS (relations). The kind is a declaration; whether a relation
-- takes tuples follows from its rules. Inference below only fills in what is
-- left undeclared.
SELECT authz.model_set_relation_metadata(:'cs', r, '{"kind": "permission"}')
  FROM unnest(ARRAY['can_create_store', 'can_edit_model', 'can_grant', 'can_manage_access', 'can_manage_issuers', 'can_publish', 'can_rollout', 'can_run_tests', 'can_view', 'can_view_all_stores', 'can_view_audit', 'can_export', 'can_view_decisions', 'can_view_health', 'can_test_others', 'can_test_explain_full', 'can_test_search', 'can_test_history']) AS r;
SELECT * FROM authz.infer_relation_kinds(:'cs', true);

SELECT authz.describe_model(:'cs');
