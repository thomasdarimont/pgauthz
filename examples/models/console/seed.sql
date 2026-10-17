-- Console seed: the demo deployment's access. Store ids are the names of the
-- stores the dev stack loads (test.sh fixtures + the console itself); a store
-- that does not exist yet is simply an id here, so this file never depends
-- on load order.
--
-- Teams named role_<realm role> are what the console derives from a Keycloak
-- token (realm_access.roles → team:role_<name>, groups → team:group_<path>,
-- organization → team:org_<alias>) and injects as contextual tuples, so the
-- rows below that name a team take effect for whoever carries that role.

-- The deployment and its registry.
-- The store name is the psql variable :cs (default console): test.sh loads
-- this fixture as console_test so a test run never touches the console store
-- a running console uses.
\if :{?cs} \else \set cs console \endif
SELECT authz.write_tuple(:'cs', 'team', 'role_console_admin', 'admin', 'platform', 'default', 'member');
SELECT authz.write_tuple(:'cs', 'platform', 'default', 'platform', 'registry', 'default');

-- Every store the dev stack knows reports to the platform (the platform admin
-- can see it and reassign owners). The console writes this tuple itself for
-- stores it creates or adopts.
SELECT authz.write_tuple(:'cs', 'platform', 'default', 'platform', 'store', s)
  FROM unnest(ARRAY[:'cs', 'demo', 'todo', 'gdrive', 'aia_acme', 'agents', 'fourq', 'helloworld', 'authzen_cert']) AS s;

-- The console's own store: platform admins own it.
SELECT authz.write_tuple(:'cs', 'team', 'role_console_admin', 'owner', 'store', :'cs', 'member');

-- demo: alice owns it, bob tests, carol looks, eva audits.
SELECT authz.write_tuple(:'cs', 'user', 'alice', 'owner',   'store', 'demo');
SELECT authz.write_tuple(:'cs', 'user', 'bob',   'tester',  'store', 'demo');
SELECT authz.write_tuple(:'cs', 'user', 'carol', 'viewer',  'store', 'demo');
SELECT authz.write_tuple(:'cs', 'user', 'eva',   'auditor', 'store', 'demo');

-- todo: bob authors the model, alice publishes and rolls out.
SELECT authz.write_tuple(:'cs', 'user', 'bob',   'author',    'store', 'todo');
SELECT authz.write_tuple(:'cs', 'user', 'alice', 'publisher', 'store', 'todo');
SELECT authz.write_tuple(:'cs', 'user', 'alice', 'owner',     'store', 'todo');

-- gdrive: alice owns it; everyone with the authz_writer realm role may share.
SELECT authz.write_tuple(:'cs', 'user', 'alice', 'owner', 'store', 'gdrive');
SELECT authz.write_tuple(:'cs', 'team', 'role_authz_writer', 'sharer', 'store', 'gdrive', 'member');

-- The registry: publishers of any store may browse it; alice publishes.
SELECT authz.write_tuple(:'cs', 'user', 'alice', 'publisher', 'registry', 'default');
SELECT authz.write_tuple(:'cs', 'user', 'bob',   'viewer',    'registry', 'default');

-- ── Demo personas (keycloak/terraform/users.console.tf): who uses the console
-- for what. Each holds one realm role; the role arrives as a team membership
-- on every console check, so the grants below are per team, not per person.
--   platform-admin  console_admin        platform admin (seeded above)
--   auditor         console_auditor      reads audit and decisions everywhere
--   iam-dev         console_iam_dev      owns the models: author + publisher, registry publisher
--   app-dev         console_app_dev      developer: viewer + tester (test policy: own access only)
--   app-secarch     console_app_secarch  security architect of an app: author on its store, registry viewer
--   support         console_support      supporter: looks up anyone's access, never edits
SELECT authz.write_tuple(:'cs', 'team', 'role_console_auditor', 'auditor', 'store', s, 'member')
  FROM unnest(ARRAY['demo', 'todo', 'gdrive', 'aia_acme', 'agents', 'fourq', 'helloworld', 'authzen_cert']) AS s;
SELECT authz.write_tuple(:'cs', 'team', 'role_console_auditor', 'viewer', 'registry', 'default', 'member');
SELECT authz.write_tuple(:'cs', 'team', 'role_console_iam_dev', r, 'store', s, 'member')
  FROM unnest(ARRAY['author', 'publisher']) AS r,
       unnest(ARRAY['demo', 'todo', 'gdrive', 'aia_acme', 'agents', 'fourq', 'helloworld', 'authzen_cert']) AS s;
SELECT authz.write_tuple(:'cs', 'team', 'role_console_iam_dev', 'publisher', 'registry', 'default', 'member');
SELECT authz.write_tuple(:'cs', 'team', 'role_console_app_dev', r, 'store', s, 'member')
  FROM unnest(ARRAY['viewer', 'tester']) AS r, unnest(ARRAY['demo', 'todo']) AS s;
SELECT authz.write_tuple(:'cs', 'team', 'role_console_app_secarch', 'author', 'store', 'demo', 'member');
SELECT authz.write_tuple(:'cs', 'team', 'role_console_app_secarch', 'tester', 'store', 'todo', 'member');
SELECT authz.write_tuple(:'cs', 'team', 'role_console_app_secarch', 'viewer', 'registry', 'default', 'member');
SELECT authz.write_tuple(:'cs', 'team', 'role_console_support', 'supporter', 'store', s, 'member')
  FROM unnest(ARRAY['demo', 'todo', 'gdrive']) AS s;
