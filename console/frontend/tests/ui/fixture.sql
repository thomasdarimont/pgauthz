-- The browser suite's store (loaded by tests/test-console-ui.sh as :store,
-- dropped afterwards): a doc type with a grant rule, alice owning two docs,
-- bob a viewer of doc:a, temp a viewer of doc:a for two more days.
\set ON_ERROR_STOP on
SELECT authz.delete_store(name, p_purge_audit => true) FROM authz.stores WHERE name = :'store';
SELECT authz.create_store(:'store', 'console browser tests');
SELECT authz.model_register_type(:'store', 'user');
SELECT authz.model_register_type(:'store', 'doc');
SELECT authz.model_register_relation(:'store', 'owner');
SELECT authz.model_register_relation(:'store', 'viewer');
SELECT authz.model_register_relation(:'store', 'can_share', NULL, '{"kind": "permission"}'::jsonb);
SELECT authz.model_add_rule(:'store', 'doc', 'owner', 'direct');
SELECT authz.model_add_rule(:'store', 'doc', 'viewer', 'direct');
SELECT authz.model_add_type_restriction(:'store', 'doc', 'viewer', 'user');
SELECT authz.model_add_rule(:'store', 'doc', 'can_share', 'computed', 'owner');
SELECT authz.model_add_grant_rule(:'store', 'doc', 'viewer', 'can_share');
SELECT authz.write_tuple(:'store', 'user', 'alice', 'owner', 'doc', 'a');
SELECT authz.write_tuple(:'store', 'user', 'alice', 'owner', 'doc', 'b');
SELECT authz.write_tuple(:'store', 'user', 'bob', 'viewer', 'doc', 'a');
SELECT authz.write_tuple(:'store', 'user', 'temp', 'viewer', 'doc', 'a', p_expires_at => now() + interval '2 days');
