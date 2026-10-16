-- ============================================================================
-- AuthZEN certification fixture — the PDP data the OpenID conformance suite
-- expects (openid/authzen issue #433, "Certification Scenario", section 1)
-- ============================================================================
--
-- The OpenID Foundation's conformance suite tests an AuthZEN 1.0 PDP by
-- playing the PEP: it sends the requests below to pgauthzd and compares the
-- decisions. This store is that fixture as a pgauthz model, so that the
-- `authzen-pdp-*-test-plan`s can run against `/stores/authzen_cert/access/v1`.
--
-- Entities (the suite sends these identifiers verbatim):
--
--   subjects   user:alice, user:bob         (bob carries role=admin as a property)
--   resources  record:record-1 (status=active), record:record-2 (status=archived)
--   actions    read, write, delete          (delete carries soft=true|false)
--
-- Core level — decided from identifiers alone, this model's whole job:
--
--   alice read  record-1  -> true          bob read  record-1 -> true
--   alice write record-1  -> true          bob write record-1 -> false
--   subjects of type user who can read record-1  ⊇ {alice, bob}
--   resources of type record alice can read      ⊇ {record-1}
--   actions alice holds on record-1              ⊇ {read, write}
--
-- Properties level (rules 5–8: archived records, the admin role, soft vs hard
-- delete) depends on request PROPERTIES, which pgauthzd does not yet feed into
-- the engine; this fixture does not model them. Rule 5 (alice may not write
-- the archived record-2) still holds by the graph: alice only reads record-2.
--
-- OpenFGA DSL equivalent:
--
--   type user
--
--   type record
--     relations
--       define reader: [user]
--       define writer: [user]
--       define read:   reader or writer
--       define write:  writer
--       define delete: writer
--
-- The actions are relations named exactly as the suite's `action.name`s.
-- ============================================================================

----------------------------------------------------------------------
-- Store. Dropped first so this file is idempotent — re-running it resets
-- the fixture (a sandbox, so its audit history is purged too).
----------------------------------------------------------------------
DO $$
BEGIN
    PERFORM authz.delete_store('authzen_cert', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN
    NULL;  -- store did not exist yet
END $$;
SELECT authz.create_store('authzen_cert', 'AuthZEN certification fixture (openid/authzen #433)');

----------------------------------------------------------------------
-- Types and relations.
----------------------------------------------------------------------
SELECT authz.model_register_type('authzen_cert', 'user');
SELECT authz.model_register_type('authzen_cert', 'record');

SELECT authz.model_register_relation('authzen_cert', 'reader');
SELECT authz.model_register_relation('authzen_cert', 'writer');
SELECT authz.model_register_relation('authzen_cert', 'read');
SELECT authz.model_register_relation('authzen_cert', 'write');
SELECT authz.model_register_relation('authzen_cert', 'delete');

----------------------------------------------------------------------
-- Rules. 'direct' = granted by a tuple; 'computed' = implied by another
-- relation on the same object.
----------------------------------------------------------------------
SELECT authz.model_add_rule('authzen_cert', 'record', 'reader', 'direct');
SELECT authz.model_add_rule('authzen_cert', 'record', 'writer', 'direct');
SELECT authz.model_add_rule('authzen_cert', 'record', 'read',   'computed', 'reader');
SELECT authz.model_add_rule('authzen_cert', 'record', 'read',   'computed', 'writer');
SELECT authz.model_add_rule('authzen_cert', 'record', 'write',  'computed', 'writer');
SELECT authz.model_add_rule('authzen_cert', 'record', 'delete', 'computed', 'writer');

-- Only users hold the direct relations (the `[user]` of the DSL above).
SELECT authz.model_add_type_restriction('authzen_cert', 'record', 'reader', 'user');
SELECT authz.model_add_type_restriction('authzen_cert', 'record', 'writer', 'user');

-- Render the model as OpenFGA-style DSL text to verify what was built.
SELECT authz.describe_model('authzen_cert');
