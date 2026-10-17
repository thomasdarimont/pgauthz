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
-- Properties level (rules 5–8), two kinds of "property":
--
--   alice write record-2 (status=archived)      -> false   (rule 5: alice only reads it)
--   bob (role=admin) write record-2 (archived)  -> true    (rule 6)
--   alice delete record-1 (soft=true)           -> true    (rule 7)
--   alice delete record-1 (soft=false)          -> false   (rule 8)
--   subjects who can write record-2 (archived)  ⊇ {bob};  records admin bob can
--   write ⊇ {record-2};  actions of bob on record-2 ⊇ {write}
--
-- ENTITY attributes — bob's role, record-2's status — are DATA the PDP holds,
-- modelled as tuples (the searches need them: "who can write the archived
-- record?" names no subject, "which records can bob write?" carries no status).
-- The ACTION property `soft` exists only in the request: pgauthzd puts the
-- AuthZEN `properties` into the condition context under the request's own
-- shape (context.subject / .resource / .action, each with .properties), and
-- one condition reads it. Missing `soft` fails closed (MODEL_DESIGN §8).
--
-- OpenFGA DSL equivalent:
--
--   type user
--
--   type record
--     relations
--       define reader:      [user]
--       define writer:      [user]
--       define admin:       [user]          # bob holds it on record:* (object wildcard)
--       define archived:    [user:*]        # flag tuple on record-2: "archived for everyone"
--       define soft_delete: [user:*]        # one conditional wildcard tuple, condition soft_requested
--       define read:   reader or writer
--       define write:  writer or (admin and archived)
--       define delete: writer and soft_delete
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
SELECT authz.model_register_relation('authzen_cert', 'admin');
SELECT authz.model_register_relation('authzen_cert', 'archived');
SELECT authz.model_register_relation('authzen_cert', 'soft_delete');
SELECT authz.model_register_relation('authzen_cert', 'read');
SELECT authz.model_register_relation('authzen_cert', 'write');
SELECT authz.model_register_relation('authzen_cert', 'delete');

----------------------------------------------------------------------
-- Rules. 'direct' = granted by a tuple; 'computed' = implied by another
-- relation on the same object.
----------------------------------------------------------------------
SELECT authz.model_add_rule('authzen_cert', 'record', 'reader', 'direct');
SELECT authz.model_add_rule('authzen_cert', 'record', 'writer', 'direct');
-- admin is held on record:* (an object-wildcard grant, MODEL_DESIGN §"Object Wildcards").
SELECT authz.model_add_rule('authzen_cert', 'record', 'admin',  'direct', p_allow_object_wildcard => true);
-- archived is a per-record flag: a user:* tuple on the record means "archived for everyone".
SELECT authz.model_add_rule('authzen_cert', 'record', 'archived', 'direct');
-- soft_delete is ONE conditional tuple user:* soft_delete record:* — true for any subject on
-- any record when the request's action.properties.soft is true (see the condition below).
SELECT authz.model_add_rule('authzen_cert', 'record', 'soft_delete', 'direct', p_allow_object_wildcard => true);

SELECT authz.model_add_rule('authzen_cert', 'record', 'read',   'computed', 'reader');
SELECT authz.model_add_rule('authzen_cert', 'record', 'read',   'computed', 'writer');
-- write: writer OR (admin AND archived) — admins may write archived records (rule 6), and
-- nothing else beyond their own writer grants (rule 4: bob cannot write the active record-1).
SELECT authz.model_add_rule('authzen_cert', 'record', 'write',  'computed', 'writer');
SELECT authz.model_add_rule('authzen_cert', 'record', 'write',  'computed', 'admin',    p_group_id => 1, p_group_op => 'intersection');
SELECT authz.model_add_rule('authzen_cert', 'record', 'write',  'computed', 'archived', p_group_id => 1, p_group_op => 'intersection');
-- delete: writer AND soft_delete — only a soft delete is allowed (rules 7, 8).
SELECT authz.model_add_rule('authzen_cert', 'record', 'delete', 'computed', 'writer',      p_group_id => 1, p_group_op => 'intersection');
SELECT authz.model_add_rule('authzen_cert', 'record', 'delete', 'computed', 'soft_delete', p_group_id => 1, p_group_op => 'intersection');

-- Who may hold the direct relations (the `[user]` / `[user:*]` of the DSL above).
SELECT authz.model_add_type_restriction('authzen_cert', 'record', 'reader', 'user');
SELECT authz.model_add_type_restriction('authzen_cert', 'record', 'writer', 'user');
SELECT authz.model_add_type_restriction('authzen_cert', 'record', 'admin',  'user');
SELECT authz.model_add_type_restriction('authzen_cert', 'record', 'archived',    'user', p_allow_wildcard => true);
SELECT authz.model_add_type_restriction('authzen_cert', 'record', 'soft_delete', 'user', p_allow_wildcard => true);

----------------------------------------------------------------------
-- The one request-property condition. pgauthzd passes the AuthZEN request's
-- properties in the context as {"action": {"name": "delete", "properties":
-- {"soft": true}}, ...}; `action` is declared required, so a request without
-- it (a core-level `delete`) fails closed and check_access_detailed reports
-- missing_context ["action"].
----------------------------------------------------------------------
SELECT authz.create_condition_sql('authzen_cert', 'soft_requested',
    $cond$ COALESCE(($1 #>> '{action,properties,soft}')::boolean, false) $cond$,
    '{"request": ["action"]}'::jsonb);

-- Render the model as OpenFGA-style DSL text to verify what was built.
SELECT authz.describe_model('authzen_cert');

-- Relation kinds (migration 0019), declared: what a subject CAN DO (permissions)
-- versus what it IS (relations). The kind is a declaration; whether a relation
-- takes tuples follows from its rules. Inference below only fills in what is
-- left undeclared.
SELECT authz.model_set_relation_metadata('authzen_cert', r, '{"kind": "permission"}')
  FROM unnest(ARRAY['delete', 'read', 'write']) AS r;
SELECT * FROM authz.infer_relation_kinds('authzen_cert', true);
