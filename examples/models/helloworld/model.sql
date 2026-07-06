-- ============================================================================
-- Hello World — the smallest useful pgauthz model
-- ============================================================================
--
-- Documents have editors and viewers; both may read, only editors may write.
-- This is the model from the README's "A complete example first" tour —
-- the minimal shape that still shows how ReBAC composes:
--
--   - Direct relations (viewer, editor — granted by tuples)
--   - Computed relations (can_read ← viewer OR editor; can_write ← editor)
--
-- OpenFGA DSL equivalent:
--
--   type user
--
--   type document
--     relations
--       define viewer: [user]
--       define editor: [user]
--       define can_read: viewer or editor
--       define can_write: editor
--
-- ============================================================================

----------------------------------------------------------------------
-- Store. Dropped first so this file is idempotent — re-running it
-- resets the helloworld store from scratch (it is a sandbox, so the
-- audit history is purged too).
----------------------------------------------------------------------
DO $$
BEGIN
    PERFORM authz.delete_store('helloworld', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN
    NULL;  -- store did not exist yet
END $$;
SELECT authz.create_store('helloworld');

----------------------------------------------------------------------
-- Types and relations.
----------------------------------------------------------------------
SELECT authz.model_register_type('helloworld', 'user');
SELECT authz.model_register_type('helloworld', 'document');

SELECT authz.model_register_relation('helloworld', 'viewer');
SELECT authz.model_register_relation('helloworld', 'editor');
SELECT authz.model_register_relation('helloworld', 'can_read');
SELECT authz.model_register_relation('helloworld', 'can_write');

----------------------------------------------------------------------
-- Rules. 'direct' = granted by a tuple; 'computed' = implied by
-- another relation on the same object.
----------------------------------------------------------------------
SELECT authz.model_add_rule('helloworld', 'document', 'viewer',    'direct');
SELECT authz.model_add_rule('helloworld', 'document', 'editor',    'direct');
SELECT authz.model_add_rule('helloworld', 'document', 'can_read',  'computed', 'viewer');
SELECT authz.model_add_rule('helloworld', 'document', 'can_read',  'computed', 'editor');
SELECT authz.model_add_rule('helloworld', 'document', 'can_write', 'computed', 'editor');

-- Render the model as OpenFGA-style DSL text to verify what was built.
SELECT authz.describe_model('helloworld');
