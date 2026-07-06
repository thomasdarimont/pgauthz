-- ============================================================================
-- Hello World — Interactive Demo
-- ============================================================================
--
-- Prerequisites: run model.sql and seed.sql first.
--
-- The full lifecycle in miniature: check, explain, search, revoke.
-- Tip: run individual sections in a SQL console to see the results.
-- ============================================================================


-- ============================================================================
-- 1. CHECK ACCESS
-- ============================================================================

-- Alice is an editor → can_write (and can_read).
SELECT authz.check_access('helloworld', 'user', 'alice', 'can_write', 'document', 'readme');
-- => true

-- Bob is a viewer → can_read, but NOT can_write.
SELECT authz.check_access('helloworld', 'user', 'bob', 'can_read',  'document', 'readme');
-- => true
SELECT authz.check_access('helloworld', 'user', 'bob', 'can_write', 'document', 'readme');
-- => false


-- ============================================================================
-- 2. EXPLAIN — why was access allowed?
-- ============================================================================

-- The short form; drop ->>'summary' for the full JSON trace tree.
SELECT authz.explain_access('helloworld', 'user', 'bob', 'can_read', 'document', 'readme')->>'summary';
--  user:bob → can_read → document:readme = ALLOWED (computed)
--    ✓ [direct_tuple] viewer on document:readme — tuple found
--  ✓ [computed] can_read on document:readme — can_read ← viewer


-- ============================================================================
-- 3. SEARCH — both directions
-- ============================================================================

-- Which documents can alice read?
SELECT * FROM authz.list_objects('helloworld', 'user', 'alice', 'can_read', 'document');
-- => readme

-- Who can read the readme?
SELECT * FROM authz.list_subjects('helloworld', 'user', 'can_read', 'document', 'readme');
-- => alice, bob


-- ============================================================================
-- 4. REVOKE — delete the tuple, and the permission is gone
-- ============================================================================

SELECT authz.delete_tuple('helloworld', 'user', 'bob', 'viewer', 'document', 'readme');
SELECT authz.check_access('helloworld', 'user', 'bob', 'can_read', 'document', 'readme');
-- => false

-- Put bob back so the demo is re-runnable.
SELECT authz.write_tuple('helloworld', 'user', 'bob', 'viewer', 'document', 'readme');
