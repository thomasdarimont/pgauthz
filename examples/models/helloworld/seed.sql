-- ============================================================================
-- Hello World — sample tuples
-- ============================================================================
--
-- Prerequisites: run model.sql first.
--
-- Alice edits the readme, Bob may only view it.
-- ============================================================================

SELECT authz.write_tuple('helloworld', 'user', 'alice', 'editor', 'document', 'readme');
SELECT authz.write_tuple('helloworld', 'user', 'bob',   'viewer', 'document', 'readme');
