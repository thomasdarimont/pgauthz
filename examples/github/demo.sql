-- ============================================================================
-- GitHub Permission Model — Interactive Demo
-- ============================================================================
--
-- Prerequisites: run model.sql and seed.sql first (or use bootstrap.sh).
--
-- GitHub's repo permission hierarchy:
--
--   admin → maintainer → writer → triager → reader
--
-- Tip: run individual sections in a SQL console to see the results.
-- ============================================================================


-- ============================================================================
-- 1. VERIFY MODEL
-- ============================================================================

-- Show all imported model rules.
SELECT object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed
  FROM authz.models_view
 WHERE store = 'github'
 ORDER BY object_type, relation, rule_type;


-- ============================================================================
-- 2. ACCESS CHECKS — Role Hierarchy
-- ============================================================================
--
-- GitHub's role hierarchy: admin → maintainer → writer → triager → reader
-- Each role inherits all permissions of the roles below it.

-- anne: direct reader — can read but nothing else
SELECT authz.check_access('github', 'user', 'anne', 'reader', 'repo', 'openfga/openfga')
    AS "anne can read (direct)";

SELECT authz.check_access('github', 'user', 'anne', 'writer', 'repo', 'openfga/openfga')
    AS "anne cannot write";

-- beth: direct writer → triager → reader
SELECT authz.check_access('github', 'user', 'beth', 'writer', 'repo', 'openfga/openfga')
    AS "beth can write (direct)";
SELECT authz.check_access('github', 'user', 'beth', 'triager', 'repo', 'openfga/openfga')
    AS "beth can triage (writer → triager)";
SELECT authz.check_access('github', 'user', 'beth', 'reader', 'repo', 'openfga/openfga')
    AS "beth can read (writer → triager → reader)";
SELECT authz.check_access('github', 'user', 'beth', 'admin', 'repo', 'openfga/openfga')
    AS "beth cannot admin";


-- ============================================================================
-- 3. ACCESS CHECKS — Team-Based Access
-- ============================================================================
--
-- charles is a direct member of team openfga/core → admin on repo
-- diane is a member of team openfga/backend, which is nested in openfga/core

-- charles: core team → admin on repo
SELECT authz.check_access('github', 'user', 'charles', 'admin', 'repo', 'openfga/openfga')
    AS "charles can admin (core team member)";
SELECT authz.check_access('github', 'user', 'charles', 'reader', 'repo', 'openfga/openfga')
    AS "charles can read (admin → ... → reader)";

-- diane: backend team → core team (nested) → admin on repo
SELECT authz.check_access('github', 'user', 'diane', 'member', 'team', 'openfga/core')
    AS "diane is core team member (via backend nesting)";
SELECT authz.check_access('github', 'user', 'diane', 'admin', 'repo', 'openfga/openfga')
    AS "diane can admin (backend → core → admin)";


-- ============================================================================
-- 4. ACCESS CHECKS — Organization-Level Delegation
-- ============================================================================
--
-- erik is an org member. The org grants repo_admin to all its members.
-- The repo is owned by the org. So:
--   erik → org member → org repo_admin → repo admin (via TTU on owner)

SELECT authz.check_access('github', 'user', 'erik', 'member', 'organization', 'openfga')
    AS "erik is org member (direct)";

SELECT authz.check_access('github', 'user', 'erik', 'admin', 'repo', 'openfga/openfga')
    AS "erik can admin (org member → repo_admin → TTU)";

SELECT authz.check_access('github', 'user', 'erik', 'reader', 'repo', 'openfga/openfga')
    AS "erik can read (admin → ... → reader)";


-- ============================================================================
-- 5. SEARCH QUERIES
-- ============================================================================

-- What actions can each user perform on the repo?
SELECT * FROM authz.list_actions('github', 'user', 'anne',    'repo', 'openfga/openfga');
SELECT * FROM authz.list_actions('github', 'user', 'beth',    'repo', 'openfga/openfga');
SELECT * FROM authz.list_actions('github', 'user', 'charles', 'repo', 'openfga/openfga');
SELECT * FROM authz.list_actions('github', 'user', 'diane',   'repo', 'openfga/openfga');
SELECT * FROM authz.list_actions('github', 'user', 'erik',    'repo', 'openfga/openfga');

-- Who can admin the repo?
SELECT * FROM authz.list_subjects('github', 'user', 'admin', 'repo', 'openfga/openfga');

-- Who can read the repo?
SELECT * FROM authz.list_subjects('github', 'user', 'reader', 'repo', 'openfga/openfga');


-- ============================================================================
-- 6. PERMISSION MATRIX — All users × all roles
-- ============================================================================
--
-- This query produces a complete permission matrix showing which users
-- have which roles on the repo. Useful for auditing.

SELECT
    u.name AS "user",
    bool_or(r.name = 'admin')      AS admin,
    bool_or(r.name = 'maintainer') AS maintainer,
    bool_or(r.name = 'writer')     AS writer,
    bool_or(r.name = 'triager')    AS triager,
    bool_or(r.name = 'reader')     AS reader
  FROM (VALUES ('anne'), ('beth'), ('charles'), ('diane'), ('erik')) AS u(name)
  CROSS JOIN (VALUES ('admin'), ('maintainer'), ('writer'), ('triager'), ('reader')) AS r(name)
 WHERE authz.check_access('github', 'user', u.name, r.name, 'repo', 'openfga/openfga')
 GROUP BY u.name
 ORDER BY u.name;

-- Expected output:
--
--   user    | admin | maintainer | writer | triager | reader
--  ---------+-------+------------+--------+---------+--------
--   anne    | f     | f          | f      | f       | t
--   beth    | f     | f          | t      | t       | t
--   charles | t     | t          | t      | t       | t
--   diane   | t     | t          | t      | t       | t
--   erik    | t     | t          | t      | t       | t


-- ============================================================================
-- 7. MODIFYING ACCESS
-- ============================================================================

-- Promote anne from reader to maintainer
SELECT authz.delete_tuple('github', 'user', 'anne', 'reader', 'repo', 'openfga/openfga');
SELECT authz.write_tuple('github', 'user', 'anne', 'maintainer', 'repo', 'openfga/openfga');

SELECT authz.check_access('github', 'user', 'anne', 'maintainer', 'repo', 'openfga/openfga')
    AS "anne is now maintainer";
SELECT authz.check_access('github', 'user', 'anne', 'writer', 'repo', 'openfga/openfga')
    AS "anne can now write (maintainer → writer)";

-- Add a new user with direct triager access
SELECT authz.write_tuple('github', 'user', 'frank', 'triager', 'repo', 'openfga/openfga');

SELECT * FROM authz.list_actions('github', 'user', 'frank', 'repo', 'openfga/openfga');
-- => triager, reader

-- Remove frank's access
SELECT authz.delete_tuple('github', 'user', 'frank', 'triager', 'repo', 'openfga/openfga');

SELECT authz.check_access('github', 'user', 'frank', 'reader', 'repo', 'openfga/openfga')
    AS "frank can no longer read";


-- ============================================================================
-- 8. CLEANUP
-- ============================================================================
--
-- delete_store removes the store and all its tuples, model rules,
-- and conditions in one call.

SELECT authz.delete_store('github');
