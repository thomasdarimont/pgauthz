-- ============================================================================
-- ACME Customer Collaboration — Interactive Demo
-- ============================================================================
--
-- The four appendix-A evaluations from *Authorization in Action*, then the
-- chapter-9 patterns. Prerequisites: run model.sql and seed.sql first.
-- Tip: run individual sections in a SQL console to see the results.
-- ============================================================================

-- 1. THE MODEL — Cedar's schema + policies as one readable DSL
SELECT authz.describe_model('aia_acme');

-- ============================================================================
-- 2. APPENDIX A.6 — the book's is-authorized calls
-- ============================================================================
-- The request context has the book's shape (§9.8): device posture + time.

-- A.6.1 Alice owns q3-plan → ALLOW on every action (managed device)
SELECT a AS action,
       authz.check_access_with_context('aia_acme', 'employee', 'alice', a, 'document', 'q3-plan',
           '{"device": {"managed": true}, "time": {"hour": 14, "weekday": "Wednesday"}}') AS "alice (owner)"
FROM unnest(ARRAY['view', 'edit', 'share']) AS a;

-- A.6.2 Kate (CustCo) is in the customer readers team → ALLOW, no context needed:
-- the device rule scopes employees only.
SELECT authz.check_access('aia_acme', 'customer', 'kate', 'view', 'document', 'q3-plan') AS "kate views q3-plan";

-- A.6.3 Bob is on the employee readers team and q3-plan is delegatable → may share
SELECT authz.check_access_with_context('aia_acme', 'employee', 'bob', 'share', 'document', 'q3-plan',
    '{"device": {"managed": true}}') AS "bob shares delegatable q3-plan";

-- A.6.4 Bob from an unmanaged laptop → DENY: the global constraint overrides the readers grant
SELECT authz.check_access_with_context('aia_acme', 'employee', 'bob', 'view', 'document', 'q3-plan',
    '{"device": {"managed": false}}') AS "bob views from unmanaged device";

-- ============================================================================
-- 3. WHY? — explain the unmanaged denial (Cedar's determiningPolicies)
-- ============================================================================
SELECT authz.explain_access('aia_acme', 'employee', 'bob', 'view', 'document', 'q3-plan',
    '{"device": {"managed": false}}') ->> 'summary' AS why;

-- The same request WITHOUT context: not a plain deny but `conditional` — the
-- PEP forgot to send `device`. Cedar would skip the erroring forbid (or reject
-- the request under strict validation); pgauthz fails closed and says what is
-- missing.
SELECT authz.check_access_detailed('aia_acme', 'employee', 'bob', 'view', 'document', 'q3-plan')
       - 'evaluated_at' AS "no context → conditional";

-- ============================================================================
-- 4. CHAPTER-9 PATTERNS
-- ============================================================================

-- 9.3.3 Relationship permission: carol manages alice → views and edits alice's doc, cannot share it
SELECT a AS action,
       authz.check_access_with_context('aia_acme', 'employee', 'carol', a, 'document', 'q3-plan',
           '{"device": {"managed": true}, "time": {"hour": 14, "weekday": "Wednesday"}}') AS "carol (manager of owner)"
FROM unnest(ARRAY['view', 'edit', 'share']) AS a;

-- 9.1 "stricter constraints outside business hours": at 22:00 only the owner edits
SELECT who,
       authz.check_access_with_context('aia_acme', 'employee', who, 'edit', 'document', 'q3-plan',
           '{"device": {"managed": true}, "time": {"hour": 22, "weekday": "Wednesday"}}') AS "edits at 22:00"
FROM unnest(ARRAY['alice', 'carol', 'frank']) AS who;

-- 9.5.2 Membership permission: team:legal reviews every Legal-classified document.
-- One tuple on classification:legal; nda-custco inherits it through TTU.
SELECT authz.check_access_with_context('aia_acme', 'employee', 'dan', 'edit', 'document', 'nda-custco',
    '{"device": {"managed": true}, "time": {"hour": 14, "weekday": "Wednesday"}}') AS "dan (legal) edits the Legal doc",
       authz.check_access_with_context('aia_acme', 'employee', 'dan', 'view', 'document', 'q3-plan',
    '{"device": {"managed": true}}') AS "dan views the confidential doc";

-- 9.5.1 Discretionary vs delegatable: sharing needs the delegatable flag AND readership
SELECT authz.check_access_with_context('aia_acme', 'employee', 'bob', 'share', 'document', 'q3-plan',
    '{"device": {"managed": true}}') AS "reader shares delegatable doc";
SELECT authz.delete_tuple('aia_acme', 'employee', '*', 'delegatable', 'document', 'q3-plan');
SELECT authz.check_access_with_context('aia_acme', 'employee', 'bob', 'share', 'document', 'q3-plan',
    '{"device": {"managed": true}}') AS "… after clearing the flag";
SELECT authz.write_tuple('aia_acme', 'employee', '*', 'delegatable', 'document', 'q3-plan');

-- 9.7.1 Template link = one direct tuple (eve-view-q3-plan)
SELECT authz.check_access_with_context('aia_acme', 'employee', 'eve', 'view', 'document', 'q3-plan',
    '{"device": {"managed": true}}') AS "eve via direct-view link";

-- 9.7.2 Overrides
--   restricted workspace: readers exist, only the owner views
SELECT authz.check_access_with_context('aia_acme', 'employee', 'bob', 'view', 'document', 'legal-review',
    '{"device": {"managed": true}}') AS "bob (reader) on restricted workspace",
       authz.check_access_with_context('aia_acme', 'employee', 'dan', 'view', 'document', 'legal-review',
    '{"device": {"managed": true}}') AS "dan (owner) on restricted workspace";
--   share lock: not even the owner
SELECT authz.check_access_with_context('aia_acme', 'employee', 'alice', 'share', 'document', 'board-deck',
    '{"device": {"managed": true}}') AS "owner shares share-locked doc";
--   temporary editor: frank's grant carries a server-time expiry
SELECT t.user_id, r.name AS relation, t.object_id, t.expires_at
  FROM authz.tuples t JOIN authz.relations r ON r.id = t.relation
 WHERE t.store_id = authz._s('aia_acme') AND t.user_id = 'frank';

-- ============================================================================
-- 5. ENUMERATION — what Cedar cannot answer without partial evaluation
-- ============================================================================
-- Which documents may bob view from a managed device? And who may view q3-plan?
SELECT object_id FROM authz.list_objects('aia_acme', 'employee', 'bob', 'view', 'document',
    '{"device": {"managed": true}}');
SELECT subject_id FROM authz.list_subjects('aia_acme', 'employee', 'view', 'document', 'q3-plan',
    '{"device": {"managed": true}}');
SELECT subject_id FROM authz.list_subjects('aia_acme', 'customer', 'view', 'document', 'q3-plan');
