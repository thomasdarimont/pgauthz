-- ============================================================================
-- Google Drive Permission Model — Interactive Demo
-- ============================================================================
--
-- Prerequisites: run model.sql and seed.sql first.
--
-- Tip: run individual sections in a SQL console to see the results.
-- ============================================================================

-- 1. VERIFY MODEL
SELECT object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed
FROM authz.models_view
WHERE store = 'gdrive'
ORDER BY object_type, relation, rule_type;


-- ============================================================================
-- 2. FOLDER OWNERSHIP — Inherited Permissions
-- ============================================================================
--
-- Alice owns the root folder. Ownership propagates via TTU:
--   root (owner) → can_write from parent → can_share from parent
-- But NOT can_change_owner (that requires ownership of the doc itself).

-- Alice can read (owner of root → viewer from parent chain → can_read)
SELECT authz.check_access('gdrive', 'user', 'alice', 'can_read', 'doc', 'design_spec')
           AS "alice can read design_spec";

-- Alice can write (owner of root → can_write from parent chain)
SELECT authz.check_access('gdrive', 'user', 'alice', 'can_write', 'doc', 'design_spec')
           AS "alice can write design_spec";

-- Alice can share (owner of root → can_share from parent chain)
SELECT authz.check_access('gdrive', 'user', 'alice', 'can_share', 'doc', 'design_spec')
           AS "alice can share design_spec";

-- Alice CANNOT change ownership (requires owner on the doc itself)
SELECT authz.check_access('gdrive', 'user', 'alice', 'can_change_owner', 'doc', 'design_spec')
           AS "alice cannot change_owner (not doc owner)";

-- Frank CAN change ownership (he is the doc owner)
SELECT authz.check_access('gdrive', 'user', 'frank', 'can_change_owner', 'doc', 'design_spec')
           AS "frank can change_owner (doc owner)";


-- ============================================================================
-- 3. DIRECT VIEWER
-- ============================================================================
--
-- Bob is a direct viewer of design_spec.
SELECT authz.check_access('gdrive', 'user', 'bob', 'can_read', 'doc', 'design_spec')
           AS "bob can read (direct viewer)";

-- Bob is a direct viewer of design_spec / no write access.
SELECT authz.check_access('gdrive', 'user', 'bob', 'can_write', 'doc', 'design_spec')
           AS "bob cannot write (viewer only)";


-- ============================================================================
-- 4. GROUP-BASED ACCESS — Userset Expansion
-- ============================================================================
--
-- Charlie is a member of the engineering group.
-- The engineering group is a viewer of the root folder.
-- Viewer propagates: root → projects → design_spec (via parent TTU).

SELECT authz.check_access('gdrive', 'user', 'charlie', 'can_read', 'doc', 'design_spec')
           AS "charlie can read (eng group → viewer on root → inherited)";

SELECT authz.check_access('gdrive', 'user', 'charlie', 'can_write', 'doc', 'design_spec')
           AS "charlie cannot write (viewer only)";


-- ============================================================================
-- 5. WILDCARD ACCESS — Public Folder
-- ============================================================================
--
-- The public/ folder has a wildcard viewer tuple (user:*).
-- This means ANY user — even one with no explicit permissions — can view
-- documents inside public/. The wildcard propagates through the folder
-- hierarchy via TTU (viewer from parent), just like normal viewer tuples.
--
-- The seed data contains:
--   write_tuple('gdrive', 'user', '*', 'viewer', 'folder', 'public')
--
-- This single tuple grants can_read to every user on every doc in public/.

-- Any arbitrary user can read the announcement (it's in public/)
SELECT authz.check_access('gdrive', 'user', 'stranger', 'can_read', 'doc', 'announcement')
           AS "stranger can read announcement (wildcard viewer on public/)";

SELECT authz.check_access('gdrive', 'user', 'anyone_at_all', 'can_read', 'doc', 'announcement')
           AS "anyone_at_all can read announcement too";

-- Wildcard grants read-only access — not write or share
SELECT authz.check_access('gdrive', 'user', 'stranger', 'can_write', 'doc', 'announcement')
           AS "stranger cannot write announcement";

-- Wildcard is scoped to public/ — does NOT leak into projects/
SELECT authz.check_access('gdrive', 'user', 'stranger', 'can_read', 'doc', 'design_spec')
           AS "stranger cannot read design_spec (not in public/)";

-- How does the wildcard resolve? Explain shows the trace:
SELECT authz.explain_access('gdrive',
                            'user', 'stranger', 'can_read', 'doc', 'announcement')
           AS "wildcard resolution trace";
-- => The trace shows: can_read → viewer from parent → wildcard tuple (*)

SELECT (authz.explain_access('gdrive',
                             'user', 'stranger', 'can_read', 'doc', 'announcement', null, true)) ->> 'summary'
           AS "wildcard resolution trace -> summary";
-- => The trace shows: can_read → viewer from parent → wildcard tuple (*)

-- ============================================================================
-- 6. SEARCH QUERIES
-- ============================================================================

-- What can Alice do on design_spec?
SELECT *
FROM authz.list_actions('gdrive', 'user', 'alice', 'doc', 'design_spec');
-- => can_read, can_share, can_write

-- What can Frank do on design_spec?
SELECT *
FROM authz.list_actions('gdrive', 'user', 'frank', 'doc', 'design_spec');
-- => can_change_owner, can_read, can_share, can_write

-- Which docs can Bob read?
SELECT *
FROM authz.list_objects('gdrive', 'user', 'bob', 'can_read', 'doc');
-- => design_spec

-- Which docs can Alice read?
SELECT *
FROM authz.list_objects('gdrive', 'user', 'alice', 'can_read', 'doc');
-- => design_spec, budget, announcement

-- Which docs can a stranger read?
SELECT *
FROM authz.list_objects('gdrive', 'user', 'stranger', 'can_read', 'doc');
-- => announcement

-- Who can read the design spec?
SELECT *
FROM authz.list_subjects('gdrive', 'user', 'can_read', 'doc', 'design_spec');
-- => alice, bob, charlie, frank

-- ============================================================================
-- 7. BATCH ACCESS CHECKS — AuthZEN Evaluations API
-- ============================================================================
--
-- check_access_batch evaluates multiple access checks in a single call.
-- Returns SETOF authz.access_check_result (one row per input check, same order).

-- Check all four permissions for Alice on design_spec in one call.
SELECT *
FROM authz.check_access_batch_typed('gdrive', ARRAY [
    ('user', 'alice', 'can_read', 'doc', 'design_spec'),
    ('user', 'alice', 'can_write', 'doc', 'design_spec'),
    ('user', 'alice', 'can_share', 'doc', 'design_spec'),
    ('user', 'alice', 'can_change_owner', 'doc', 'design_spec')
    ]::authz.access_check[]);
-- => (user, alice, can_read,         doc, design_spec, t)
--    (user, alice, can_write,        doc, design_spec, t)
--    (user, alice, can_share,        doc, design_spec, t)
--    (user, alice, can_change_owner, doc, design_spec, f)

-- Compare permissions across users for the same document.
-- Useful for rendering a sharing dialog or access audit.
SELECT *
FROM authz.check_access_batch_typed('gdrive', ARRAY [
    ('user', 'alice', 'can_read', 'doc', 'design_spec'),
    ('user', 'bob', 'can_read', 'doc', 'design_spec'),
    ('user', 'charlie', 'can_read', 'doc', 'design_spec'),
    ('user', 'frank', 'can_read', 'doc', 'design_spec'),
    ('user', 'stranger', 'can_read', 'doc', 'design_spec')
    ]::authz.access_check[]);
-- => decisions: t, t, t, t, f  (everyone except stranger)

-- Wildcard: check if various users can read the public announcement.
SELECT *
FROM authz.check_access_batch_typed('gdrive', ARRAY [
    ('user', 'alice', 'can_read', 'doc', 'announcement'),
    ('user', 'stranger', 'can_read', 'doc', 'announcement'),
    ('user', 'stranger', 'can_write', 'doc', 'announcement')
    ]::authz.access_check[]);
-- => decisions: t, t, f  (wildcard grants read-only, not write)

-- Short-circuit: "Does the user have ALL required permissions?"
-- deny_on_first_deny stops early when a check fails.
SELECT *
FROM authz.check_access_batch_typed('gdrive', ARRAY [
    ('user', 'bob', 'can_read', 'doc', 'design_spec'),
    ('user', 'bob', 'can_write', 'doc', 'design_spec'),
    ('user', 'bob', 'can_share', 'doc', 'design_spec')
    ]::authz.access_check[], p_semantic => 'deny_on_first_deny');
-- => decisions: t, f, NULL  (bob can read but not write — stops, never checks can_share)

-- Short-circuit: "Does the user have ANY of these permissions?"
-- permit_on_first_permit stops early when a check succeeds.
SELECT *
FROM authz.check_access_batch_typed('gdrive', ARRAY [
    ('user', 'stranger', 'can_write', 'doc', 'announcement'),
    ('user', 'stranger', 'can_share', 'doc', 'announcement'),
    ('user', 'stranger', 'can_read', 'doc', 'announcement')
    ]::authz.access_check[], p_semantic => 'permit_on_first_permit');
-- => decisions: f, f, t  (stranger can't write or share, but CAN read via wildcard)


-- ============================================================================
-- 8. EXPLAIN — Resolution Trace
-- ============================================================================

-- How does Charlie get can_read on design_spec?
SELECT authz.explain_access('gdrive',
                            'user', 'charlie', 'can_read', 'doc', 'design_spec');

-- How does a stranger get can_read on announcement? (wildcard)
SELECT authz.explain_access('gdrive',
                            'user', 'stranger', 'can_read', 'doc', 'announcement');


-- ============================================================================
-- 9. EXPLAIN — Successful Paths Only
-- ============================================================================
--
-- By default, explain_access shows all evaluated paths (both granted and
-- denied). Pass p_successful_only => true to see only the paths that
-- actually granted access — useful when the full trace is noisy.

-- Full trace (all paths):
SELECT authz.explain_access('gdrive',
                            'user', 'charlie', 'can_read', 'doc', 'design_spec') ->> 'summary'
           AS "full trace";

-- Successful paths only:
SELECT authz.explain_access('gdrive',
                            'user', 'charlie', 'can_read', 'doc', 'design_spec',
                            p_successful_only => true) ->> 'summary'
           AS "successful paths only";

-- Extract just the summary text (human-readable):
SELECT authz.explain_access('gdrive',
                            'user', 'stranger', 'can_read', 'doc', 'announcement',
                            p_successful_only => true) ->> 'summary'
           AS "wildcard successful path";
-- Shows only the chain: can_read → viewer from parent → wildcard tuple (*)


-- ============================================================================
-- 10. PERMISSION MATRIX
-- ============================================================================

SELECT u.name                               AS "user",
       bool_or(r.name = 'can_change_owner') AS change_owner,
       bool_or(r.name = 'can_write')        AS write,
       bool_or(r.name = 'can_share')        AS share,
       bool_or(r.name = 'can_read')         AS read
FROM (VALUES ('alice'), ('bob'), ('charlie'), ('frank'), ('stranger')) AS u(name)
         CROSS JOIN (VALUES ('can_change_owner'), ('can_write'), ('can_share'), ('can_read')) AS r(name)
WHERE authz.check_access('gdrive', 'user', u.name, r.name, 'doc', 'design_spec')
GROUP BY u.name
ORDER BY u.name;

-- Expected:
--   user    | change_owner | write | share | read
--  ---------+--------------+-------+-------+------
--   alice   | f            | t     | t     | t
--   bob     | f            | f     | f     | t
--   charlie | f            | f     | f     | t
--   frank   | t            | t     | t     | t


-- ============================================================================
-- 11. TEMPORAL GATES — Download Quota (ADR 0012)
-- ============================================================================
--
-- doc.download = can_read, guarded by two gates over the ACTION LOG: at most
-- 100 downloads per UTC day per user, and at most 3 of the same document.
-- The file service records each download after it happened; the engine
-- never infers actions from decisions.

-- Bob may download design_spec (he can read it) — no history yet.
SELECT authz.check_access('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec')
           AS "bob may download design_spec (no history)";

-- The file service records three downloads of design_spec by bob.
SELECT authz.record_event('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec', 'response',
                          '{"output": {"bytes": 1048576}}')
  FROM generate_series(1, 3);

-- A fourth download of the SAME document is denied: 3 recorded + this one > 3.
SELECT authz.check_access('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec')
           AS "bob may download design_spec again (after 3)";
-- Expected: f

-- Why? The graph allowed; the per-file gate vetoed (decision.reason = gate_denied).
SELECT e->>'reason' AS reason, e->>'gate' AS gate, e->>'scope' AS scope,
       e->>'observed' AS observed, e->>'threshold' AS threshold
  FROM jsonb_array_elements(
       authz.explain_access('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec')->'trace') e
 WHERE e->>'rule_type' = 'temporal_gate';
-- Expected:
--   gate_passed | daily_download_quota | subject | 4 | 100
--   gate_denied | per_file_limit       | object  | 4 | 3

-- The per-file limit is per OBJECT: another readable document is still fine
-- (alice's public folder makes announcement readable by everyone).
SELECT authz.check_access('gdrive', 'user', 'bob', 'download', 'doc', 'announcement')
           AS "bob may download announcement";

-- Enumeration agrees with the checks: design_spec is gone from bob's list.
SELECT object_id FROM authz.list_objects('gdrive', 'user', 'bob', 'download', 'doc') ORDER BY 1;

-- What did bob download today? (auditor view of the action log)
SELECT occurred_at, action, object_type, object_id, kind, recorded_by
  FROM authz.list_events('gdrive', p_subject_type => 'user', p_subject_id => 'bob');

-- For a hard bound under concurrency the file service reserves instead of
-- check-then-record: decision + `request` event under a per-subject lock.
SELECT authz.reserve_event('gdrive', 'user', 'bob', 'download', 'doc', 'announcement')
           AS "reserve a download of announcement";


-- ============================================================================
-- 12. CLEANUP
-- ============================================================================

SELECT authz.delete_store('gdrive');
