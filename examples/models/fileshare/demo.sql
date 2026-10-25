-- ============================================================================
-- Advanced File Sharing — Showcase Queries
-- ============================================================================
--
-- Run after model.sql + seed.sql. The gdrive example walks through the
-- inheritance, groups and wildcards this model shares with it; this file
-- shows what the fileshare model adds around sharing.

-- ============================================================================
-- 1. TEMPORAL GATES — Download Quota (ADR 0012)
-- ============================================================================
--
-- doc.download = can_read, guarded by two gates over the ACTION LOG: at most
-- 100 downloads per UTC day per user, and at most 3 of the same document.
-- The file service records each download after it happened; the engine
-- never infers actions from decisions.

SELECT authz.check_access('fileshare', 'user', 'bob', 'download', 'doc', 'design_spec')
           AS "bob may download design_spec (no history)";

-- The file service records three downloads of design_spec by bob.
SELECT authz.record_event('fileshare', 'user', 'bob', 'download', 'doc', 'design_spec', 'response',
                          '{"output": {"bytes": 1048576}}')
  FROM generate_series(1, 3);

-- A fourth download of the SAME document is denied: 3 recorded + this one > 3.
SELECT authz.check_access('fileshare', 'user', 'bob', 'download', 'doc', 'design_spec')
           AS "bob may download design_spec again (after 3)";
-- Expected: f

-- Why? The graph allowed; the per-file gate vetoed (decision.reason = gate_denied).
SELECT e->>'reason' AS reason, e->>'gate' AS gate, e->>'scope' AS scope,
       e->>'observed' AS observed, e->>'threshold' AS threshold
  FROM jsonb_array_elements(
       authz.explain_access('fileshare', 'user', 'bob', 'download', 'doc', 'design_spec')->'trace') e
 WHERE e->>'rule_type' = 'temporal_gate';
-- Expected:
--   gate_passed | daily_download_quota | subject | 4 | 100
--   gate_denied | per_file_limit       | object  | 4 | 3

-- The per-file limit is per OBJECT: another readable document is still fine.
SELECT authz.check_access('fileshare', 'user', 'bob', 'download', 'doc', 'announcement')
           AS "bob may download announcement";

-- Enumeration agrees with the checks: design_spec is gone from bob's list.
SELECT object_id FROM authz.list_objects('fileshare', 'user', 'bob', 'download', 'doc') ORDER BY 1;

-- For a hard bound under concurrency the file service reserves instead of
-- check-then-record: decision + `request` event under a per-subject lock.
SELECT authz.reserve_event('fileshare', 'user', 'bob', 'download', 'doc', 'announcement')
           AS "reserve a download of announcement";


-- ============================================================================
-- 2. SHARING AS AN ACTION — grant rules with record_as, share-rate gates
-- ============================================================================
--
-- The share dialog renders from grant_options and saves through apply_grants.
-- Every grant and revoke that changes a tuple is recorded as a `share` event
-- of the ACTOR, and the share-rate gates on can_share count those events.

-- What may alice (can_share inherited from root) and frank (the owner) do?
SELECT 'alice' AS actor, relation, can_grant, can_revoke, requires, requires_revoke, grantee_types
  FROM authz.grant_options('fileshare', 'user', 'alice', 'doc', 'design_spec')
UNION ALL
SELECT 'frank', relation, can_grant, can_revoke, requires, requires_revoke, grantee_types
  FROM authz.grant_options('fileshare', 'user', 'frank', 'doc', 'design_spec')
 ORDER BY 1, 2;
-- Expected: alice grants viewer (not editor, not owner) and revokes nothing;
--           frank grants and revokes all three.

-- Frank saves the dialog: erin becomes an editor, bob is no longer a viewer.
SELECT authz.apply_grants('fileshare', 'user', 'frank',
    p_grants  => '[{"user_type":"user","user_id":"erin","relation":"editor","object_type":"doc","object_id":"design_spec"}]',
    p_revokes => '[{"user_type":"user","user_id":"bob","relation":"viewer","object_type":"doc","object_id":"design_spec"}]');
-- {"granted": 1, "revoked": 1}

-- The action log has both as frank's share events (the recorder is the role that called).
SELECT occurred_at, subject_id AS actor, payload->>'op' AS op, payload->>'relation' AS relation, payload->>'user_id' AS whom
  FROM authz.list_events('fileshare', p_action => 'share', p_subject_type => 'user', p_subject_id => 'frank')
 ORDER BY seq;

-- The gates on can_share see them: 2 of 20 shares this hour, 1 new person today on design_spec.
SELECT e->>'gate' AS gate, e->>'reason' AS reason, e->>'observed' AS observed, e->>'threshold' AS threshold
  FROM jsonb_array_elements(
       authz.explain_access('fileshare', 'user', 'frank', 'can_share', 'doc', 'design_spec')->'trace') e
 WHERE e->>'rule_type' = 'temporal_gate';


-- ============================================================================
-- 3. RELATION CONSTRAINTS — exactly one owner, at most ten editors
-- ============================================================================

-- How full is each capped relation on design_spec?
SELECT 'owner' AS relation, direct_count, max_direct, min_direct, direct_headroom
  FROM authz.relation_usage('fileshare', 'doc', 'design_spec', 'owner')
UNION ALL
SELECT 'editor', direct_count, max_direct, min_direct, direct_headroom
  FROM authz.relation_usage('fileshare', 'doc', 'design_spec', 'editor');

-- A second owner is refused (SQLSTATE ZA001; pgauthzd answers 409 relation_full) …
DO $$
BEGIN
    PERFORM authz.write_tuple('fileshare', 'user', 'gina', 'owner', 'doc', 'design_spec');
EXCEPTION WHEN SQLSTATE 'ZA001' THEN
    RAISE NOTICE 'refused as expected: %', SQLERRM;
END $$;

-- … and so is revoking the last one (ZA002 / 409 relation_floor).
DO $$
BEGIN
    PERFORM authz.revoke('fileshare', 'user', 'frank', 'user', 'frank', 'owner', 'doc', 'design_spec');
EXCEPTION WHEN SQLSTATE 'ZA002' THEN
    RAISE NOTICE 'refused as expected: %', SQLERRM;
END $$;

-- The handover is ONE batch, decided on its net result: frank out, gina in.
SELECT authz.apply_grants('fileshare', 'user', 'frank',
    p_grants  => '[{"user_type":"user","user_id":"gina","relation":"owner","object_type":"doc","object_id":"design_spec"}]',
    p_revokes => '[{"user_type":"user","user_id":"frank","relation":"owner","object_type":"doc","object_id":"design_spec"}]');
SELECT authz.check_access('fileshare', 'user', 'gina', 'can_change_owner', 'doc', 'design_spec') AS "gina owns design_spec";

-- The readable rendering of the whole model, constraints and gates included.
SELECT authz.describe_model('fileshare');


-- ============================================================================
-- 4. CLEANUP — back to the seed state
-- ============================================================================
SELECT authz.apply_grants('fileshare', 'user', 'gina',
    p_grants  => '[{"user_type":"user","user_id":"frank","relation":"owner","object_type":"doc","object_id":"design_spec"},
                   {"user_type":"user","user_id":"bob","relation":"viewer","object_type":"doc","object_id":"design_spec"}]',
    p_revokes => '[{"user_type":"user","user_id":"gina","relation":"owner","object_type":"doc","object_id":"design_spec"},
                   {"user_type":"user","user_id":"erin","relation":"editor","object_type":"doc","object_id":"design_spec"}]');
