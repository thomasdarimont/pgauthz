-- ============================================================================
-- Advanced File Sharing — the gdrive model plus everything a real product
-- adds around sharing
-- ============================================================================
--
-- Derived from examples/models/gdrive (folders, documents, groups, inherited
-- access). gdrive stays the faithful Google-Drive model; this example is the
-- showcase for the pgauthz features a file-sharing product grows into:
--
--   - Temporal gates on doc.download (ADR 0012): a daily quota and a per-file
--     limit over the action log the file service records to
--   - Sharing as an action (grant rules with record_as, migration 0027): every
--     grant / revoke is an event of the actor, and a share-rate gate on
--     can_share bounds it — at most 20 shares an hour per person, at most 10
--     new people per document per day per sharer
--   - Relation constraints (migrations 0025/0026): exactly one owner per
--     document (handover as one batch), at most 10 direct editors with an
--     advisory ceiling of 50 effective ones
--   - An editor role (editors write, owners share; "editors can share" is off)
--   - Expiring shares (seed.sql: a reviewer for seven days)
--
-- OpenFGA DSL equivalent (pgauthz additions as comments, as describe_model renders them):
--
--   type user
--
--   type group
--     relations
--       define member: [user]
--
--   type folder
--     relations
--       define owner:  [user]
--       define parent: [folder]
--       define viewer: [user, user:*, group#member] or owner or viewer from parent
--       define can_create_file: owner
--       define can_write: owner or can_write from parent
--       define can_share: owner or can_share from parent
--       # grant viewer requires can_share, recorded as share
--
--   type doc
--     relations
--       define owner:  [user]
--       define parent: [folder]
--       define viewer: [user, user:*, group#member]
--       define editor: [user, group#member]
--       define can_change_owner: owner
--       define can_read:  viewer or editor or owner or viewer from parent
--       define can_share: owner or can_share from parent
--       define can_write: owner or editor or can_write from parent
--       define download: can_read
--       define share   # the action grants and revokes are recorded as
--       # gate daily_download_quota: at most 100 downloads per UTC day
--       #   count_within{calendar: "day", tz: "UTC", kind: "response", max: 100, plus: 1}
--       # gate per_file_limit: at most 3 downloads of THIS document per UTC day
--       #   count_within{calendar: "day", tz: "UTC", scope: "object", kind: "response", max: 3, plus: 1}
--       # gate share_rate on can_share: at most 20 shares per hour per actor
--       #   count_within{window: "1h", action: "share", max: 20, plus: 1}
--       # gate share_spread on can_share: at most 10 new people per document per UTC day (per sharer)
--       #   count_distinct_within{calendar: "day", tz: "UTC", scope: "object", action: "share", key: "payload.user_id", max: 10, plus: 1}
--       # grant viewer requires can_share (revoke requires owner), recorded as share
--       # grant editor requires owner, recorded as share
--       # grant owner requires can_change_owner, recorded as share
--       # constraint owner: min_direct 1, max_direct 1
--       # constraint editor: max_direct 10, max_effective 50

DO $$
BEGIN
    PERFORM authz.delete_store('fileshare', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN
    NULL;  -- store did not exist yet
END $$;
SELECT authz.create_store('fileshare', 'Advanced file sharing: gdrive plus quotas, share limits and ownership rules');

-- ── Types and relations ──────────────────────────────────────────────────────
SELECT authz.model_register_type('fileshare', t) FROM unnest(ARRAY['user', 'group', 'folder', 'doc']) t;
SELECT authz.model_register_relation('fileshare', r)
  FROM unnest(ARRAY['member', 'owner', 'parent', 'viewer', 'editor']) r;
SELECT authz.model_register_relation('fileshare', r, NULL, '{"kind": "permission"}')
  FROM unnest(ARRAY['can_create_file', 'can_change_owner', 'can_read', 'can_share', 'can_write', 'download']) r;
-- `share`: the action a grant or revoke is recorded as. A permission kind
-- (nobody is assigned "share"); it exists so the action log has a vocabulary
-- entry and gates can count it.
SELECT authz.model_register_relation('fileshare', 'share', 'the sharing action: a grant or revoke made through the share dialog', '{"kind": "permission"}');

-- ── group ────────────────────────────────────────────────────────────────────
SELECT authz.model_add_rule('fileshare', 'group', 'member', 'direct');
SELECT authz.model_add_type_restriction('fileshare', 'group', 'member', 'user');

-- ── folder ───────────────────────────────────────────────────────────────────
SELECT authz.model_add_rule('fileshare', 'folder', 'owner',  'direct');
SELECT authz.model_add_rule('fileshare', 'folder', 'parent', 'direct');
SELECT authz.model_add_rule('fileshare', 'folder', 'viewer', 'direct');
SELECT authz.model_add_rule('fileshare', 'folder', 'viewer', 'computed', 'owner');
SELECT authz.model_add_rule('fileshare', 'folder', 'viewer', 'ttu', NULL, 'parent', 'viewer');
SELECT authz.model_add_rule('fileshare', 'folder', 'can_create_file', 'computed', 'owner');
SELECT authz.model_add_rule('fileshare', 'folder', 'can_write', 'computed', 'owner');
SELECT authz.model_add_rule('fileshare', 'folder', 'can_write', 'ttu', NULL, 'parent', 'can_write');
SELECT authz.model_add_rule('fileshare', 'folder', 'can_share', 'computed', 'owner');
SELECT authz.model_add_rule('fileshare', 'folder', 'can_share', 'ttu', NULL, 'parent', 'can_share');
SELECT authz.model_add_type_restriction('fileshare', 'folder', 'owner',  'user');
SELECT authz.model_add_type_restriction('fileshare', 'folder', 'parent', 'folder');
SELECT authz.model_add_type_restriction('fileshare', 'folder', 'viewer', 'user');
SELECT authz.model_add_type_restriction('fileshare', 'folder', 'viewer', 'user', p_allow_wildcard => true);
SELECT authz.model_add_type_restriction('fileshare', 'folder', 'viewer', 'group', p_allowed_user_relation => 'member');

-- ── doc ──────────────────────────────────────────────────────────────────────
SELECT authz.model_add_rule('fileshare', 'doc', 'owner',  'direct');
SELECT authz.model_add_rule('fileshare', 'doc', 'parent', 'direct');
SELECT authz.model_add_rule('fileshare', 'doc', 'viewer', 'direct');
SELECT authz.model_add_rule('fileshare', 'doc', 'editor', 'direct');
SELECT authz.model_add_rule('fileshare', 'doc', 'can_change_owner', 'computed', 'owner');
SELECT authz.model_add_rule('fileshare', 'doc', 'can_read', 'computed', 'viewer');
SELECT authz.model_add_rule('fileshare', 'doc', 'can_read', 'computed', 'editor');
SELECT authz.model_add_rule('fileshare', 'doc', 'can_read', 'computed', 'owner');
SELECT authz.model_add_rule('fileshare', 'doc', 'can_read', 'ttu', NULL, 'parent', 'viewer');
SELECT authz.model_add_rule('fileshare', 'doc', 'can_share', 'computed', 'owner');
SELECT authz.model_add_rule('fileshare', 'doc', 'can_share', 'ttu', NULL, 'parent', 'can_share');
SELECT authz.model_add_rule('fileshare', 'doc', 'can_write', 'computed', 'owner');
SELECT authz.model_add_rule('fileshare', 'doc', 'can_write', 'computed', 'editor');
SELECT authz.model_add_rule('fileshare', 'doc', 'can_write', 'ttu', NULL, 'parent', 'can_write');
SELECT authz.model_add_rule('fileshare', 'doc', 'download', 'computed', 'can_read');   -- the action the file service records
SELECT authz.model_add_type_restriction('fileshare', 'doc', 'owner',  'user');
SELECT authz.model_add_type_restriction('fileshare', 'doc', 'parent', 'folder');
SELECT authz.model_add_type_restriction('fileshare', 'doc', 'viewer', 'user');
SELECT authz.model_add_type_restriction('fileshare', 'doc', 'viewer', 'user', p_allow_wildcard => true);
SELECT authz.model_add_type_restriction('fileshare', 'doc', 'viewer', 'group', p_allowed_user_relation => 'member');
SELECT authz.model_add_type_restriction('fileshare', 'doc', 'editor', 'user');
SELECT authz.model_add_type_restriction('fileshare', 'doc', 'editor', 'group', p_allowed_user_relation => 'member');

-- ── Temporal gates on doc.download (ADR 0012) ────────────────────────────────
-- RULE OF THUMB: a gate answers a PERMISSION question ("may this happen
-- now, given what already happened?") that a security/compliance owner
-- wants enforced centrally. Anything that decides an OUTCOME — which
-- account to debit, whether to retry, the next workflow state — belongs in
-- the application, not here. Gates are veto-only backstops, not a workflow
-- engine, and they bound RECORDED actions: keep the recorder reliable.
--
-- Both hang on doc#download and are evaluated after the graph allows, over
-- the download events the file service records (authz.record_event) AFTER
-- each download (kind = response: completed downloads count, not attempts).
-- "plus: 1" counts the request being decided, so the caps are inclusive of
-- it. See docs/MODEL_DESIGN.md §17.
SELECT authz.add_gate('fileshare', 'doc', 'download', 'daily_download_quota', '{
  "description": "at most 100 downloads per UTC day",
  "all_of": [{"count_within": {"calendar": "day", "tz": "UTC", "kind": "response", "max": 100, "plus": 1}}]}');
SELECT authz.add_gate('fileshare', 'doc', 'download', 'per_file_limit', '{
  "description": "at most 3 downloads of this document per UTC day",
  "all_of": [{"count_within": {"calendar": "day", "tz": "UTC", "scope": "object", "kind": "response", "max": 3, "plus": 1}}]}');

-- ── Sharing as an action (grant rules + record_as, migrations 0017 / 0027) ───
-- Who may hand a relation out: viewer needs can_share (owner, or inherited
-- from the folder), taking a viewer away on a doc needs the owner; editors
-- are handed out by owners only ("editors can share" is off); ownership is
-- handed over by the current owner (can_change_owner). Every grant and
-- revoke that changes a tuple is recorded for the ACTOR as a `share` event
-- (payload: op, relation, user_type, user_id, …), so the gates below see it.
SELECT authz.model_add_grant_rule('fileshare', 'folder', 'viewer', 'can_share', p_record_as => 'share');
SELECT authz.model_add_grant_rule('fileshare', 'doc',    'viewer', 'can_share', p_requires_revoke => 'owner', p_record_as => 'share');
SELECT authz.model_add_grant_rule('fileshare', 'doc',    'editor', 'owner', p_record_as => 'share');
SELECT authz.model_add_grant_rule('fileshare', 'doc',    'owner',  'can_change_owner', p_record_as => 'share');

-- The share-rate gates hang on can_share — the right grant checks before it
-- writes — and count `share` events: a person shares at most 20 times an
-- hour, and hands one document to at most 10 new people a day (distinct
-- grantees among the sharer's share events on this document — gates decide
-- for the checked principal; revokes carry op=revoke and are kept out by
-- match).
SELECT authz.add_gate('fileshare', 'doc', 'can_share', 'share_rate', '{
  "description": "at most 20 shares per hour per person",
  "all_of": [{"count_within": {"window": "1h", "action": "share", "max": 20, "plus": 1}}]}');
SELECT authz.add_gate('fileshare', 'doc', 'can_share', 'share_spread', '{
  "description": "at most 10 new people per document per UTC day, per sharer",
  "all_of": [{"count_distinct_within": {"calendar": "day", "tz": "UTC", "scope": "object", "action": "share",
                                        "match": {"op": "grant"}, "key": "payload.user_id", "max": 10, "plus": 1}}]}');

-- ── Relation constraints (migrations 0025 / 0026) ────────────────────────────
-- A document has exactly one owner: a second owner tuple is refused (SQLSTATE
-- ZA001 / 409 relation_full), revoking the last one is refused (ZA002 / 409
-- relation_floor), and a handover is one apply_grants batch (revoke the old
-- owner, grant the new one), decided on its net result. At most 10 direct
-- editors per document; the advisory ceiling of 50 effective editors (direct
-- plus group members) is what relation_usage reports headroom against.
SELECT authz.model_set_relation_constraint('fileshare', 'doc', 'owner',  p_max_direct => 1, p_min_direct => 1);
SELECT authz.model_set_relation_constraint('fileshare', 'doc', 'editor', p_max_direct => 10, p_max_effective => 50);
