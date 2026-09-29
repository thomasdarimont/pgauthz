-- ============================================================================
-- Four questions — the pitch's "killer example", runnable
-- ============================================================================
--
--   "Share this folder with the marketing team, except Bob; give external
--    reviewers read-only until next Friday, but only once they have accepted the
--    NDA; cap downloads at three a day; and any payment over 10k needs two
--    distinct approvers."
--
-- One sentence, four kinds of rule — and every classic model answers only
-- one of the four questions:
--
--   Who are you?                     RBAC   → roles are relationships here (team#member)
--   How are you related to this?     ReBAC  → the graph: team → folder → doc, BUT NOT blocked
--   What is true right now?          ABAC   → expiry on the reviewer's tuple ("until next Friday")
--   What has already happened?       gates  → NDA accepted first, three downloads a day,
--                                             two distinct approvers (and not yourself)
--
-- Rule by rule:
--   share with marketing      team:marketing#member → editor → folder      (userset)
--   except Bob                user:bob → blocked → folder; can_* = editor BUT NOT blocked
--   reviewers, until next Friday user:carol → reviewer → folder, expires_at = +7 days
--   only once NDA accepted    gate nda_first on doc#review: formerly_within(accept_nda, 30 days)
--   three downloads a day     gate three_a_day on doc#download: count_within(calendar day)
--   > 10k needs 2 approvers   gate four_eyes on payment#execute_large:
--                               count_distinct_within(approval_received, key payload.input.approver, min 2)
--                               AND count_within(approval_received, match approver = $request.self, max 0)
--                               — none of the approvals may be the executor's own
--
-- Two modelling decisions worth reading:
--   * Reviewers are checked on `review`, employees on `can_read`. A gate hangs
--     on the question asked (doc#review), so the NDA requirement never touches
--     the marketing team; the external review portal asks `review`.
--   * "Over 10k" is a distinct action (`execute_large`), not a threshold inside
--     the gate: gates are AND-only vetoes, and "small OR (large AND approved)"
--     is not expressible. Risk tiers as separate actions is the same advice as
--     view/edit/share instead of doc:all — the payments service asks the one
--     that matches the amount.
--
-- OpenFGA DSL equivalent (describe_model renders the same):
--
--   type user
--   type team
--     relations
--       define member: [user]
--   type folder
--     relations
--       define editor:   [user, team#member]
--       define reviewer: [user]
--       define blocked:  [user]
--       define can_edit: editor but not blocked
--       define can_read: editor but not blocked
--       define review:   reviewer but not blocked
--   type doc
--     relations
--       define parent:   [folder]
--       define can_edit: can_edit from parent
--       define can_read: can_read from parent
--       define review:   review from parent
--       define download: can_read or review
--       # gate nda_first:   formerly_within{window: "30 days", action: accept_nda, kind: response, recorded_by: [svc:review-portal]}
--       # gate three_a_day: count_within{calendar: day, tz: UTC, kind: response, max: 3, plus: 1}
--   type payment
--     relations
--       define requester:     [user]
--       define execute:       requester
--       define execute_large: requester
--       # gate four_eyes: count_distinct_within{...key: payload.input.approver, min: 2}
--       #                  AND count_within{approval_received, match: {input.approver: $request.self}, max: 0}

DO $$
BEGIN
    PERFORM authz.delete_store('fourq', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN
    NULL;  -- store did not exist yet
END $$;
SELECT authz.create_store('fourq', 'Four questions: the pitch example');

-- Types
SELECT authz.model_register_type('fourq', 'user');
SELECT authz.model_register_type('fourq', 'team');
SELECT authz.model_register_type('fourq', 'folder');
SELECT authz.model_register_type('fourq', 'doc');
SELECT authz.model_register_type('fourq', 'payment');

-- Relations (structural links, roles, permissions — and the action vocabulary
-- the gates count: accept_nda, approve, approval_received, download)
SELECT authz.model_register_relation('fourq', r)
  FROM unnest(ARRAY['member', 'editor', 'reviewer', 'blocked', 'parent',
                    'can_edit', 'can_read', 'review', 'download',
                    'requester', 'execute', 'execute_large',
                    'accept_nda', 'approval_received']) AS r;

-- team
SELECT authz.model_add_rule('fourq', 'team', 'member', 'direct');
SELECT authz.model_add_type_restriction('fourq', 'team', 'member', 'user');

-- folder: who is granted what, and the exclusion for Bob
SELECT authz.model_add_rule('fourq', 'folder', 'editor',   'direct');
SELECT authz.model_add_rule('fourq', 'folder', 'reviewer', 'direct');
SELECT authz.model_add_rule('fourq', 'folder', 'blocked',  'direct');
SELECT authz.model_add_type_restriction('fourq', 'folder', 'editor', 'user');
SELECT authz.model_add_type_restriction('fourq', 'folder', 'editor', 'team', p_allowed_user_relation => 'member');
SELECT authz.model_add_type_restriction('fourq', 'folder', 'reviewer', 'user');
SELECT authz.model_add_type_restriction('fourq', 'folder', 'blocked',  'user');
-- can_edit = editor BUT NOT blocked
SELECT authz.model_add_rule('fourq', 'folder', 'can_edit', 'computed', p_computed_relation => 'editor',  p_group_id => 1, p_group_op => 'exclusion');
SELECT authz.model_add_rule('fourq', 'folder', 'can_edit', 'computed', p_computed_relation => 'blocked', p_group_id => 1, p_group_op => 'exclusion', p_negated => true);
-- can_read = editor BUT NOT blocked   (the team reads and edits; reviewers use `review`)
SELECT authz.model_add_rule('fourq', 'folder', 'can_read', 'computed', p_computed_relation => 'editor',  p_group_id => 1, p_group_op => 'exclusion');
SELECT authz.model_add_rule('fourq', 'folder', 'can_read', 'computed', p_computed_relation => 'blocked', p_group_id => 1, p_group_op => 'exclusion', p_negated => true);
-- review = reviewer BUT NOT blocked
SELECT authz.model_add_rule('fourq', 'folder', 'review', 'computed', p_computed_relation => 'reviewer', p_group_id => 1, p_group_op => 'exclusion');
SELECT authz.model_add_rule('fourq', 'folder', 'review', 'computed', p_computed_relation => 'blocked',  p_group_id => 1, p_group_op => 'exclusion', p_negated => true);

-- doc: everything is inherited from the folder
SELECT authz.model_add_rule('fourq', 'doc', 'parent', 'direct');
SELECT authz.model_add_type_restriction('fourq', 'doc', 'parent', 'folder');
SELECT authz.model_add_rule('fourq', 'doc', 'can_edit', 'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'can_edit');
SELECT authz.model_add_rule('fourq', 'doc', 'can_read', 'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'can_read');
SELECT authz.model_add_rule('fourq', 'doc', 'review',   'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'review');
SELECT authz.model_add_rule('fourq', 'doc', 'download', 'computed', p_computed_relation => 'can_read');
SELECT authz.model_add_rule('fourq', 'doc', 'download', 'computed', p_computed_relation => 'review');

-- payment: the requester executes; the amount tier is the action asked
SELECT authz.model_add_rule('fourq', 'payment', 'requester',     'direct');
SELECT authz.model_add_type_restriction('fourq', 'payment', 'requester', 'user');
SELECT authz.model_add_rule('fourq', 'payment', 'execute',       'computed', p_computed_relation => 'requester');
SELECT authz.model_add_rule('fourq', 'payment', 'execute_large', 'computed', p_computed_relation => 'requester');

-- The action log's projection for approvals: the payments service records,
-- on the REQUESTER's behalf, one `approval_received` per approval, naming the
-- approver. The schema makes that field mandatory, so the gate can count it.
SELECT authz.model_set_payload_schema('fourq', 'approval_received',
    '{"required": {"input.approver": "string"}, "optional": {"input.amount": "number"}}');

-- ── Gates: what has already happened ────────────────────────────────────────
-- Reviewers must have accepted the NDA (recorded by the review portal) first —
-- a 30-day re-acknowledgement, which also keeps the gate window inside the
-- event retention the fixtures assume (the retention guard is database-wide).
SELECT authz.add_gate('fourq', 'doc', 'review', 'nda_first', '{
  "description": "reviewers must have accepted the NDA within the last 30 days",
  "all_of": [{"formerly_within": {"window": "30 days", "action": "accept_nda", "kind": "response",
                                  "recorded_by": ["svc:review-portal"]}}]}');

-- At most three downloads per UTC day, per principal, across all documents.
SELECT authz.add_gate('fourq', 'doc', 'download', 'three_a_day', '{
  "description": "at most 3 downloads per UTC day",
  "all_of": [{"count_within": {"calendar": "day", "tz": "UTC", "kind": "response", "max": 3, "plus": 1}}]}');

-- A large payment needs two DISTINCT approvers on THIS payment — and the
-- executor may not be one of them (separation of duties). Both clauses read
-- the SAME approval events: clause 1 counts distinct approvers, clause 2
-- requires that none of them name the caller. The caller's id comes from the
-- request context (`$request.self`, supplied by the PEP that also records the
-- approvals); a check without it fails closed (gate_missing_context), it does
-- not quietly pass.
SELECT authz.add_gate('fourq', 'payment', 'execute_large', 'four_eyes', '{
  "description": "two distinct approvers on this payment, none of them yourself",
  "all_of": [
    {"count_distinct_within": {"window": "30 days", "action": "approval_received", "scope": "object",
                               "kind": "response", "key": "payload.input.approver", "min": 2,
                               "recorded_by": ["svc:payments"]}},
    {"count_within": {"window": "30 days", "action": "approval_received", "scope": "object",
                      "kind": "response", "match": {"input.approver": "$request.self"}, "max": 0,
                      "recorded_by": ["svc:payments"]}}
  ]}');

SELECT authz.describe_model('fourq');
