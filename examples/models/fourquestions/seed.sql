-- ============================================================================
-- Four questions — Seed Data
-- ============================================================================
--
--   team:marketing      members alice, bob, dave
--   folder:campaign     editor  team:marketing#member          (share with marketing)
--                       blocked user:bob                       (except Bob)
--                       reviewer user:carol, expires in 7 days (external, read-only)
--                       reviewer user:erin,  expires in 7 days (external, has NOT accepted the NDA)
--   doc:brief, doc:budget   parent folder:campaign
--   payment:p1          requester dave, 12,000 (large)
--   payment:p2          requester dave,    500 (small)
--
--   Action log (what already happened, as the services recorded it):
--     carol  accept_nda   (response, recorded by svc:review-portal)

-- Roles are relationships
SELECT authz.write_tuple('fourq', 'user', 'alice', 'member', 'team', 'marketing');
SELECT authz.write_tuple('fourq', 'user', 'bob',   'member', 'team', 'marketing');
SELECT authz.write_tuple('fourq', 'user', 'dave',  'member', 'team', 'marketing');

-- Share the folder with the team — one tuple for the whole team, now and later
SELECT authz.write_tuple('fourq', 'team', 'marketing', 'editor', 'folder', 'campaign', p_user_relation => 'member');
-- … except Bob
SELECT authz.write_tuple('fourq', 'user', 'bob', 'blocked', 'folder', 'campaign');

-- External reviewers, read-only "until next Friday" — the sentence is spoken on
-- a Friday, so that is a week from load. Server-time expiry on the tuple:
-- enforced on every check, search and time-travel path, garbage-collected with
-- its audit history.
SELECT authz.write_tuple('fourq', 'user', 'carol', 'reviewer', 'folder', 'campaign',
    p_expires_at => now() + interval '7 days');
SELECT authz.write_tuple('fourq', 'user', 'erin', 'reviewer', 'folder', 'campaign',
    p_expires_at => now() + interval '7 days');

-- Documents inherit everything from the folder
SELECT authz.write_tuple('fourq', 'folder', 'campaign', 'parent', 'doc', 'brief');
SELECT authz.write_tuple('fourq', 'folder', 'campaign', 'parent', 'doc', 'budget');

-- Payments
SELECT authz.write_tuple('fourq', 'user', 'dave', 'requester', 'payment', 'p1');   -- 12,000
SELECT authz.write_tuple('fourq', 'user', 'dave', 'requester', 'payment', 'p2');   --    500

-- What already happened: carol accepted the NDA (the review portal recorded it)
SELECT authz.record_event('fourq', 'user', 'carol', 'accept_nda', p_kind => 'response',
    p_recorded_by => 'svc:review-portal');
