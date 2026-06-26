-- demo_cel.sql — CEL (Common Expression Language) condition showcase
-- ============================================================================
--
-- Companion to demo.sql that shows conditions written in CEL (lang = 'cel')
-- instead of SQL. Kept separate because CEL requires the optional pg_cel
-- evaluator extension (extensions/pg-cel); demo.sql stays dependency-free.
--
-- Each statement below is standalone, so you can run them ONE AT A TIME in psql
-- or your IDE (in IntelliJ: put the caret on a statement and press Ctrl+Enter /
-- Cmd+Enter) and see each result.
--
-- Prerequisites:
--   1. The 'demo' store, model, and seed data (model.sql + seed.sql).
--   2. The pg_cel extension installed. Bring the stack up with CEL enabled:
--        PGAUTHZ_CEL=1 ./start.sh   # or: ./start.sh --cel
--        PGAUTHZ_CEL=1 ./init.sh
--      Without it, the INSERT below is rejected with
--      "uses lang=cel but no CEL evaluator is installed".
--
-- With pg_cel, the two context bags are exposed as the CEL variables request.*
-- and stored.*, so the cast-heavy SQL form from demo.sql:
--
--   ($1->>'current_time')::timestamptz
--       < ($2->>'grant_time')::timestamptz + ($2->>'grant_duration')::interval
--
-- becomes the cleaner CEL form below.


-- 1. Create a time-based condition in CEL: access expires after a grant window.
--    Note: CEL duration() takes a Go-style duration string ("2h"), not "2 hours".
INSERT INTO authz.conditions (store_id, name, expression, lang, required_context)
VALUES (
    authz._s('demo'),
    'non_expired_grant_cel',
    'timestamp(request.current_time) < timestamp(stored.grant_time) + duration(stored.grant_duration)',
    authz._cond_lang_cel(),
    '{"request": ["current_time"], "stored": ["grant_time", "grant_duration"]}'::jsonb
)
ON CONFLICT (store_id, name) DO NOTHING;


-- 2. Write a conditional tuple: Bob can view doc_temp_cel_001, but only for
--    2 hours from the grant time.
SELECT authz.write_tuple('demo',
    'internal_user', 'bob', 'viewer', 'document', 'doc_temp_cel_001',
    p_condition => 'non_expired_grant_cel',
    p_condition_context => '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2h"}'::jsonb
);


-- 3. Within the grant window (09:00–11:00) → allowed.
SELECT authz.check_access_with_context('demo',
    'internal_user', 'bob', 'viewer', 'document', 'doc_temp_cel_001',
    '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb);
-- => true


-- 4. After the window expires → denied.
SELECT authz.check_access_with_context('demo',
    'internal_user', 'bob', 'viewer', 'document', 'doc_temp_cel_001',
    '{"current_time": "2026-03-11T12:00:00Z"}'::jsonb);
-- => false


-- 5. Without context → denied (the CEL expression references request.current_time,
--    which is absent, so evaluation fails safely to deny).
SELECT authz.check_access('demo',
    'internal_user', 'bob', 'viewer', 'document', 'doc_temp_cel_001');
-- => false


-- 6. Inspect the stored CEL condition.
SELECT name, lang, expression
  FROM authz.conditions
 WHERE store_id = authz._s('demo')
   AND name = 'non_expired_grant_cel';


-- 7. Clean up the demo tuple (the 'non_expired_grant_cel' condition is left in
--    the store as a reference example).
DELETE FROM authz.tuples
 WHERE object_id = 'doc_temp_cel_001'
   AND object_type = authz._t('demo', 'document');
