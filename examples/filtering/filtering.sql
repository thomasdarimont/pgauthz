-- filtering.sql — "Authorization as a JOIN": filter your own table by ReBAC
-- ============================================================================
--
-- The in-database answer to the list-filtering / "which rows can this user see?"
-- problem. Instead of an external engine emitting a SQL filter via partial
-- evaluation (and an ORM adapter translating it), you JOIN
-- authz.list_objects(...) directly against your own table — one query,
-- one round-trip, no dialect translation.
--
-- Prerequisites: the 'demo' store with model + seed loaded:
--   cat examples/models/demo/model.sql examples/models/demo/seed.sql | psql ...
--
-- Each statement is standalone — run them one at a time (IntelliJ: Ctrl/Cmd+Enter)
-- to see each result.

-- A stand-in for YOUR application table. In a real app this is your existing
-- documents table; here it is seeded with the demo store's document ids so the
-- JOIN has something to filter.
CREATE SCHEMA IF NOT EXISTS appdemo;
CREATE TABLE IF NOT EXISTS appdemo.documents (
    id         text PRIMARY KEY,
    title      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO appdemo.documents (id, title) VALUES
    ('doc_payroll_001',        'Payroll - March'),
    ('doc_acc_001',            'Accounting ledger'),
    ('doc_tax_001',            'Tax filing'),
    ('doc_client_001',         'Client deck'),
    ('doc_client_002',         'Client contract'),
    ('doc_client_private_001', 'Client private notes')
ON CONFLICT (id) DO NOTHING;


-- 1. Bob can_read → only his authorized rows (payroll, accounting, tax).
--    The authorization set is computed ONCE (MATERIALIZED), then the database
--    filters appdemo.documents against it.
WITH authorized AS MATERIALIZED (
    SELECT object_id, is_wildcard
      FROM authz.list_objects('demo','internal_user','bob','can_read','document')
)
SELECT d.id, d.title
  FROM appdemo.documents d
 WHERE EXISTS (SELECT 1 FROM authorized WHERE is_wildcard)   -- wildcard → all rows
    OR d.id IN (SELECT object_id FROM authorized)            -- else explicit grants
 ORDER BY d.id;


-- 2. nadia_auditor holds an object-wildcard viewer grant (document:*), so the
--    authorized set is a single is_wildcard row — and the filter returns ALL
--    rows via the is_wildcard branch (a naive id-JOIN would wrongly return none).
WITH authorized AS MATERIALIZED (
    SELECT object_id, is_wildcard
      FROM authz.list_objects('demo','internal_user','nadia_auditor','can_read','document')
)
SELECT d.id, d.title
  FROM appdemo.documents d
 WHERE EXISTS (SELECT 1 FROM authorized WHERE is_wildcard)
    OR d.id IN (SELECT object_id FROM authorized)
 ORDER BY d.id;


-- 3. A user with no grants → zero rows (the filter excludes everything).
WITH authorized AS MATERIALIZED (
    SELECT object_id, is_wildcard
      FROM authz.list_objects('demo','internal_user','nobody','can_read','document')
)
SELECT d.id, d.title
  FROM appdemo.documents d
 WHERE EXISTS (SELECT 1 FROM authorized WHERE is_wildcard)
    OR d.id IN (SELECT object_id FROM authorized)
 ORDER BY d.id;


-- Clean up the demo application table (the 'demo' authz store is left intact).
DROP SCHEMA appdemo CASCADE;
