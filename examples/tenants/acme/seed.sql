-- Test data for the ACME tenant's stores: the example models' own seeds
-- replayed into the tenant's stores (the fixture stores demo, todo and
-- fileshare, loaded by tests/test.sh — the demo's engagement eng_42 with its
-- tax team and client org is the tax story), plus the tenant's own people
-- so their "own access" tests in the console have something to show.
-- Idempotent (write_tuple upserts); run by setup.sh after setup.sql.

-- Replay a store's live tuples into another store with the same model:
-- names resolved from the catalog, conditions by name (apply_model carried
-- the condition definitions), expiry kept; namespaced types (a per-app
-- namespace, written as that app's role only) are left out.
CREATE OR REPLACE FUNCTION pg_temp.replay_tuples(p_from text, p_to text) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE r record; n integer := 0;
BEGIN
    FOR r IN
        SELECT ut.name AS user_type, t.user_id, ur.name AS user_relation, rl.name AS relation,
               ot.name AS object_type, t.object_id, c.name AS condition_name, t.condition_context, t.expires_at
          FROM authz.tuples t
          JOIN authz.types     ut ON ut.id = t.user_type
          JOIN authz.types     ot ON ot.id = t.object_type
          JOIN authz.relations rl ON rl.id = t.relation
          LEFT JOIN authz.relations  ur ON ur.id = t.user_relation
          LEFT JOIN authz.conditions c  ON c.id = t.condition_id
         WHERE t.store_id = authz._s(p_from)
           AND (t.expires_at IS NULL OR t.expires_at > now())
           AND ut.namespace IS NULL AND ot.namespace IS NULL   -- not the per-app namespaced types the test suites leave behind
         ORDER BY t.created_at
    LOOP
        PERFORM authz.write_tuple(p_to, r.user_type, r.user_id, r.relation, r.object_type, r.object_id,
                                  p_user_relation => r.user_relation, p_condition => r.condition_name,
                                  p_condition_context => r.condition_context, p_expires_at => r.expires_at,
                                  p_performed_by => 'examples/tenants/acme');
        n := n + 1;
    END LOOP;
    RETURN n;
END;
$$;

SELECT 'acme_tax'       AS store, pg_temp.replay_tuples('demo',      'acme_tax')       AS tuples
UNION ALL SELECT 'acme_todo',      pg_temp.replay_tuples('todo',      'acme_todo')
UNION ALL SELECT 'acme_fileshare', pg_temp.replay_tuples('fileshare', 'acme_fileshare');

-- The tenant's people in their stores (the realm's users, by preferred_username):
--   acme_tax        acme-dev on the tax team (tax_clerk of assignment eng_42_tax through it),
--                   acme-iam on the payroll team, acme-admin the engagement's advisor
--   acme_fileshare  acme-admin owns the projects folder, acme-dev reads the budget,
--                   acme-auditor reads everything under root
--   acme_todo       acme-admin administers todo-1, acme-dev edits it
DO $$
BEGIN
    PERFORM authz.write_tuple('acme_tax', 'internal_user', 'acme-dev',   'member',  'team',       'tax_team',     p_performed_by => 'examples/tenants/acme');
    PERFORM authz.write_tuple('acme_tax', 'internal_user', 'acme-iam',   'member',  'team',       'payroll_team', p_performed_by => 'examples/tenants/acme');
    PERFORM authz.write_tuple('acme_tax', 'internal_user', 'acme-admin', 'advisor', 'engagement', 'eng_42',       p_performed_by => 'examples/tenants/acme');

    PERFORM authz.write_tuple('acme_fileshare', 'user', 'acme-admin',   'owner',  'folder', 'projects', p_performed_by => 'examples/tenants/acme');
    PERFORM authz.write_tuple('acme_fileshare', 'user', 'acme-dev',     'viewer', 'doc',    'budget',   p_performed_by => 'examples/tenants/acme');
    PERFORM authz.write_tuple('acme_fileshare', 'user', 'acme-auditor', 'viewer', 'folder', 'root',     p_performed_by => 'examples/tenants/acme');

    PERFORM authz.write_tuple('acme_todo', 'user', 'acme-admin', 'admin',  'todo', 'todo-1', p_performed_by => 'examples/tenants/acme');
    PERFORM authz.write_tuple('acme_todo', 'user', 'acme-dev',   'editor', 'todo', 'todo-1', p_performed_by => 'examples/tenants/acme');
END $$;

-- What the data decides, as a smoke check
SELECT 'acme_tax: alice can_read doc_payroll_001'      AS check, authz.check_access('acme_tax', 'internal_user', 'alice',    'can_read', 'document', 'doc_payroll_001')
UNION ALL SELECT 'acme_fileshare: acme-dev can_read budget', authz.check_access('acme_fileshare', 'user', 'acme-dev',     'can_read', 'doc',  'budget')
UNION ALL SELECT 'acme_fileshare: acme-auditor can_read design_spec', authz.check_access('acme_fileshare', 'user', 'acme-auditor', 'can_read', 'doc', 'design_spec')
UNION ALL SELECT 'acme_todo: acme-dev can_manage_todo_items todo-1', authz.check_access('acme_todo', 'user', 'acme-dev', 'can_manage_todo_items', 'todo', 'todo-1');
