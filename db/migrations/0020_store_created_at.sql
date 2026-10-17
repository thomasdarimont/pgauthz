-- 0020_store_created_at.sql
--
-- When a store was created (the console lists it; operators sort by it).
-- Existing stores are backfilled from their earliest audit entry — the
-- first model or tuple change — else from now.
ALTER TABLE authz.stores ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
UPDATE authz.stores s
   SET created_at = LEAST(
         COALESCE((SELECT min(a.performed_at) FROM authz.models_audit a WHERE a.store_id = s.id), now()),
         COALESCE((SELECT min(a.performed_at) FROM authz.tuples_audit a WHERE a.store_id = s.id), now()))
 WHERE s.created_at >= now() - interval '1 minute';   -- only rows the ADD COLUMN just defaulted
