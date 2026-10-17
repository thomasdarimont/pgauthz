-- 0021_condition_description.sql
--
-- Conditions get a description (what the expression is for, in words) and
-- creation / last-change times, like stores. The audit copy carries the
-- description so a version shows what it was documented as. Existing rows
-- are backfilled from their audit history.
ALTER TABLE authz.conditions
    ADD COLUMN IF NOT EXISTS description text,
    ADD COLUMN IF NOT EXISTS created_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_at  timestamptz NOT NULL DEFAULT now();
ALTER TABLE authz.conditions_audit ADD COLUMN IF NOT EXISTS description text;
UPDATE authz.conditions c
   SET created_at = COALESCE((SELECT min(a.performed_at) FROM authz.conditions_audit a WHERE a.condition_id = c.id), c.created_at),
       updated_at = COALESCE((SELECT max(a.performed_at) FROM authz.conditions_audit a WHERE a.condition_id = c.id), c.updated_at);
