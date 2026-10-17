-- 0019_relation_metadata.sql
--
-- Relation metadata: a JSON document on every relation, open for keys the
-- engine does not interpret (a display label, a documentation link) and ONE
-- key it does: "kind" — "relation" (what a subject IS: assignable by a tuple,
-- e.g. viewer, owner, member) or "permission" (what a subject CAN DO: derived
-- from other relations by computed/ttu rules only, e.g. can_read). A
-- permission never has direct rules, type restrictions or tuples; the engine
-- refuses them. Managed with model_register_relation(..., p_metadata) and
-- model_set_relation_metadata; exported/applied by the model registry.
ALTER TABLE authz.relations ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE authz.relations DROP CONSTRAINT IF EXISTS relations_metadata_check;
ALTER TABLE authz.relations ADD CONSTRAINT relations_metadata_check
    CHECK (jsonb_typeof(metadata) = 'object'
           AND (metadata->>'kind' IS NULL OR metadata->>'kind' IN ('relation', 'permission')));

-- Existing models: a relation that has rules but no direct rule on any type
-- is a permission (nothing can be assigned to it); everything else stays a
-- relation. (The engine's infer_relation_kinds does the same at runtime.)
UPDATE authz.relations r
   SET metadata = r.metadata || jsonb_build_object('kind',
         CASE WHEN EXISTS (SELECT 1 FROM authz.models m WHERE m.store_id = r.store_id AND m.relation = r.id AND m.rule_type = 1)
              THEN 'relation' ELSE 'permission' END)
 WHERE r.metadata->>'kind' IS NULL
   AND EXISTS (SELECT 1 FROM authz.models m WHERE m.store_id = r.store_id AND m.relation = r.id);
