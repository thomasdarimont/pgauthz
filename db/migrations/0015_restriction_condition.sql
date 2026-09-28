-- 0015_restriction_condition.sql
--
-- Condition-bound type restrictions (OpenFGA `[user, user:* with cond]`).
--
-- A restriction row is a FACET: which subject shape (type, userset relation,
-- wildcard) may be directly assigned to a relation. It may now also name a
-- condition the tuple MUST carry (`condition_id`). Write-time validation
-- (authz._check_type_restriction) matches a tuple against a facet of its
-- shape AND:
--   - an unconditioned tuple matches only a facet with condition_id NULL;
--   - a conditioned tuple matches a facet with condition_id NULL (open facet:
--     any condition is fine — pgauthz conditions are per tuple by design) or
--     with condition_id = the tuple's condition.
-- So `[user:* with cond]` (only conditioned facets for the wildcard shape)
-- makes a wildcard viewer WITHOUT `cond` — or with another condition — a
-- write error, which is the guarantee the OpenFGA import previously dropped
-- silently. Facets with no condition keep today's behaviour exactly.
--
-- Structure only; behaviour lives in db/engine (core_internal.sql,
-- tuples.sql, model.sql, model_registry.sql) and db/openfga.

-- Composite FK target: a restriction may only reference a condition of its
-- own store (same-store discipline as the other model FKs).
ALTER TABLE authz.conditions
    ADD CONSTRAINT conditions_id_store_unique UNIQUE (id, store_id);

ALTER TABLE authz.type_restrictions
    ADD COLUMN condition_id integer;

ALTER TABLE authz.type_restrictions
    ADD CONSTRAINT type_restrictions_condition_fkey
    FOREIGN KEY (condition_id, store_id) REFERENCES authz.conditions (id, store_id);

COMMENT ON COLUMN authz.type_restrictions.condition_id IS
    'When set, a tuple of this facet''s shape MUST carry this condition (OpenFGA '
    '"with <cond>"). NULL = open facet: unconditioned tuples, and conditioned ones '
    'with any condition, match it.';

-- The facet identity now includes the condition: `[user, user with cond]` is
-- two rows. Expression index (COALESCE) because both optional columns are
-- nullable; model_add_type_restriction's ON CONFLICT names the same expressions.
DROP INDEX authz.idx_type_restrictions_unique;
CREATE UNIQUE INDEX idx_type_restrictions_unique
    ON authz.type_restrictions (store_id, object_type, relation, allowed_user_type,
                                COALESCE(allowed_user_relation, -1), allow_wildcard,
                                COALESCE(condition_id, -1));
