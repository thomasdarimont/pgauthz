-- Human-readable views over the model and type-restriction tables (resolve
-- integer IDs to names). Idempotent code (CREATE OR REPLACE VIEW), substrate
-- profile — moved out of schema.sql so that file is pure structural DDL.
--
-- Depends on: schema.sql (authz.models, authz.type_restrictions, and the
-- authz.stores / types / relations lookup tables).

-- Human-readable view of model rules (resolves integer IDs to names).
CREATE OR REPLACE VIEW authz.models_view AS
SELECT
    mr.id,
    s.name  AS store,
    t.name  AS object_type,
    r.name  AS relation,
    CASE mr.rule_type
        WHEN 1 THEN 'direct'
        WHEN 2 THEN 'computed'
        WHEN 3 THEN 'ttu'
    END AS rule_type,
    cr.name AS computed_relation,
    tr.name AS tupleset_relation,
    tc.name AS tupleset_computed,
    mr.group_id,
    CASE mr.group_op
        WHEN 0 THEN 'or'
        WHEN 1 THEN 'intersection'
        WHEN 2 THEN 'exclusion'
    END AS group_op,
    mr.negated,
    mr.allow_object_wildcard
  FROM authz.models mr
  JOIN authz.stores s    ON s.id  = mr.store_id
  JOIN authz.types t     ON t.id  = mr.object_type
  JOIN authz.relations r ON r.id  = mr.relation
  LEFT JOIN authz.relations cr ON cr.id = mr.computed_relation
  LEFT JOIN authz.relations tr ON tr.id = mr.tupleset_relation
  LEFT JOIN authz.relations tc ON tc.id = mr.tupleset_computed;

-- Human-readable view of type restrictions (resolves integer IDs to names).
CREATE OR REPLACE VIEW authz.type_restrictions_view AS
SELECT
    tr.id,
    s.name  AS store,
    ot.name AS object_type,
    r.name  AS relation,
    aut.name AS allowed_user_type,
    aur.name AS allowed_user_relation,
    tr.allow_wildcard
  FROM authz.type_restrictions tr
  JOIN authz.stores s     ON s.id  = tr.store_id
  JOIN authz.types ot     ON ot.id = tr.object_type
  JOIN authz.relations r  ON r.id  = tr.relation
  JOIN authz.types aut    ON aut.id = tr.allowed_user_type
  LEFT JOIN authz.relations aur ON aur.id = tr.allowed_user_relation;
