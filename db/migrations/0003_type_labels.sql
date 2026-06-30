-- 0003_type_labels.sql
--
-- Logical grouping of model types via free-form key:value labels.
--
-- A type has at most one `namespace` (the app that *manages* tuples for it),
-- but it can belong to many logical groups along several axes — e.g.
-- `engagement` is `group:accounting` AND `group:sharing`. `labels` captures that
-- many-to-many membership so tooling (the playground graph, docs, dashboards)
-- can cluster, filter, or hide types by domain without inventing its own scheme.
--
-- Convention: each label is `key:value` (e.g. `group:accounting`, `tier:sensitive`);
-- a colon-less entry is a bare tag. Multi-value-per-key falls out naturally as
-- several array entries (`group:accounting`, `group:sharing`), which is exactly
-- the clustering case and stays GIN-indexable via array containment.
--
-- Labels are advisory metadata only: they carry NO access-control meaning (that
-- stays with `namespace`). Structure only — the registration/setter behaviour
-- lives in idempotent engine code (db/engine/model.sql).

ALTER TABLE authz.types ADD COLUMN labels text[] NOT NULL DEFAULT '{}';

-- Membership lookups ("which types are labelled group:accounting") use
-- array containment, which a GIN index accelerates.
CREATE INDEX types_labels_gin ON authz.types USING gin (labels);

COMMENT ON COLUMN authz.types.labels IS
    'Free-form key:value logical-grouping labels (advisory; a type may carry '
    'many, including several values for one key). Distinct from namespace, '
    'which is the single managing app and governs access. Used by tooling to '
    'cluster/filter types. Default {}.';
