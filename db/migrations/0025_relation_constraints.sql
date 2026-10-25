-- 0025_relation_constraints.sql
--
-- Relation constraints: how many subjects a relation may hold on one object,
-- as model data per (object type, relation).
--
--   max_direct    — enforced at WRITE time: the number of live direct tuples
--                   (as written: a userset subject counts as one) on one
--                   object for the relation may not exceed it. Wildcard tuples
--                   are refused on a capped relation (they are unbounded).
--   max_effective — advisory: the intended size of the RESOLVED holder set
--                   (direct, usersets, inherited). Never enforced on a write —
--                   a resolved count fans out (a folder share would re-count
--                   every document below it) and fails writes for distant
--                   reasons; relation_usage reports count and headroom.
--
-- History follows the grant-rules precedent: an append-only audit table so
-- "what was the cap on Tuesday" stays answerable.

CREATE TABLE authz.relation_constraints (
    id            integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    store_id      integer NOT NULL REFERENCES authz.stores(id),
    object_type   integer NOT NULL,
    relation      integer NOT NULL,
    max_direct    integer CHECK (max_direct > 0),
    max_effective integer CHECK (max_effective > 0),
    CHECK (max_direct IS NOT NULL OR max_effective IS NOT NULL),
    UNIQUE (store_id, object_type, relation),
    -- Composite FKs: same-store references only (see authz.models).
    FOREIGN KEY (object_type, store_id) REFERENCES authz.types     (id, store_id),
    FOREIGN KEY (relation,    store_id) REFERENCES authz.relations (id, store_id)
);

CREATE TABLE authz.relation_constraints_audit (
    seq            bigint      NOT NULL GENERATED ALWAYS AS IDENTITY,
    action         text        NOT NULL,   -- 'INSERT' or 'DELETE'
    performed_at   timestamptz NOT NULL DEFAULT now(),
    performed_by   text        NOT NULL DEFAULT current_user,
    constraint_id  integer     NOT NULL,   -- authz.relation_constraints.id
    store_id       integer     NOT NULL,
    object_type    integer     NOT NULL,
    relation       integer     NOT NULL,
    max_direct     integer,
    max_effective  integer,
    PRIMARY KEY (seq)
);

CREATE INDEX idx_relation_constraints_audit_replay
    ON authz.relation_constraints_audit (constraint_id, performed_at DESC, seq DESC);
CREATE INDEX idx_relation_constraints_audit_store
    ON authz.relation_constraints_audit (store_id, performed_at);
