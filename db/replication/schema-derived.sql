-- Minimal schema for app databases that subscribe to derived permissions.
-- No authz functions, models, or tuples — just the flat lookup table, its
-- two side tables, the per-store freshness row, and two helpers: one that
-- applies the wildcard contract, one that says how stale the copy may be.
-- The same schema serves a subscriber of the whole store (publication
-- authz_derived) and one of a single namespace (authz_derived_<ns>): the
-- helpers work per object type, so a namespace subscriber simply has no rows
-- for the other types.
--
-- The partition layout must match the primary exactly for logical
-- replication to route rows correctly.

CREATE SCHEMA IF NOT EXISTS authz;

CREATE TABLE IF NOT EXISTS authz.materialized_relations (
    store         text    NOT NULL,
    user_type     text    NOT NULL,
    user_id       text    NOT NULL,
    relation    text    NOT NULL,
    object_type   text    NOT NULL,
    object_id     text    NOT NULL,
    namespace     text    NOT NULL DEFAULT '',   -- the object type's namespace; lets a publication row filter select it
    is_permission boolean NOT NULL DEFAULT false, -- true: a permission (can_read), false: a relation (member, parent)
    refreshed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (store, user_id, user_type, relation, object_type, object_id, namespace, is_permission)
) PARTITION BY HASH (store, user_id);

CREATE TABLE authz.materialized_relations_0 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 0);
CREATE TABLE authz.materialized_relations_1 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 1);
CREATE TABLE authz.materialized_relations_2 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 2);
CREATE TABLE authz.materialized_relations_3 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 3);
CREATE TABLE authz.materialized_relations_4 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 4);
CREATE TABLE authz.materialized_relations_5 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 5);
CREATE TABLE authz.materialized_relations_6 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 6);
CREATE TABLE authz.materialized_relations_7 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 7);

-- The subjects and objects the engine knows (= have at least one tuple).
-- A '*' row in materialized_relations applies only to entities that are
-- NOT listed here: a known subject or object has authoritative concrete
-- rows (exclusions already applied); an unknown one has nothing that could
-- narrow the wildcard.
CREATE TABLE IF NOT EXISTS authz.materialized_subjects (
    store         text    NOT NULL,
    user_type     text    NOT NULL,
    user_id       text    NOT NULL,
    refreshed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (store, user_type, user_id)
);

CREATE TABLE IF NOT EXISTS authz.materialized_objects (
    store         text    NOT NULL,
    object_type   text    NOT NULL,
    object_id     text    NOT NULL,
    namespace     text    NOT NULL DEFAULT '',
    refreshed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (store, object_type, object_id, namespace)
);

-- Freshness, one row per store the primary derives (replicated): every
-- change performed before as_of is reflected in this copy.
CREATE TABLE IF NOT EXISTS authz.materialized_refresh_state (
    store                 text PRIMARY KEY,
    cursor_at             timestamptz NOT NULL,
    cursor_seq            bigint      NOT NULL DEFAULT 0,
    as_of                 timestamptz NOT NULL,
    feed_drained          boolean     NOT NULL DEFAULT true,
    last_run_started_at   timestamptz,
    last_run_finished_at  timestamptz,
    last_run_changes      integer NOT NULL DEFAULT 0,
    last_run_pairs        integer NOT NULL DEFAULT 0,
    last_run_rows_written integer NOT NULL DEFAULT 0,
    last_run_gate         interval
);

-- "How stale can this copy be?" — NULL until the store is derived.
CREATE OR REPLACE FUNCTION authz.permissions_as_of(p_store text)
RETURNS timestamptz
LANGUAGE sql STABLE AS $$
    SELECT as_of FROM authz.materialized_refresh_state WHERE store = p_store;
$$;

-- The freshness threshold a consumer enforces: true only if every change
-- performed before now() - p_max_staleness is reflected. A worker stalled by
-- a long-open transaction on the primary, or a replication lag, makes this
-- false — fall back to the live check_access then.
CREATE OR REPLACE FUNCTION authz.permissions_fresh(p_store text, p_max_staleness interval)
RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT COALESCE((SELECT as_of >= now() - p_max_staleness
                       FROM authz.materialized_refresh_state WHERE store = p_store), false);
$$;

-- The wildcard contract (see materialized_relations.sql on the primary):
--
--   subject keys = {user_id}   ∪ {'*' if the subject is unknown}
--   object keys  = {object_id} ∪ {'*' if the object is unknown}
--   allowed      = a row exists with user_id IN subject keys
--                                 AND object_id IN object keys
--
-- A single SQL expression, so the planner can inline it into a listing
-- query:  SELECT d.* FROM documents d
--          WHERE authz.check_permission('demo','internal_user','bob','can_read','document', d.id);
CREATE OR REPLACE FUNCTION authz.check_permission(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_permission  text,
    p_object_type text,
    p_object_id   text
) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT EXISTS(
        SELECT 1 FROM authz.materialized_relations p
         WHERE p.store       = p_store
           AND p.user_type   = p_user_type
           AND p.relation  = p_permission
           AND p.object_type = p_object_type
           AND (p.user_id = p_user_id
                OR (p.user_id = '*' AND NOT EXISTS (
                        SELECT 1 FROM authz.materialized_subjects s
                         WHERE s.store = p_store AND s.user_type = p_user_type
                           AND s.user_id = p_user_id)))
           AND (p.object_id = p_object_id
                OR (p.object_id = '*' AND NOT EXISTS (
                        SELECT 1 FROM authz.materialized_objects o
                         WHERE o.store = p_store AND o.object_type = p_object_type
                           AND o.object_id = p_object_id)))
    );
$$;
