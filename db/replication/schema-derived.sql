-- Minimal schema for app databases that subscribe to derived permissions.
-- No authz functions, models, or tuples — just the flat lookup table, its
-- two side tables and one helper that applies the wildcard contract.
--
-- The partition layout must match the primary exactly for logical
-- replication to route rows correctly.

CREATE SCHEMA IF NOT EXISTS authz;

CREATE TABLE IF NOT EXISTS authz.materialized_permissions (
    store         text    NOT NULL,
    user_type     text    NOT NULL,
    user_id       text    NOT NULL,
    permission    text    NOT NULL,
    object_type   text    NOT NULL,
    object_id     text    NOT NULL,
    refreshed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (store, user_id, user_type, permission, object_type, object_id)
) PARTITION BY HASH (store, user_id);

CREATE TABLE authz.materialized_permissions_0 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 0);
CREATE TABLE authz.materialized_permissions_1 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 1);
CREATE TABLE authz.materialized_permissions_2 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 2);
CREATE TABLE authz.materialized_permissions_3 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 3);
CREATE TABLE authz.materialized_permissions_4 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 4);
CREATE TABLE authz.materialized_permissions_5 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 5);
CREATE TABLE authz.materialized_permissions_6 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 6);
CREATE TABLE authz.materialized_permissions_7 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 7);

-- The subjects and objects the engine knows (= have at least one tuple).
-- A '*' row in materialized_permissions applies only to entities that are
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
    refreshed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (store, object_type, object_id)
);

-- The wildcard contract (see materialized_permissions.sql on the primary):
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
        SELECT 1 FROM authz.materialized_permissions p
         WHERE p.store       = p_store
           AND p.user_type   = p_user_type
           AND p.permission  = p_permission
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
