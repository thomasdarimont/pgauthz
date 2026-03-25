-- Minimal schema for app databases that subscribe to derived permissions.
-- No authz functions, models, or tuples — just the flat lookup table.
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

-- Convenience function for access checks (optional).
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
        SELECT 1 FROM authz.materialized_permissions
         WHERE store       = p_store
           AND user_id     = p_user_id
           AND user_type   = p_user_type
           AND permission  = p_permission
           AND object_type = p_object_type
           AND object_id   = p_object_id
    );
$$;
