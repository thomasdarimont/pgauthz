-- Public store management API.
-- All functions accept text parameters and resolve IDs internally.
--
-- Depends on: engine/core_internal.sql

------------------------------------------------------------------------
-- create_store: creates a new authorization store.
-- Returns the store ID. Raises an exception if the name already exists.
--
-- Examples:
--   SELECT authz.create_store('myapp');
--   SELECT authz.create_store('myapp', 'My application permissions');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.create_store(
    p_name        text,
    p_description text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer;
BEGIN
    INSERT INTO authz.stores (name, description)
    VALUES (p_name, p_description)
    RETURNING id INTO v_store_id;

    RETURN v_store_id;
END;
$$;

------------------------------------------------------------------------
-- _drop_store_tuple_partitions: detaches and drops the per-type tuple
-- partitions of a store (reclaiming the hot storage). Shared by
-- delete_store and retire_store. Partition names mirror the convention
-- used when they are created (tuples_<store>_<type>, non-alnum -> '_').
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._drop_store_tuple_partitions(
    p_store_id   integer,
    p_store_name text
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_store_safe text := regexp_replace(p_store_name, '[^a-zA-Z0-9]', '_', 'g');
    v_type_safe  text;
    v_part_name  text;
    v_type_rec   record;
BEGIN
    FOR v_type_rec IN
        SELECT name FROM authz.types WHERE store_id = p_store_id
    LOOP
        v_type_safe := regexp_replace(v_type_rec.name, '[^a-zA-Z0-9]', '_', 'g');
        v_part_name := 'tuples_' || v_store_safe || '_' || v_type_safe;
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'authz' AND c.relname = v_part_name AND c.relispartition
        ) THEN
            EXECUTE format('ALTER TABLE authz.tuples DETACH PARTITION authz.%I', v_part_name);
            EXECUTE format('DROP TABLE authz.%I', v_part_name);
        END IF;
    END LOOP;
END;
$$;

------------------------------------------------------------------------
-- retire_store: soft-deletes a store (the audit-safe alternative to
-- delete_store). Drops only the live tuple data (and reclaims the hot
-- tuple partitions), then marks the store retired (stores.deleted_at).
--
-- The store's dictionary (types / relations / models / conditions) and
-- its full audit history are KEPT, so the audit_* time-travel functions
-- can still resolve it by name and answer "could X do Y at time T?" long
-- after it stops serving live checks. Live APIs reject a retired store
-- (authz._s resolves live-only), and its name stays reserved.
--
-- Use this for regulated / audit-critical stores. delete_store remains
-- the explicit physical-removal (erasure) path. A retired store can later
-- be purged with delete_store.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.retire_store(p_store text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);   -- live-only: cannot retire twice
BEGIN
    DELETE FROM authz.tuples WHERE store_id = v_store_id;
    PERFORM authz._drop_store_tuple_partitions(v_store_id, p_store);

    UPDATE authz.stores SET deleted_at = now() WHERE id = v_store_id;
END;
$$;

------------------------------------------------------------------------
-- delete_store: physically removes a store and all its associated data
-- (an erasure / right-to-be-forgotten path). Deletes in dependency order:
-- tuples → models → conditions → types/relations → store, and drops the
-- store's tuple partitions.
--
-- The audit history is PRESERVED by default (the tuple deletions performed
-- here are themselves audited). Pass p_purge_audit => true to also remove
-- the store's audit rows. Retained audit rows reference the deleted
-- store/type/relation IDs — these are never reused, so the rows stay
-- unambiguous, but they are no longer resolvable by name. For
-- audit-critical stores, prefer retire_store, which keeps them resolvable.
--
-- Resolves the store including retired ones, so a previously retired store
-- can be purged here.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.delete_store(
    p_store       text,
    p_purge_audit boolean DEFAULT false
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id   integer := authz._s(p_store, true);
BEGIN
    DELETE FROM authz.tuples            WHERE store_id = v_store_id;
    IF p_purge_audit THEN
        PERFORM set_config('authz.audit_maintenance', 'on', true);
        DELETE FROM authz.tuples_audit  WHERE store_id = v_store_id;
        PERFORM set_config('authz.audit_maintenance', '', true);
    END IF;
    DELETE FROM authz.type_restrictions WHERE store_id = v_store_id;
    DELETE FROM authz.models            WHERE store_id = v_store_id;
    IF p_purge_audit THEN
        -- The model deletes above are themselves logged to models_audit;
        -- purge those rows too (append-only, so under a maintenance window).
        PERFORM set_config('authz.audit_maintenance', 'on', true);
        DELETE FROM authz.models_audit  WHERE store_id = v_store_id;
        PERFORM set_config('authz.audit_maintenance', '', true);
    END IF;
    DELETE FROM authz.conditions        WHERE store_id = v_store_id;
    IF p_purge_audit THEN
        -- The condition deletes above are logged to conditions_audit; purge.
        PERFORM set_config('authz.audit_maintenance', 'on', true);
        DELETE FROM authz.conditions_audit WHERE store_id = v_store_id;
        PERFORM set_config('authz.audit_maintenance', '', true);
    END IF;
    DELETE FROM authz.namespace_access  WHERE store_id = v_store_id;

    -- Drop tuple partitions for this store's types
    PERFORM authz._drop_store_tuple_partitions(v_store_id, p_store);

    DELETE FROM authz.types      WHERE store_id = v_store_id;
    DELETE FROM authz.relations  WHERE store_id = v_store_id;
    DELETE FROM authz.stores     WHERE id       = v_store_id;
END;
$$;
