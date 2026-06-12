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
) RETURNS smallint
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id smallint;
BEGIN
    INSERT INTO authz.stores (name, description)
    VALUES (p_name, p_description)
    RETURNING id INTO v_store_id;

    RETURN v_store_id;
END;
$$;

------------------------------------------------------------------------
-- delete_store: removes a store and all its associated data.
-- Deletes in dependency order: tuples → audit → models → conditions
-- → types/relations → store. Also drops tuple partitions for the store.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.delete_store(
    p_store text
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id   smallint := authz._s(p_store);
    v_store_safe text;
    v_type_safe  text;
    v_part_name  text;
    v_type_rec   record;
BEGIN
    DELETE FROM authz.tuples            WHERE store_id = v_store_id;
    DELETE FROM authz.tuples_audit      WHERE store_id = v_store_id;
    DELETE FROM authz.type_restrictions WHERE store_id = v_store_id;
    DELETE FROM authz.models            WHERE store_id = v_store_id;
    DELETE FROM authz.conditions        WHERE store_id = v_store_id;
    DELETE FROM authz.namespace_access  WHERE store_id = v_store_id;

    -- Drop tuple partitions for this store's types
    v_store_safe := regexp_replace(p_store, '[^a-zA-Z0-9]', '_', 'g');
    FOR v_type_rec IN
        SELECT name FROM authz.types WHERE store_id = v_store_id
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

    DELETE FROM authz.types      WHERE store_id = v_store_id;
    DELETE FROM authz.relations  WHERE store_id = v_store_id;
    DELETE FROM authz.stores     WHERE id       = v_store_id;
END;
$$;
