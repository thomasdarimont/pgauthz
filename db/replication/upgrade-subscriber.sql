-- Upgrade a SUBSCRIBER of the derived tables from the first shape
-- (authz.materialized_permissions with a `permission` column) to the current
-- one. Logical replication matches tables and columns by NAME and carries no
-- DDL, so a subscriber must be changed by hand, in this order:
--
--   1. subscriber:  ALTER SUBSCRIPTION <sub> DISABLE;
--   2. publisher:   load db/replication/materialized_relations.sql (renames its
--                   tables in place, repoints the authz_derived publication),
--                   then SELECT authz.refresh_all_materialized_relations(store)
--                   for every registered store (rows get namespace / kind)
--   3. subscriber:  this file, then db/replication/schema-derived.sql
--                   (idempotent: adds what is still missing)
--   4. subscriber:  ALTER SUBSCRIPTION <sub> REFRESH PUBLICATION;  -- picks up materialized_refresh_state
--                   ALTER SUBSCRIPTION <sub> ENABLE;
--   5. verify:      SELECT * FROM pg_subscription_rel WHERE srsubstate <> 'r';   -- empty when caught up
--                   compare a digest of the tables with the publisher (see tests/test-replication.sh)
--
-- Rows already replicated are kept (the publisher's rebuild in step 2 then
-- deletes and re-inserts them with their namespace and kind, which replicates
-- as ordinary changes). Idempotent: every step checks the current shape.

DO $$
DECLARE
    r record;
BEGIN
    -- table, partitions, key constraint
    IF to_regclass('authz.materialized_permissions') IS NOT NULL
       AND to_regclass('authz.materialized_relations') IS NULL THEN
        ALTER TABLE authz.materialized_permissions RENAME TO materialized_relations;
        IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'materialized_permissions_pkey') THEN
            ALTER TABLE authz.materialized_relations RENAME CONSTRAINT materialized_permissions_pkey TO materialized_relations_pkey;
        END IF;
        FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'authz' AND c.relname ~ '^materialized_permissions_[0-9]+$' LOOP
            EXECUTE format('ALTER TABLE authz.%I RENAME TO %I', r.relname,
                           replace(r.relname, 'materialized_permissions_', 'materialized_relations_'));
        END LOOP;
    END IF;
    -- the name column
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'authz' AND table_name = 'materialized_relations' AND column_name = 'permission') THEN
        ALTER TABLE authz.materialized_relations RENAME COLUMN permission TO relation;
    END IF;
    -- namespace and kind, both in the key
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'authz' AND table_name = 'materialized_relations' AND column_name = 'namespace') THEN
        ALTER TABLE authz.materialized_relations ADD COLUMN namespace text NOT NULL DEFAULT '';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'authz' AND table_name = 'materialized_relations' AND column_name = 'is_permission') THEN
        ALTER TABLE authz.materialized_relations ADD COLUMN is_permission boolean NOT NULL DEFAULT false;
        ALTER TABLE authz.materialized_relations DROP CONSTRAINT materialized_relations_pkey;
        ALTER TABLE authz.materialized_relations ADD PRIMARY KEY (store, user_id, user_type, relation, object_type, object_id, namespace, is_permission);
    END IF;
    IF to_regclass('authz.materialized_objects') IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                        WHERE table_schema = 'authz' AND table_name = 'materialized_objects' AND column_name = 'namespace') THEN
        ALTER TABLE authz.materialized_objects ADD COLUMN namespace text NOT NULL DEFAULT '';
        ALTER TABLE authz.materialized_objects DROP CONSTRAINT materialized_objects_pkey;
        ALTER TABLE authz.materialized_objects ADD PRIMARY KEY (store, object_type, object_id, namespace);
    END IF;
    -- freshness row (created by schema-derived.sql if absent)
    IF to_regclass('authz.materialized_refresh_state') IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                        WHERE table_schema = 'authz' AND table_name = 'materialized_refresh_state' AND column_name = 'last_run_gate') THEN
            ALTER TABLE authz.materialized_refresh_state ADD COLUMN last_run_gate interval;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                        WHERE table_schema = 'authz' AND table_name = 'materialized_refresh_state' AND column_name = 'store_id') THEN
            ALTER TABLE authz.materialized_refresh_state ADD COLUMN store_id integer;
        END IF;
    END IF;
END;
$$;
