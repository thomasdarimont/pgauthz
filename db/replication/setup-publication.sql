-- Creates publications on the primary for selective logical replication.
--
-- Three publications:
--   1. authz_metadata       — all metadata tables (tiny, replicate fully)
--   2. authz_accounting     — only tuple partitions needed for accounting
--                             authorization chains (skips client-facing types)
--   3. authz_derived        — materialized_permissions table (flat, no authz
--                             schema/functions needed on subscriber)
--
-- The accounting app needs these types to resolve check_access paths:
--   document(9) → in_internal_space → internal_data_space(7)
--     → parent_assignment → assignment(6) → accountant/payroll_clerk/tax_clerk
--     → parent_engagement → engagement(5) → advisor/assistant
--   assignment roles are usersets: team(3)#member
--
-- Deliberately excluded (client-facing, not needed for internal accounting):
--   client_org(4), client_data_space(8), upload_request(10)

-- Grant the replicator role SELECT on the authz schema.
GRANT USAGE ON SCHEMA authz TO replicator;
GRANT SELECT ON ALL TABLES IN SCHEMA authz TO replicator;
ALTER DEFAULT PRIVILEGES IN SCHEMA authz GRANT SELECT TO replicator;

-- Logical replication requires a replica identity for UPDATE/DELETE.
-- Tables with a PRIMARY KEY use it automatically; tables without one
-- (tuples and tuple partitions) need REPLICA IDENTITY FULL.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT n.nspname || '.' || c.relname AS tbl
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'authz'
           AND c.relname LIKE 'tuples_%'
           AND c.relkind = 'r'  -- leaf tables only
    LOOP
        EXECUTE format('ALTER TABLE %s REPLICA IDENTITY FULL', r.tbl);
    END LOOP;
END;
$$;

-- 1. Metadata: all rows, these tables are small and rarely change.
CREATE PUBLICATION authz_metadata FOR TABLE
    authz.stores,
    authz.types,
    authz.relations,
    authz.conditions,
    authz.models,
    authz.namespace_access;

-- 2. Accounting-relevant tuple partitions.
-- publish_via_partition_root = true: changes are published using the root
-- table's identity (authz.tuples), so the subscriber routes them into
-- its own local partitions correctly.
--
-- Document type uses hash sub-partitioning (modulus 8), so we list all
-- leaf partitions explicitly.
CREATE PUBLICATION authz_accounting FOR TABLE
    authz.tuples_demo_team,
    authz.tuples_demo_engagement,
    authz.tuples_demo_assignment,
    authz.tuples_demo_internal_data_space,
    authz.tuples_demo_document_0,
    authz.tuples_demo_document_1,
    authz.tuples_demo_document_2,
    authz.tuples_demo_document_3,
    authz.tuples_demo_document_4,
    authz.tuples_demo_document_5,
    authz.tuples_demo_document_6,
    authz.tuples_demo_document_7
    WITH (publish_via_partition_root = true);

-- 3. Derived permissions: a flat lookup table that app databases can
-- subscribe to without needing the authz schema or functions.
-- Hash-partitioned by (store, user_id), so we list all leaf partitions.
CREATE PUBLICATION authz_derived FOR TABLE
    authz.materialized_permissions_0,
    authz.materialized_permissions_1,
    authz.materialized_permissions_2,
    authz.materialized_permissions_3,
    authz.materialized_permissions_4,
    authz.materialized_permissions_5,
    authz.materialized_permissions_6,
    authz.materialized_permissions_7
    WITH (publish_via_partition_root = true);
