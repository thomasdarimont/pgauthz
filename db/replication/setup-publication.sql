-- Creates publications on the primary for selective logical replication.
--
-- Three publications:
--   1. authz_metadata       — all metadata tables (tiny, replicate fully)
--   2. authz_accounting     — only tuple partitions needed for accounting
--                             authorization chains (skips client-facing types)
--   3. authz_derived        — materialized_relations table plus its two
--                             side tables materialized_subjects /
--                             materialized_objects (the wildcard contract)
--                             and materialized_refresh_state (freshness);
--                             flat, no authz schema/functions needed on
--                             the subscriber
--   4. authz_derived_dms    — the same, row-filtered to the object types of
--                             namespace 'dms' (one application's share)
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
ALTER DEFAULT PRIVILEGES IN SCHEMA authz GRANT SELECT ON TABLES TO replicator;

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
-- subscribe to without needing the authz schema or functions, plus the
-- side tables the subscriber's check_permission() needs to apply '*'
-- rows correctly (see materialized_relations.sql, "the wildcard
-- contract") and the per-store freshness row. The partitioned tables are
-- published through their root (publish_via_partition_root), so the
-- subscriber routes rows into its own partitions and a row filter on the
-- root applies to every partition.
CREATE PUBLICATION authz_derived FOR TABLE
    authz.materialized_relations,
    authz.materialized_subjects,
    authz.materialized_objects,
    authz.materialized_refresh_state
    WITH (publish_via_partition_root = true);

-- 4. The same, narrowed to one application's namespace: only the rows of
-- object types in namespace 'dms' (document, folder in this demo — see
-- init-replication.sh), plus the whole subject set and the freshness row,
-- which are store-wide notions the wildcard contract and permissions_fresh()
-- need regardless. The filter names `namespace`, which is why that column is
-- part of the table's primary key (a row filter may only reference replica
-- identity columns — and only built-in types). The rows keep both kinds; an
-- application that only wants permissions reads `WHERE is_permission` (or
-- adds `AND is_permission` to a filter like this one — is_permission is in
-- the key for that reason). Adding a type to the namespace needs no change
-- here; moving a type between namespaces or re-declaring a relation's kind
-- needs refresh_all_materialized_relations.
-- One publication per application; a publication is a volume boundary, not a
-- security one (any replication role that may read the tables may subscribe
-- to any publication) — isolate tenants with stores.
CREATE PUBLICATION authz_derived_dms FOR TABLE
    authz.materialized_relations WHERE (store = 'demo' AND namespace = 'dms'),
    authz.materialized_objects     WHERE (store = 'demo' AND namespace = 'dms'),
    authz.materialized_subjects,
    authz.materialized_refresh_state
    WITH (publish_via_partition_root = true);
