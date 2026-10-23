-- Engine/tenant stats for metrics sampling (ADR 0010, Slice 3).
--
-- pgauthzd polls this on an interval to publish per-store gauges
-- (pgauthzd_store_tuples, pgauthzd_stores_total). App roles have no direct
-- table access, so it is SECURITY DEFINER (roles.sql) and granted to
-- authz_reader — the sampler runs on the ordinary reader/writer connection.
--
-- Returns the top p_limit stores by tuple count (bounded cardinality — the
-- caller emits one series per store), each row also carrying stores_total (the
-- true store count, so the operator sees when there are more tenants than
-- series). A LEFT JOIN + count over the partitioned tuples table is a real scan;
-- keep the sample interval modest on large deployments.
-- list_stores: every store with its facts — live and retired (retired_at
-- set) — for tooling that may call the API but not read the tables (the
-- admin API, pgauthzctl with a reader DSN). Reader tier: a store's name and
-- description are what every reader already learns from the functions.
CREATE OR REPLACE FUNCTION authz.list_stores()
RETURNS TABLE (
    name        text,
    description text,
    docs_url    text,
    created_at  timestamptz,
    retired_at  timestamptz
)
LANGUAGE sql STABLE AS $$
    SELECT s.name, s.description, s.docs_url, s.created_at, s.deleted_at
      FROM authz.stores s
     ORDER BY s.name;
$$;

-- list_recorder_actions: the store's recorder allowlists (ADR 0012) —
-- which DB roles may record which actions; a role without a row may
-- record any declared action.
CREATE OR REPLACE FUNCTION authz.list_recorder_actions(p_store text)
RETURNS TABLE (db_role text, actions text[])
LANGUAGE sql STABLE AS $$
    SELECT ra.db_role, array_agg(rl.name ORDER BY rl.name)
      FROM authz.recorder_actions ra
      JOIN authz.relations rl ON rl.id = ra.action
     WHERE ra.store_id = authz._s(p_store, true)
     GROUP BY ra.db_role
     ORDER BY ra.db_role;
$$;

-- list_namespaces: the store's namespaces — the types in each and the DB
-- roles with read / write access (namespace_access). A namespace with
-- grants but no type any more, or with types but no grants, is listed too.
CREATE OR REPLACE FUNCTION authz.list_namespaces(p_store text)
RETURNS TABLE (namespace text, types text[], access jsonb)
LANGUAGE sql STABLE AS $$
    WITH s AS (SELECT authz._s(p_store, true) AS id),
    names AS (
        SELECT t.namespace FROM authz.types t, s WHERE t.store_id = s.id AND t.namespace IS NOT NULL
        UNION
        SELECT na.namespace FROM authz.namespace_access na, s WHERE na.store_id = s.id
    )
    SELECT n.namespace,
           coalesce((SELECT array_agg(t.name ORDER BY t.name) FROM authz.types t, s WHERE t.store_id = s.id AND t.namespace = n.namespace), '{}'),
           coalesce((SELECT jsonb_agg(jsonb_build_object('db_role', na.db_role, 'can_read', na.can_read, 'can_write', na.can_write) ORDER BY na.db_role)
                       FROM authz.namespace_access na, s WHERE na.store_id = s.id AND na.namespace = n.namespace), '[]'::jsonb)
      FROM names n
     ORDER BY n.namespace;
$$;

CREATE OR REPLACE FUNCTION authz.store_stats(p_limit int DEFAULT 100)
RETURNS TABLE(store text, tuples bigint, stores_total bigint)
LANGUAGE sql
STABLE
AS $$
    SELECT s.name,
           count(t.*)::bigint,
           (SELECT count(*) FROM authz.stores)::bigint
      FROM authz.stores s
      LEFT JOIN authz.tuples t ON t.store_id = s.id
     GROUP BY s.name
     ORDER BY count(t.*) DESC, s.name
     LIMIT greatest(p_limit, 0);
$$;

COMMENT ON FUNCTION authz.store_stats(int) IS
    'ADR 0010: per-store tuple counts (top-N) + total store count, for metrics sampling.';
