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
