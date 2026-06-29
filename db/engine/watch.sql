-- ============================================================================
-- Watch / changefeed API.
--
-- Streams tuple changes from the immutable tuples_audit log so consumers can
-- invalidate caches, materialize permissions, or sync downstream systems — the
-- SpiceDB "Watch" analog, built on infrastructure that already exists.
--
-- Cursor + safety: changes are cursored by (performed_at, seq). `seq` is
-- assigned at INSERT time, not commit time, so a naive `seq > cursor` poll could
-- permanently skip a row whose transaction commits AFTER a higher seq has been
-- consumed. watch_changes instead orders by (performed_at, seq) and only emits
-- rows older than `p_lag` (the stability lag). Because the writer roles carry a
-- statement_timeout, a write transaction cannot outlive it; setting `p_lag` at
-- or above that bound makes "every row with performed_at <= now() - p_lag is
-- final" a guarantee, so no row is ever skipped. A smaller lag trades that
-- guarantee for lower latency (fine for at-least-once cache invalidation). For
-- strict exactly-once streaming, use logical replication on tuples_audit.
--
-- Push: the _audit_tuple trigger emits NOTIFY authz_changes (payload = store_id,
-- deduplicated to one per store per transaction). Treat it as a doorbell — on
-- notification, call watch_changes(after the last cursor) to pull the rows.
-- ============================================================================

CREATE OR REPLACE FUNCTION authz.watch_changes(
    p_store       text,
    p_after_at    timestamptz DEFAULT '-infinity',
    p_after_seq   bigint      DEFAULT 0,
    p_limit       int         DEFAULT 1000,
    p_lag          interval  DEFAULT '1 second',
    p_object_types text[]    DEFAULT NULL,   -- NULL = all types; else only these
    p_namespaces   text[]    DEFAULT NULL,   -- NULL = all; else only these namespaces (by the object type's namespace)
    p_relations    text[]    DEFAULT NULL    -- NULL = all; else only these relations (the changed tuple's relation)
) RETURNS TABLE (
    seq            bigint,
    action         text,
    performed_at   timestamptz,
    performed_by   text,
    user_type      text,
    user_id        text,
    user_relation  text,
    relation       text,
    object_type    text,
    object_id      text,
    condition_name text
)
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    -- Retired-inclusive: a consumer keeps draining a retired store's changefeed
    -- to receive its final events, including the STORE_RETIRED lifecycle event
    -- (which, being lag-gated, only becomes visible after the store is retired).
    v_store_id     integer := authz._s(p_store, true);
    v_object_types integer[] := CASE WHEN p_object_types IS NOT NULL
        THEN (SELECT array_agg(authz._t(v_store_id, t)) FROM unnest(p_object_types) AS t) END;
    v_relations    integer[] := CASE WHEN p_relations IS NOT NULL
        THEN (SELECT array_agg(authz._r(v_store_id, r)) FROM unnest(p_relations) AS r) END;
BEGIN
    RETURN QUERY
        SELECT a.seq,
               a.action,
               a.performed_at,
               a.performed_by,
               ut.name,
               a.user_id,
               ur.name,
               r.name,
               ot.name,
               a.object_id,
               c.name
          FROM authz.tuples_audit a
          -- LEFT joins so the store-level STORE_RETIRED event (sentinel type /
          -- relation ids that don't resolve) still surfaces; for ordinary tuple
          -- events the ids always resolve, so this is equivalent to inner joins.
     LEFT JOIN authz.types     ut ON ut.store_id = a.store_id AND ut.id = a.user_type
     LEFT JOIN authz.relations r  ON r.store_id  = a.store_id AND r.id  = a.relation
     LEFT JOIN authz.types     ot ON ot.store_id = a.store_id AND ot.id = a.object_type
     LEFT JOIN authz.relations ur ON ur.store_id = a.store_id AND ur.id = a.user_relation
     LEFT JOIN authz.conditions c ON c.store_id  = a.store_id AND c.id  = a.condition_id
         WHERE a.store_id = v_store_id
           AND (a.performed_at, a.seq) > (p_after_at, p_after_seq)
           AND a.performed_at <= clock_timestamp() - p_lag
           -- Store-lifecycle events are store-wide: they bypass the per-tuple
           -- type / namespace / relation filters so a narrowly-scoped watcher
           -- still learns the whole store was retired.
           AND (a.action = 'STORE_RETIRED' OR p_object_types IS NULL OR a.object_type = ANY(v_object_types))
           AND (a.action = 'STORE_RETIRED' OR p_namespaces   IS NULL OR ot.namespace  = ANY(p_namespaces))
           AND (a.action = 'STORE_RETIRED' OR p_relations    IS NULL OR a.relation     = ANY(v_relations))
         ORDER BY a.performed_at, a.seq
         LIMIT p_limit;
END;
$$;

-- watch_cursor: the store's current high-water (performed_at, seq). A consumer
-- that only wants future changes can start here; a consumer that needs a robust
-- resume should persist the (performed_at, seq) of the last row it processed.
CREATE OR REPLACE FUNCTION authz.watch_cursor(p_store text)
RETURNS TABLE (at timestamptz, seq bigint)
LANGUAGE sql STABLE AS $$
    SELECT max(performed_at), max(seq)
      FROM authz.tuples_audit
     WHERE store_id = authz._s(p_store, true);   -- retired-inclusive, like watch_changes
$$;
