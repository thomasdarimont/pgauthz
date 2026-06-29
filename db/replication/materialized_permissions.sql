-- Materialized permissions: a flat, denormalized table that app databases
-- can subscribe to without needing the authz schema or functions.
--
-- The app just queries:
--   SELECT EXISTS(
--       SELECT 1 FROM authz.materialized_permissions
--        WHERE store = 'demo' AND user_type = 'internal_user' AND user_id = 'eva'
--          AND permission = 'can_read' AND object_type = 'document' AND object_id = 'doc_acc_001'
--   );
--
-- Change-driven: a trigger on authz.tuples queues affected objects for
-- re-evaluation and sends a NOTIFY. The queue is processed either:
--   - Explicitly: SELECT authz.process_permissions_refresh_queue();
--   - Via pg_cron: schedule periodic processing
--   - Via external worker: LISTEN authz_permissions_changed

------------------------------------------------------------------------
-- The derived permissions table.
-- Hash-partitioned by (store, user_id) for partition pruning on the
-- primary access pattern: "can user X do Y on Z?"
------------------------------------------------------------------------
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

-- 8 hash partitions (same modulus as the document tuple partitions).
CREATE TABLE IF NOT EXISTS authz.materialized_permissions_0 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 0);
CREATE TABLE IF NOT EXISTS authz.materialized_permissions_1 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 1);
CREATE TABLE IF NOT EXISTS authz.materialized_permissions_2 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 2);
CREATE TABLE IF NOT EXISTS authz.materialized_permissions_3 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 3);
CREATE TABLE IF NOT EXISTS authz.materialized_permissions_4 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 4);
CREATE TABLE IF NOT EXISTS authz.materialized_permissions_5 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 5);
CREATE TABLE IF NOT EXISTS authz.materialized_permissions_6 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 6);
CREATE TABLE IF NOT EXISTS authz.materialized_permissions_7 PARTITION OF authz.materialized_permissions FOR VALUES WITH (MODULUS 8, REMAINDER 7);

------------------------------------------------------------------------
-- Refresh queue: tracks which objects need permission re-evaluation.
------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.permissions_refresh_queue (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    store_id    smallint NOT NULL,
    object_type smallint NOT NULL,
    object_id   text     NOT NULL,
    queued_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);

------------------------------------------------------------------------
-- refresh_permissions_for_object: re-evaluates all permissions for one object.
-- Finds all user types and user IDs that appear in tuples for this store,
-- then checks each against all defined relations for the object type.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._refresh_permissions_for_object(
    p_store_id    smallint,
    p_object_type smallint,
    p_object_id   text
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_name  text;
    v_type_name   text;
    v_count       integer := 0;
    v_rel         record;
    v_user        record;
BEGIN
    SELECT name INTO v_store_name FROM authz.stores WHERE id = p_store_id;
    SELECT name INTO v_type_name  FROM authz.types  WHERE id = p_object_type;

    -- Delete existing permissions for this object
    DELETE FROM authz.materialized_permissions
     WHERE store = v_store_name
       AND object_type = v_type_name
       AND object_id = p_object_id;

    -- For each relation defined on this object type...
    FOR v_rel IN
        SELECT DISTINCT r.name AS relation_name, r.id AS relation_id
          FROM authz.models m
          JOIN authz.relations r ON r.id = m.relation
         WHERE m.store_id = p_store_id
           AND m.object_type = p_object_type
    LOOP
        -- For each user type + user_id known to this store...
        FOR v_user IN
            SELECT DISTINCT t2.name AS type_name, t.user_id
              FROM authz.tuples t
              JOIN authz.types t2 ON t2.id = t.user_type
             WHERE t.store_id = p_store_id
               AND t.user_relation IS NULL
               AND t2.store_id = p_store_id
        LOOP
            -- Check if this user has this permission
            IF authz._check_access(
                p_store_id,
                (SELECT id FROM authz.types WHERE store_id = p_store_id AND name = v_user.type_name),
                v_user.user_id,
                v_rel.relation_id,
                p_object_type,
                p_object_id
            ) THEN
                INSERT INTO authz.materialized_permissions
                    (store, user_type, user_id, permission, object_type, object_id)
                VALUES
                    (v_store_name, v_user.type_name, v_user.user_id,
                     v_rel.relation_name, v_type_name, p_object_id)
                ON CONFLICT DO NOTHING;
                v_count := v_count + 1;
            END IF;
        END LOOP;
    END LOOP;

    RETURN v_count;
END;
$$;

------------------------------------------------------------------------
-- process_permissions_refresh_queue: processes all pending queue entries.
-- Returns the number of permissions refreshed.
--
-- Entries are claimed and removed in a single DELETE so that entries
-- enqueued by concurrent writers while processing runs stay queued for
-- the next run (a separate unqualified DELETE would discard them
-- unprocessed). FOR UPDATE SKIP LOCKED skips entries already claimed
-- by another worker, so multiple workers can run this concurrently.
-- If the transaction aborts mid-refresh, the claim rolls back and the
-- entries remain queued.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.process_permissions_refresh_queue()
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_total  integer := 0;
    v_count  integer;
    v_rec    record;
BEGIN
    -- Claim pending entries, deduplicated per object (multiple changes
    -- to the same object need only one refresh).
    FOR v_rec IN
        WITH claimed AS (
            DELETE FROM authz.permissions_refresh_queue
             WHERE id IN (
                 SELECT id FROM authz.permissions_refresh_queue
                  FOR UPDATE SKIP LOCKED
             )
             RETURNING store_id, object_type, object_id
        )
        SELECT DISTINCT store_id, object_type, object_id FROM claimed
    LOOP
        v_count := authz._refresh_permissions_for_object(
            v_rec.store_id, v_rec.object_type, v_rec.object_id
        );
        v_total := v_total + v_count;
    END LOOP;

    RETURN v_total;
END;
$$;

------------------------------------------------------------------------
-- Full refresh: rebuild all materialized permissions for a store.
-- Useful for initial population and periodic consistency checks.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.refresh_all_materialized_permissions(
    p_store text
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id smallint := authz._s(p_store);
    v_total    integer := 0;
    v_count    integer;
    v_obj      record;
BEGIN
    DELETE FROM authz.materialized_permissions WHERE store = p_store;

    FOR v_obj IN
        SELECT DISTINCT t.object_type, t.object_id
          FROM authz.tuples t
         WHERE t.store_id = v_store_id
    LOOP
        v_count := authz._refresh_permissions_for_object(
            v_store_id, v_obj.object_type, v_obj.object_id
        );
        v_total := v_total + v_count;
    END LOOP;

    RETURN v_total;
END;
$$;

------------------------------------------------------------------------
-- Trigger: queue affected objects for re-evaluation on tuple changes.
--
-- Only queues — does NOT process. Processing happens either:
--   a) Explicitly via SELECT authz.process_permissions_refresh_queue();
--   b) Via pg_cron (production): SELECT cron.schedule('* * * * *',
--        'SELECT authz.process_permissions_refresh_queue()');
--   c) Via LISTEN/NOTIFY with an external worker
--
-- On INSERT/DELETE, the directly affected object is queued.
-- Additionally, any objects that reference the changed tuple's object
-- via tupleset relations are also queued (reverse TTU traversal),
-- because their computed permissions may have changed.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._queue_permissions_refresh()
RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_row    authz.tuples;
    v_parent record;
BEGIN
    v_row := COALESCE(NEW, OLD);

    -- Queue the directly affected object
    INSERT INTO authz.permissions_refresh_queue (store_id, object_type, object_id)
    VALUES (v_row.store_id, v_row.object_type, v_row.object_id);

    -- Queue objects that reference this object via tupleset relations.
    -- Example: changing team membership → re-evaluate assignments that
    -- reference the team via userset, and their parent objects.
    FOR v_parent IN
        SELECT DISTINCT t.object_type, t.object_id
          FROM authz.tuples t
         WHERE t.store_id  = v_row.store_id
           AND t.user_type = v_row.object_type
           AND t.user_id   = v_row.object_id
    LOOP
        INSERT INTO authz.permissions_refresh_queue (store_id, object_type, object_id)
        VALUES (v_row.store_id, v_parent.object_type, v_parent.object_id);

        -- Second level: objects referencing the parent (e.g., documents in a data space)
        INSERT INTO authz.permissions_refresh_queue (store_id, object_type, object_id)
        SELECT DISTINCT t2.store_id, t2.object_type, t2.object_id
          FROM authz.tuples t2
         WHERE t2.store_id  = v_row.store_id
           AND t2.user_type = v_parent.object_type
           AND t2.user_id   = v_parent.object_id;
    END LOOP;

    -- Notify listeners that the queue has new entries.
    PERFORM pg_notify('authz_permissions_changed', '');

    RETURN v_row;
END;
$$;

-- Attach the trigger to the tuples table (fires for all partitions).
DROP TRIGGER IF EXISTS trg_queue_permissions_refresh ON authz.tuples;
CREATE TRIGGER trg_queue_permissions_refresh
    AFTER INSERT OR UPDATE OR DELETE ON authz.tuples
    FOR EACH ROW
    EXECUTE FUNCTION authz._queue_permissions_refresh();
