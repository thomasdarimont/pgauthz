-- Materialized permissions: a flat, denormalized table that app databases
-- can subscribe to without needing the authz schema or functions — the
-- pgauthz equivalent of a hosted "permissions index".
--
-- Three tables travel together (publication authz_derived):
--
--   authz.materialized_permissions  (store, user_type, user_id, permission, object_type, object_id)
--   authz.materialized_subjects     (store, user_type, user_id)     — subjects the engine knows
--   authz.materialized_objects      (store, object_type, object_id) — objects the engine knows
--
-- THE WILDCARD CONTRACT. The engine cannot expand an object wildcard
-- (document:*) — it does not know the application's object universe — and
-- will not enumerate every user for a subject wildcard (employee:*). Such
-- grants are stored as literal '*' rows instead, and a '*' row is correct
-- ONLY for a subject or object the engine does not know: a known subject or
-- object has authoritative concrete rows (exclusions, markers and
-- intersections already applied), while an unknown one has no tuples and
-- therefore nothing that could narrow the wildcard. Hence the two side
-- tables. The subscriber-side helper authz.check_permission() in
-- schema-derived.sql implements the rule:
--
--   subject keys = {user_id}   ∪ {'*' if (store, user_type, user_id) ∉ materialized_subjects}
--   object keys  = {object_id} ∪ {'*' if (store, object_type, object_id) ∉ materialized_objects}
--   allowed      = EXISTS row WITH user_id IN subject keys AND object_id IN object keys
--
-- Consumers that join on the table directly must apply the same rule, or
-- call the helper (a single inlinable SQL expression).
--
-- WHAT A PRECOMPUTED ROW CANNOT HOLD: conditions and contextual tuples are
-- evaluated with no request context (fail-closed, the conditional grant is
-- absent), and temporal gates are not evaluated at all (they are per-principal
-- history). The refresh goes through authz._decide with an empty gate list.
-- Decisions that must be exact at the moment of the request stay on the
-- live check_access.
--
-- Change-driven: a trigger on authz.tuples queues affected objects for
-- re-evaluation and sends a NOTIFY. The queue is processed either:
--   - Explicitly: SELECT authz.process_permissions_refresh_queue();
--   - Via pg_cron: schedule periodic processing
--   - Via external worker: LISTEN authz_permissions_changed
--
-- INSTALL ORDER AND OWNERSHIP. Load after the engine (the functions call
-- authz._decide). The refresh functions are SECURITY DEFINER so that the
-- engine's per-session memo table is always created under one role (mixing
-- an invoker-run graph walk with the definer-run public check_access in one
-- session fails with "permission denied for table _check_memo_v2"). When
-- authz_owner exists (db/security/roles.sql has run) the block at the end
-- transfers ownership to it; re-running roles.sql does the same. The worker
-- that processes the queue needs only EXECUTE on
-- process_permissions_refresh_queue().

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
-- The side tables of the wildcard contract (see header): every subject
-- and every object that has at least one tuple in the store. A '*' row
-- in materialized_permissions applies only to entities NOT listed here.
------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.materialized_subjects (
    store         text    NOT NULL,
    user_type     text    NOT NULL,
    user_id       text    NOT NULL,
    refreshed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (store, user_type, user_id)
);

CREATE TABLE IF NOT EXISTS authz.materialized_objects (
    store         text    NOT NULL,
    object_type   text    NOT NULL,
    object_id     text    NOT NULL,
    refreshed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (store, object_type, object_id)
);

------------------------------------------------------------------------
-- Refresh queue: tracks which objects need permission re-evaluation.
------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.permissions_refresh_queue (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    store_id    integer NOT NULL,
    object_type integer NOT NULL,
    object_id   text     NOT NULL,
    queued_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);

------------------------------------------------------------------------
-- _refresh_permissions_for_object: re-evaluates all permissions for one
-- object (or for the wildcard pseudo-object '*', whose rows are the
-- answer for objects the engine does not know). Iterates every subject
-- known to the store — including the '*' subject when a subject-wildcard
-- tuple exists, whose rows are the answer for unknown subjects — against
-- every relation defined on the object type, through authz._decide with
-- an empty gate list (graph only, no request context).
--
-- Also keeps the side tables current: the object is listed in
-- materialized_objects while it has tuples and delisted when it has
-- none; every iterated concrete subject is listed in
-- materialized_subjects (vanished subjects are swept by
-- process_permissions_refresh_queue).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._refresh_permissions_for_object(
    p_store_id    integer,
    p_object_type integer,
    p_object_id   text
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_store_name  text;
    v_type_name   text;
    v_count       integer := 0;
    v_rel         record;
    v_user        record;
BEGIN
    SELECT name INTO v_store_name FROM authz.stores WHERE id = p_store_id;
    SELECT name INTO v_type_name  FROM authz.types  WHERE id = p_object_type;
    IF v_store_name IS NULL OR v_type_name IS NULL THEN
        RETURN 0;   -- store or type removed meanwhile; nothing to derive
    END IF;

    -- Delete existing permissions for this object
    DELETE FROM authz.materialized_permissions
     WHERE store = v_store_name
       AND object_type = v_type_name
       AND object_id = p_object_id;

    -- Side table: known object ⇔ has at least one tuple ('*' is not an object)
    IF p_object_id <> '*' THEN
        IF EXISTS (SELECT 1 FROM authz.tuples t
                    WHERE t.store_id = p_store_id AND t.object_type = p_object_type
                      AND t.object_id = p_object_id) THEN
            INSERT INTO authz.materialized_objects (store, object_type, object_id)
            VALUES (v_store_name, v_type_name, p_object_id)
            ON CONFLICT (store, object_type, object_id) DO UPDATE SET refreshed_at = now();
        ELSE
            DELETE FROM authz.materialized_objects
             WHERE store = v_store_name AND object_type = v_type_name AND object_id = p_object_id;
            RETURN 0;   -- no tuples ⇒ the '*' rows (if any) are the answer
        END IF;
    END IF;

    -- For each relation defined on this object type...
    FOR v_rel IN
        SELECT DISTINCT r.name AS relation_name, r.id AS relation_id
          FROM authz.models m
          JOIN authz.relations r ON r.id = m.relation
         WHERE m.store_id = p_store_id
           AND m.object_type = p_object_type
    LOOP
        -- For each user type + user_id known to this store (direct subjects
        -- only; usersets are object references). The '*' subject rides along
        -- when a subject-wildcard tuple exists — its rows are the answer for
        -- subjects the engine does not know.
        FOR v_user IN
            SELECT DISTINCT t2.name AS type_name, t2.id AS type_id, t.user_id
              FROM authz.tuples t
              JOIN authz.types t2 ON t2.id = t.user_type
             WHERE t.store_id = p_store_id
               AND t.user_relation IS NULL
               AND t2.store_id = p_store_id
        LOOP
            IF v_user.user_id <> '*' THEN
                INSERT INTO authz.materialized_subjects (store, user_type, user_id)
                VALUES (v_store_name, v_user.type_name, v_user.user_id)
                ON CONFLICT (store, user_type, user_id) DO NOTHING;
            END IF;

            -- Graph-only decision: no request context, no gates.
            IF authz._decide(
                p_store_id,
                v_user.type_id,
                v_user.user_id,
                v_rel.relation_id,
                p_object_type,
                p_object_id,
                NULL, false, '[]'::jsonb
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
-- _sweep_materialized_subjects: delist subjects that no longer have any
-- tuple in the store and drop their rows. Once unknown, a subject is
-- covered by the '*' rows (nothing can narrow a wildcard for it any more).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._sweep_materialized_subjects(p_store_id integer)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_store_name text;
    v_gone       integer := 0;
BEGIN
    SELECT name INTO v_store_name FROM authz.stores WHERE id = p_store_id;
    IF v_store_name IS NULL THEN RETURN 0; END IF;

    WITH gone AS (
        DELETE FROM authz.materialized_subjects s
         WHERE s.store = v_store_name
           AND NOT EXISTS (
               SELECT 1 FROM authz.tuples t
               JOIN authz.types ut ON ut.id = t.user_type
                WHERE t.store_id = p_store_id
                  AND t.user_relation IS NULL
                  AND ut.name = s.user_type
                  AND t.user_id = s.user_id)
        RETURNING s.user_type, s.user_id
    ),
    purged AS (
        DELETE FROM authz.materialized_permissions p
         USING gone g
         WHERE p.store = v_store_name
           AND p.user_type = g.user_type
           AND p.user_id = g.user_id
        RETURNING 1
    )
    SELECT count(*) INTO v_gone FROM gone;

    RETURN v_gone;
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
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_total  integer := 0;
    v_count  integer;
    v_rec    record;
    v_stores integer[] := '{}';
    v_store  integer;
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
        IF NOT v_rec.store_id = ANY (v_stores) THEN
            v_stores := v_stores || v_rec.store_id;
        END IF;
    END LOOP;

    -- Subjects that lost their last tuple become unknown (wildcard-covered).
    FOREACH v_store IN ARRAY v_stores LOOP
        PERFORM authz._sweep_materialized_subjects(v_store);
    END LOOP;

    RETURN v_total;
END;
$$;

------------------------------------------------------------------------
-- Full refresh: rebuild all materialized permissions (and the side
-- tables) for a store. Useful for initial population and periodic
-- consistency checks.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.refresh_all_materialized_permissions(
    p_store text
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_total    integer := 0;
    v_count    integer;
    v_obj      record;
BEGIN
    DELETE FROM authz.materialized_permissions WHERE store = p_store;
    DELETE FROM authz.materialized_subjects    WHERE store = p_store;
    DELETE FROM authz.materialized_objects     WHERE store = p_store;

    -- Every object with tuples, plus the '*' pseudo-object whenever an
    -- object-wildcard tuple exists (its rows answer for unknown objects).
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
--
-- SECURITY DEFINER: tuple writes reach authz.tuples through the engine's
-- BYPASSRLS helper (authz._rls_upsert_tuple, owned by a role that owns
-- nothing else), so the trigger must not depend on the writer's
-- privileges to insert into the queue.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._queue_permissions_refresh()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_row    authz.tuples;
    v_parent record;
BEGIN
    v_row := COALESCE(NEW, OLD);

    -- Queue the directly affected object
    INSERT INTO authz.permissions_refresh_queue (store_id, object_type, object_id)
    VALUES (v_row.store_id, v_row.object_type, v_row.object_id);

    -- An object-wildcard grant (object_id = '*') changes the answer for
    -- EVERY object of the type: known objects carry authoritative concrete
    -- rows, so each must be re-derived, along with the objects that
    -- reference any of them (two levels, as below). A wildcard write is a
    -- privileged, rare operation; re-deriving the whole type is the price.
    IF v_row.object_id = '*' THEN
        INSERT INTO authz.permissions_refresh_queue (store_id, object_type, object_id)
        SELECT DISTINCT t.store_id, t.object_type, t.object_id
          FROM authz.tuples t
         WHERE t.store_id = v_row.store_id
           AND t.object_type = v_row.object_type;

        INSERT INTO authz.permissions_refresh_queue (store_id, object_type, object_id)
        WITH level1 AS (
            SELECT DISTINCT t.object_type, t.object_id
              FROM authz.tuples t
             WHERE t.store_id  = v_row.store_id
               AND t.user_type = v_row.object_type)
        SELECT v_row.store_id, l.object_type, l.object_id FROM level1 l
        UNION
        SELECT v_row.store_id, t2.object_type, t2.object_id
          FROM authz.tuples t2
          JOIN level1 l ON l.object_type = t2.user_type AND l.object_id = t2.user_id
         WHERE t2.store_id = v_row.store_id;
    END IF;

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

------------------------------------------------------------------------
-- Ownership: when roles.sql has created authz_owner, the definer
-- functions and the tables must belong to it (same role as the rest of
-- the engine). Idempotent; a no-op before roles.sql has run.
------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authz_owner') THEN
        -- OWNER TO does not recurse into partitions: name them all.
        FOR r IN
            SELECT c.oid::regclass AS obj
              FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'authz'
               AND c.relkind IN ('r', 'p')
               AND (c.relname LIKE 'materialized\_%' OR c.relname = 'permissions_refresh_queue')
        LOOP
            EXECUTE format('ALTER TABLE %s OWNER TO authz_owner', r.obj);
        END LOOP;
        ALTER FUNCTION authz._refresh_permissions_for_object(integer, integer, text) OWNER TO authz_owner;
        ALTER FUNCTION authz._sweep_materialized_subjects(integer)                   OWNER TO authz_owner;
        ALTER FUNCTION authz.process_permissions_refresh_queue()                     OWNER TO authz_owner;
        ALTER FUNCTION authz.refresh_all_materialized_permissions(text)              OWNER TO authz_owner;
        ALTER FUNCTION authz._queue_permissions_refresh()                            OWNER TO authz_owner;
    END IF;
END;
$$;

-- Internal helpers are not for app roles.
REVOKE ALL ON FUNCTION authz._refresh_permissions_for_object(integer, integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._sweep_materialized_subjects(integer)                   FROM PUBLIC;
