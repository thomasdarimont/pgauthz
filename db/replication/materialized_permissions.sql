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
-- INCREMENTAL, CHANGEFEED-DRIVEN. The source of change is the audit
-- changefeed, authz.watch_changes (AUDIT.md → Watching for changes): a store
-- is registered by refresh_all_materialized_permissions(), which takes the
-- initial snapshot and records a (performed_at, seq) cursor just before it.
-- A worker — SELECT authz.refresh_materialized_permissions(), run from
-- pg_cron, on LISTEN authz_changes (the audit log's own doorbell), or in a
-- loop — pulls one lag-gated page of the feed per registered store, resumes
-- from the stored cursor after a crash, and for each delta re-derives only
-- the (subject, object) pairs whose answer can have changed:
--
--   objects  = the delta's object plus every object that reaches it through
--              tuples (reverse closure over tuple edges, full depth, cycle
--              safe); an object-wildcard delta ('*') seeds every object of
--              the type
--   subjects = the delta's own subject when it is a plain principal (the
--              model defines no relation on its type, so it can never be an
--              edge); every known subject of the type for a subject-wildcard
--              delta; every known subject when the delta's subject is a
--              userset or an object reference (team#member, parent folder,
--              a classification) — the safe over-approximation
--   relations = every relation of the object's type
--
-- Each pair's allowed relations are recomputed and DIFFED against the stored
-- rows, so the table only ever receives real inserts and deletes (a CDC
-- consumer sees deltas). Objects that lost their last tuple and subjects
-- that lost theirs are delisted and lose their rows (they are wildcard
-- covered from then on).
--
-- EXPIRY. The feed reports writes, not the passing of time, so for every
-- inserted tuple that carries expires_at the worker files a deferred delta
-- in authz.permissions_refresh_queue, due at that instant; refresh_all files
-- one per expiring tuple of the store. When it falls due the tuple is
-- already invisible to the engine and the rows it granted are withdrawn.
--
-- FRESHNESS. authz.materialized_refresh_state (one row per registered store,
-- replicated) carries the cursor and `as_of`: every change performed before
-- as_of is reflected. authz.materialized_permissions_status() on the primary,
-- authz.permissions_as_of(store) on the subscriber. The feed's stability lag
-- (p_lag, default 1 s; see watch_changes) bounds how soon a change can be
-- picked up — and must stay at or above the writers' statement_timeout for
-- the "no row is ever skipped" guarantee.
--
-- REQUIRES the audit profile (tuples_audit + watch_changes), i.e. a full
-- install.
--
-- INSTALL ORDER AND OWNERSHIP. Load after the engine (the functions call
-- authz._decide and authz.watch_changes). The refresh functions are
-- SECURITY DEFINER so that the engine's per-session memo table is always
-- created under one role (mixing an invoker-run graph walk with the
-- definer-run public check_access in one session fails with "permission
-- denied for table _check_memo_v2"). When authz_owner exists
-- (db/security/roles.sql has run) the block at the end transfers ownership
-- to it; re-running roles.sql does the same. The worker role needs only
-- EXECUTE on refresh_materialized_permissions().

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
-- Deferred deltas: one row per expiring tuple, due at its expiry (filed
-- by the worker from the feed and by refresh_all). Claimed and deleted
-- by the worker when due. Manual whole-object entries (subject columns
-- NULL) are accepted too and re-derive the object for every subject.
------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.permissions_refresh_queue (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    store_id      integer NOT NULL,
    object_type   integer NOT NULL,
    object_id     text    NOT NULL,
    relation      integer,
    user_type     integer,
    user_id       text,
    user_relation integer,
    op            text,                 -- EXPIRE | MANUAL
    queued_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    due_at        timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- Upgrade of a pre-incremental queue (whole-object rows): add the columns.
ALTER TABLE authz.permissions_refresh_queue
    ADD COLUMN IF NOT EXISTS relation      integer,
    ADD COLUMN IF NOT EXISTS user_type     integer,
    ADD COLUMN IF NOT EXISTS user_id       text,
    ADD COLUMN IF NOT EXISTS user_relation integer,
    ADD COLUMN IF NOT EXISTS op            text,
    ADD COLUMN IF NOT EXISTS due_at        timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE INDEX IF NOT EXISTS idx_permissions_refresh_queue_due ON authz.permissions_refresh_queue (due_at);

------------------------------------------------------------------------
-- Per-store cursor and freshness. Replicated with the permissions, so
-- the subscriber can tell how stale its copy may be.
------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.materialized_refresh_state (
    store                 text PRIMARY KEY,
    cursor_at             timestamptz NOT NULL,   -- watch_changes cursor: last (performed_at, seq) applied
    cursor_seq            bigint      NOT NULL DEFAULT 0,
    as_of                 timestamptz NOT NULL,   -- every change performed before this instant is reflected
    feed_drained          boolean     NOT NULL DEFAULT true,  -- the last page was not full
    last_run_started_at   timestamptz,
    last_run_finished_at  timestamptz,
    last_run_changes      integer NOT NULL DEFAULT 0,  -- feed rows + due deferred rows, this store
    last_run_pairs        integer NOT NULL DEFAULT 0,  -- (subject, object) pairs re-derived, whole run
    last_run_rows_written integer NOT NULL DEFAULT 0   -- permission rows inserted + deleted, whole run
);

------------------------------------------------------------------------
-- Session work tables. Created under the definer role (the same role the
-- engine's memo table uses), truncated on every run.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._mp_prepare_pairs()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS _mp_pairs (
        store_id    integer NOT NULL,
        object_type integer NOT NULL,
        object_id   text    NOT NULL,
        user_type   integer NOT NULL,
        user_id     text    NOT NULL,
        PRIMARY KEY (store_id, object_type, object_id, user_type, user_id));
    TRUNCATE _mp_pairs;
    CREATE TEMP TABLE IF NOT EXISTS _mp_claimed (
        id            bigint GENERATED ALWAYS AS IDENTITY,
        store_id      integer, object_type integer, object_id text, relation integer,
        user_type     integer, user_id text, user_relation integer, op text);
    TRUNCATE _mp_claimed RESTART IDENTITY;
END;
$$;

------------------------------------------------------------------------
-- _derive_pairs: re-derive every (subject, object) pair in _mp_pairs.
--
--   1. resolve every object and every subject of the pairs — names and
--      whether it still has tuples — BEFORE any pruning, so an object and a
--      subject that vanished in the same change are both seen
--   2. objects without tuples are delisted and lose all their rows (the
--      '*' rows, if any, answer for them from now on); the rest are listed
--   3. subjects without tuples likewise
--   4. each remaining pair is decided for every relation of the object's
--      type through authz._decide with an empty gate list (graph only, no
--      request context), and the result is diffed against the stored rows:
--      rows no longer allowed are deleted, new ones inserted
--
-- Returns the pairs decided and the rows written (inserts + deletes).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._derive_pairs(OUT pairs integer, OUT rows_written integer)
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_n integer;
BEGIN
    rows_written := 0;

    -- 1. resolve
    CREATE TEMP TABLE IF NOT EXISTS _mp_objects (
        store_id integer, object_type integer, object_id text,
        store text, type_name text, has_tuples boolean,
        PRIMARY KEY (store_id, object_type, object_id));
    CREATE TEMP TABLE IF NOT EXISTS _mp_subjects (
        store_id integer, user_type integer, user_id text,
        store text, type_name text, has_tuples boolean,
        PRIMARY KEY (store_id, user_type, user_id));
    TRUNCATE _mp_objects, _mp_subjects;

    INSERT INTO _mp_objects
    SELECT DISTINCT p.store_id, p.object_type, p.object_id, s.name, ot.name,
           EXISTS (SELECT 1 FROM authz.tuples t
                    WHERE t.store_id = p.store_id AND t.object_type = p.object_type
                      AND t.object_id = p.object_id)
      FROM _mp_pairs p
      JOIN authz.stores s  ON s.id  = p.store_id
      JOIN authz.types  ot ON ot.id = p.object_type;

    INSERT INTO _mp_subjects
    SELECT DISTINCT p.store_id, p.user_type, p.user_id, s.name, ut.name,
           EXISTS (SELECT 1 FROM authz.tuples t
                    WHERE t.store_id = p.store_id AND t.user_type = p.user_type
                      AND t.user_id = p.user_id AND t.user_relation IS NULL)
      FROM _mp_pairs p
      JOIN authz.stores s  ON s.id  = p.store_id
      JOIN authz.types  ut ON ut.id = p.user_type;

    -- 2. objects without tuples
    DELETE FROM authz.materialized_permissions mp
     USING _mp_objects o
     WHERE NOT o.has_tuples
       AND mp.store = o.store AND mp.object_type = o.type_name AND mp.object_id = o.object_id;
    GET DIAGNOSTICS v_n = ROW_COUNT; rows_written := rows_written + v_n;

    DELETE FROM authz.materialized_objects mo
     USING _mp_objects o
     WHERE NOT o.has_tuples
       AND mo.store = o.store AND mo.object_type = o.type_name AND mo.object_id = o.object_id;

    INSERT INTO authz.materialized_objects (store, object_type, object_id)
    SELECT o.store, o.type_name, o.object_id FROM _mp_objects o
     WHERE o.has_tuples AND o.object_id <> '*'
    ON CONFLICT (store, object_type, object_id) DO NOTHING;

    DELETE FROM _mp_pairs p
     USING _mp_objects o
     WHERE NOT o.has_tuples
       AND p.store_id = o.store_id AND p.object_type = o.object_type AND p.object_id = o.object_id;

    -- 3. subjects without tuples
    DELETE FROM authz.materialized_permissions mp
     USING _mp_subjects su
     WHERE NOT su.has_tuples
       AND mp.store = su.store AND mp.user_type = su.type_name AND mp.user_id = su.user_id;
    GET DIAGNOSTICS v_n = ROW_COUNT; rows_written := rows_written + v_n;

    DELETE FROM authz.materialized_subjects ms
     USING _mp_subjects su
     WHERE NOT su.has_tuples
       AND ms.store = su.store AND ms.user_type = su.type_name AND ms.user_id = su.user_id;

    INSERT INTO authz.materialized_subjects (store, user_type, user_id)
    SELECT su.store, su.type_name, su.user_id FROM _mp_subjects su
     WHERE su.has_tuples AND su.user_id <> '*'
    ON CONFLICT (store, user_type, user_id) DO NOTHING;

    DELETE FROM _mp_pairs p
     USING _mp_subjects su
     WHERE NOT su.has_tuples
       AND p.store_id = su.store_id AND p.user_type = su.user_type AND p.user_id = su.user_id;

    SELECT count(*) INTO pairs FROM _mp_pairs;

    -- 4. decide and diff
    CREATE TEMP TABLE IF NOT EXISTS _mp_want (
        store text, user_type text, user_id text, permission text,
        object_type text, object_id text, allowed boolean);
    TRUNCATE _mp_want;
    INSERT INTO _mp_want
    SELECT o.store, su.type_name, p.user_id, r.name, o.type_name, p.object_id,
           authz._decide(p.store_id, p.user_type, p.user_id, r.id, p.object_type, p.object_id,
                         NULL, false, '[]'::jsonb)
      FROM _mp_pairs p
      JOIN _mp_objects  o  ON o.store_id = p.store_id AND o.object_type = p.object_type AND o.object_id = p.object_id
      JOIN _mp_subjects su ON su.store_id = p.store_id AND su.user_type = p.user_type AND su.user_id = p.user_id
      JOIN (SELECT DISTINCT m.store_id, m.object_type, m.relation FROM authz.models m) m
        ON m.store_id = p.store_id AND m.object_type = p.object_type
      JOIN authz.relations r ON r.id = m.relation;

    DELETE FROM authz.materialized_permissions mp
     USING _mp_pairs p
      JOIN _mp_objects  o  ON o.store_id = p.store_id AND o.object_type = p.object_type AND o.object_id = p.object_id
      JOIN _mp_subjects su ON su.store_id = p.store_id AND su.user_type = p.user_type AND su.user_id = p.user_id
     WHERE mp.store = o.store AND mp.object_type = o.type_name AND mp.object_id = p.object_id
       AND mp.user_type = su.type_name AND mp.user_id = p.user_id
       AND NOT EXISTS (SELECT 1 FROM _mp_want w
                        WHERE w.allowed
                          AND w.store = mp.store AND w.user_type = mp.user_type AND w.user_id = mp.user_id
                          AND w.object_type = mp.object_type AND w.object_id = mp.object_id
                          AND w.permission = mp.permission);
    GET DIAGNOSTICS v_n = ROW_COUNT; rows_written := rows_written + v_n;

    INSERT INTO authz.materialized_permissions (store, user_type, user_id, permission, object_type, object_id)
    SELECT w.store, w.user_type, w.user_id, w.permission, w.object_type, w.object_id
      FROM _mp_want w WHERE w.allowed
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_n = ROW_COUNT; rows_written := rows_written + v_n;
END;
$$;

------------------------------------------------------------------------
-- _mp_blast_radius: turn the deltas in _mp_claimed into (subject, object)
-- pairs in _mp_pairs (see the header for the rule).
--
-- Procedural on purpose: every lookup into authz.tuples carries constant
-- keys (store, type, id), so it is one index probe per partition. A
-- single set-based query with the keys coming from a CTE made the planner
-- hash-join the whole tuples table — every store, every partition — per
-- delta (4 s on a database with large benchmark stores next to a tiny one).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._mp_blast_radius()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    r record;
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS _mp_known (
        store_id integer, user_type integer, user_id text,
        PRIMARY KEY (store_id, user_type, user_id));
    CREATE TEMP TABLE IF NOT EXISTS _mp_principal (
        store_id integer, user_type integer,
        PRIMARY KEY (store_id, user_type));
    CREATE TEMP TABLE IF NOT EXISTS _mp_closure (
        delta_id bigint, store_id integer, object_type integer, object_id text,
        PRIMARY KEY (delta_id, store_id, object_type, object_id));
    CREATE TEMP TABLE IF NOT EXISTS _mp_frontier (
        delta_id bigint, store_id integer, object_type integer, object_id text);
    CREATE TEMP TABLE IF NOT EXISTS _mp_next (LIKE _mp_frontier);
    TRUNCATE _mp_known, _mp_principal, _mp_closure, _mp_frontier, _mp_next;

    -- every subject each store knows
    FOR r IN SELECT DISTINCT c.store_id FROM _mp_claimed c LOOP
        INSERT INTO _mp_known
        SELECT DISTINCT r.store_id, t.user_type, t.user_id
          FROM authz.tuples t
         WHERE t.store_id = r.store_id AND t.user_relation IS NULL
        ON CONFLICT DO NOTHING;
    END LOOP;

    -- principal subject types: no relation is defined on the type in the
    -- MODEL, so no tuple can ever make one of its members an edge (a userset
    -- source, a parent, a manager). Decided from the model, not from the
    -- current tuples: a batch that deletes the last tuple on a type must not
    -- turn that type into a principal while its deltas are being processed
    -- — the deleted edge's delta is exactly the one that has to re-derive
    -- every subject above it. (A type with rules but used only as a
    -- principal is treated as a possible edge: safe over-approximation.)
    FOR r IN SELECT DISTINCT c.store_id, c.user_type FROM _mp_claimed c WHERE c.user_type IS NOT NULL LOOP
        IF NOT EXISTS (SELECT 1 FROM authz.models m
                        WHERE m.store_id = r.store_id AND m.object_type = r.user_type)
           AND NOT EXISTS (SELECT 1 FROM authz.tuples t
                            WHERE t.store_id = r.store_id AND t.object_type = r.user_type) THEN
            INSERT INTO _mp_principal VALUES (r.store_id, r.user_type) ON CONFLICT DO NOTHING;
        END IF;
    END LOOP;

    -- seeds: the delta's object; for an object wildcard, every object of the type
    INSERT INTO _mp_closure
    SELECT c.id, c.store_id, c.object_type, c.object_id FROM _mp_claimed c
    ON CONFLICT DO NOTHING;
    FOR r IN SELECT c.id, c.store_id, c.object_type FROM _mp_claimed c WHERE c.object_id = '*' LOOP
        INSERT INTO _mp_closure
        SELECT DISTINCT r.id, r.store_id, t.object_type, t.object_id
          FROM authz.tuples t
         WHERE t.store_id = r.store_id AND t.object_type = r.object_type
        ON CONFLICT DO NOTHING;
    END LOOP;

    -- reverse closure, breadth first: objects whose tuples reference a
    -- frontier object as their subject (usersets, parent references)
    INSERT INTO _mp_frontier SELECT delta_id, store_id, object_type, object_id FROM _mp_closure;
    LOOP
        TRUNCATE _mp_next;
        FOR r IN SELECT DISTINCT f.store_id, f.object_type, f.object_id FROM _mp_frontier f LOOP
            WITH ins AS (
                INSERT INTO _mp_closure
                SELECT f.delta_id, t.store_id, t.object_type, t.object_id
                  FROM _mp_frontier f
                  JOIN authz.tuples t ON t.store_id = r.store_id
                                     AND t.user_type = r.object_type AND t.user_id = r.object_id
                 WHERE f.store_id = r.store_id AND f.object_type = r.object_type AND f.object_id = r.object_id
                ON CONFLICT DO NOTHING
                RETURNING delta_id, store_id, object_type, object_id)
            INSERT INTO _mp_next SELECT * FROM ins;
        END LOOP;
        EXIT WHEN NOT EXISTS (SELECT 1 FROM _mp_next);
        TRUNCATE _mp_frontier;
        INSERT INTO _mp_frontier SELECT * FROM _mp_next;
    END LOOP;

    -- subjects per delta × the delta's closure
    INSERT INTO _mp_pairs (store_id, object_type, object_id, user_type, user_id)
    SELECT DISTINCT cl.store_id, cl.object_type, cl.object_id, s.user_type, s.user_id
      FROM _mp_closure cl
      JOIN (
            -- the delta's own direct subject, always (it may just have lost its last tuple)
            SELECT c.id AS delta_id, c.store_id, c.user_type, c.user_id
              FROM _mp_claimed c
             WHERE c.user_relation IS NULL AND c.user_type IS NOT NULL AND c.user_id IS NOT NULL
            UNION
            -- subject wildcard: every known subject of that type has authoritative rows
            SELECT c.id, c.store_id, k.user_type, k.user_id
              FROM _mp_claimed c
              JOIN _mp_known k ON k.store_id = c.store_id AND k.user_type = c.user_type
             WHERE c.user_relation IS NULL AND c.user_id = '*'
            UNION
            -- userset, object reference (non-principal type), or whole-object
            -- entry: every known subject
            SELECT c.id, c.store_id, k.user_type, k.user_id
              FROM _mp_claimed c
              JOIN _mp_known k ON k.store_id = c.store_id
             WHERE c.user_type IS NULL
                OR c.user_relation IS NOT NULL
                OR (c.user_id <> '*' AND NOT EXISTS (SELECT 1 FROM _mp_principal pr
                                                       WHERE pr.store_id = c.store_id AND pr.user_type = c.user_type))
           ) s ON s.delta_id = cl.delta_id
    ON CONFLICT DO NOTHING;
END;
$$;

------------------------------------------------------------------------
-- refresh_materialized_permissions: the worker. For every registered
-- store, pull one page of authz.watch_changes after the stored cursor
-- (p_limit rows, stability lag p_lag), file deferred deltas for inserted
-- tuples that expire, claim the deferred deltas that fell due, compute
-- the blast radius, re-derive, record cursor and as_of. Returns the
-- number of pairs re-derived; call again while any store's feed_drained
-- is false.
--
-- Deferred rows are claimed and deleted in one statement, FOR UPDATE SKIP
-- LOCKED; an aborted run rolls everything back, including the cursor, so
-- the page is replayed. One worker is the intended deployment: two workers
-- would pull the same page (a wasted but harmless double derivation).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.refresh_materialized_permissions(
    p_lag   interval DEFAULT '1 second',
    p_limit int      DEFAULT 1000
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_started  timestamptz := clock_timestamp();
    v_state    record;
    v_n        integer;
    v_last_at  timestamptz;
    v_last_seq bigint;
    v_pairs    integer := 0;
    v_written  integer := 0;
BEGIN
    PERFORM authz._mp_prepare_pairs();
    CREATE TEMP TABLE IF NOT EXISTS _mp_feed (
        store text, store_id integer, changes integer,
        last_at timestamptz, last_seq bigint, drained boolean);
    TRUNCATE _mp_feed;
    CREATE TEMP TABLE IF NOT EXISTS _mp_page (
        seq bigint, action text, performed_at timestamptz,
        user_type text, user_id text, user_relation text,
        relation text, object_type text, object_id text);

    FOR v_state IN
        SELECT s.store, s.cursor_at, s.cursor_seq, st.id AS store_id
          FROM authz.materialized_refresh_state s
          JOIN authz.stores st ON st.name = s.store
    LOOP
        TRUNCATE _mp_page;
        INSERT INTO _mp_page
        SELECT w.seq, w.action, w.performed_at, w.user_type, w.user_id, w.user_relation,
               w.relation, w.object_type, w.object_id
          FROM authz.watch_changes(v_state.store, v_state.cursor_at, v_state.cursor_seq, p_limit, p_lag) w;
        GET DIAGNOSTICS v_n = ROW_COUNT;

        SELECT pg.performed_at, pg.seq INTO v_last_at, v_last_seq
          FROM _mp_page pg ORDER BY pg.performed_at DESC, pg.seq DESC LIMIT 1;

        -- tuple deltas (lifecycle events and unresolvable names are skipped)
        INSERT INTO _mp_claimed (store_id, object_type, object_id, relation, user_type, user_id, user_relation, op)
        SELECT v_state.store_id, ot.id, pg.object_id, r.id, ut.id, pg.user_id, ur.id, pg.action
          FROM _mp_page pg
          JOIN authz.types     ot ON ot.store_id = v_state.store_id AND ot.name = pg.object_type
          JOIN authz.relations r  ON r.store_id  = v_state.store_id AND r.name  = pg.relation
          JOIN authz.types     ut ON ut.store_id = v_state.store_id AND ut.name = pg.user_type
     LEFT JOIN authz.relations ur ON ur.store_id = v_state.store_id AND ur.name = pg.user_relation
         WHERE pg.action IN ('INSERT', 'UPDATE', 'DELETE');

        -- inserted tuples that will expire: file the deferred delta.
        -- statement_timestamp(), like the RLS expiry policy: every tuple the
        -- derivation below can see is filed. (clock_timestamp() here opened a
        -- millisecond race — a tuple expiring between statement start and this
        -- step was derived but never filed, so its rows were never withdrawn.)
        INSERT INTO authz.permissions_refresh_queue
            (store_id, object_type, object_id, relation, user_type, user_id, user_relation, op, due_at)
        SELECT DISTINCT t.store_id, t.object_type, t.object_id, t.relation, t.user_type, t.user_id, t.user_relation,
               'EXPIRE', t.expires_at
          FROM _mp_claimed c
          JOIN authz.tuples t ON t.store_id = c.store_id AND t.object_type = c.object_type
                             AND t.object_id = c.object_id AND t.relation = c.relation
                             AND t.user_type = c.user_type AND t.user_id = c.user_id
                             AND t.user_relation IS NOT DISTINCT FROM c.user_relation
         WHERE c.store_id = v_state.store_id
           AND c.op IN ('INSERT', 'UPDATE')
           AND t.expires_at IS NOT NULL AND t.expires_at > statement_timestamp()
           AND NOT EXISTS (SELECT 1 FROM authz.permissions_refresh_queue q
                            WHERE q.op = 'EXPIRE' AND q.due_at = t.expires_at
                              AND q.store_id = t.store_id AND q.object_type = t.object_type
                              AND q.object_id = t.object_id AND q.relation = t.relation
                              AND q.user_type = t.user_type AND q.user_id = t.user_id
                              AND q.user_relation IS NOT DISTINCT FROM t.user_relation);

        INSERT INTO _mp_feed VALUES (
            v_state.store, v_state.store_id, v_n,
            COALESCE(v_last_at, v_state.cursor_at), COALESCE(v_last_seq, v_state.cursor_seq),
            v_n < p_limit);
    END LOOP;

    -- deferred deltas that fell due (expiries, manual entries)
    WITH claimed AS (
        DELETE FROM authz.permissions_refresh_queue
         WHERE id IN (SELECT id FROM authz.permissions_refresh_queue
                       WHERE due_at <= statement_timestamp()
                       FOR UPDATE SKIP LOCKED)
         RETURNING store_id, object_type, object_id, relation, user_type, user_id, user_relation, op)
    INSERT INTO _mp_claimed (store_id, object_type, object_id, relation, user_type, user_id, user_relation, op)
    SELECT store_id, object_type, object_id, relation, user_type, user_id, user_relation, op FROM claimed;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    UPDATE _mp_feed f SET changes = f.changes + d.n
      FROM (SELECT c.store_id, count(*) AS n FROM _mp_claimed c
             WHERE c.op NOT IN ('INSERT', 'UPDATE', 'DELETE') GROUP BY c.store_id) d
     WHERE d.store_id = f.store_id;

    IF EXISTS (SELECT 1 FROM _mp_claimed) THEN
        PERFORM authz._mp_blast_radius();
        SELECT d.pairs, d.rows_written INTO v_pairs, v_written FROM authz._derive_pairs() d;
    END IF;

    UPDATE authz.materialized_refresh_state s
       SET cursor_at             = f.last_at,
           cursor_seq            = f.last_seq,
           feed_drained          = f.drained,
           as_of                 = GREATEST(s.as_of, CASE WHEN f.drained THEN v_started - p_lag ELSE f.last_at END),
           last_run_started_at   = v_started,
           last_run_finished_at  = clock_timestamp(),
           last_run_changes      = f.changes,
           last_run_pairs        = v_pairs,
           last_run_rows_written = v_written
      FROM _mp_feed f
     WHERE f.store = s.store;

    RETURN v_pairs;
END;
$$;

------------------------------------------------------------------------
-- Whole-object re-derivation (every known subject × this object).
-- Kept for manual repair; the worker computes finer pairs itself.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._refresh_permissions_for_object(
    p_store_id    integer,
    p_object_type integer,
    p_object_id   text
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_pairs integer; v_written integer;
BEGIN
    PERFORM authz._mp_prepare_pairs();
    INSERT INTO _mp_pairs (store_id, object_type, object_id, user_type, user_id)
    SELECT DISTINCT p_store_id, p_object_type, p_object_id, t.user_type, t.user_id
      FROM authz.tuples t
     WHERE t.store_id = p_store_id AND t.user_relation IS NULL
    ON CONFLICT DO NOTHING;
    SELECT d.pairs, d.rows_written INTO v_pairs, v_written FROM authz._derive_pairs() d;
    RETURN v_written;
END;
$$;

------------------------------------------------------------------------
-- refresh_all_materialized_permissions: register a store for incremental
-- refresh (or rebuild it): clear its derived rows, take the cursor just
-- before the snapshot (p_lag before now — the feed's stability lag — so a
-- write committing while the snapshot runs is replayed, never missed),
-- derive every object × every known subject, file a deferred delta for
-- every expiring tuple. Returns the rows written.
------------------------------------------------------------------------
DROP FUNCTION IF EXISTS authz.refresh_all_materialized_permissions(text);  -- pre-changefeed signature
CREATE OR REPLACE FUNCTION authz.refresh_all_materialized_permissions(
    p_store text,
    p_lag   interval DEFAULT '1 second'
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_store_id  integer := authz._s(p_store);
    v_started   timestamptz := clock_timestamp();
    -- not later than this transaction's own writes (performed_at = transaction_timestamp())
    v_cursor_at timestamptz := LEAST(clock_timestamp() - p_lag, transaction_timestamp());
    v_pairs     integer; v_written integer;
BEGIN
    DELETE FROM authz.materialized_permissions WHERE store = p_store;
    DELETE FROM authz.materialized_subjects    WHERE store = p_store;
    DELETE FROM authz.materialized_objects     WHERE store = p_store;
    DELETE FROM authz.permissions_refresh_queue WHERE store_id = v_store_id;

    PERFORM authz._mp_prepare_pairs();
    INSERT INTO _mp_pairs (store_id, object_type, object_id, user_type, user_id)
    SELECT v_store_id, o.object_type, o.object_id, k.user_type, k.user_id
      FROM (SELECT DISTINCT t.object_type, t.object_id FROM authz.tuples t WHERE t.store_id = v_store_id) o
     CROSS JOIN (SELECT DISTINCT t.user_type, t.user_id FROM authz.tuples t
                  WHERE t.store_id = v_store_id AND t.user_relation IS NULL) k
    ON CONFLICT DO NOTHING;
    SELECT d.pairs, d.rows_written INTO v_pairs, v_written FROM authz._derive_pairs() d;

    INSERT INTO authz.permissions_refresh_queue
        (store_id, object_type, object_id, relation, user_type, user_id, user_relation, op, due_at)
    SELECT t.store_id, t.object_type, t.object_id, t.relation, t.user_type, t.user_id, t.user_relation,
           'EXPIRE', t.expires_at
      FROM authz.tuples t
     WHERE t.store_id = v_store_id AND t.expires_at IS NOT NULL;   -- visible ⇒ not yet expired (RLS)

    INSERT INTO authz.materialized_refresh_state
        (store, cursor_at, cursor_seq, as_of, feed_drained,
         last_run_started_at, last_run_finished_at, last_run_changes, last_run_pairs, last_run_rows_written)
    VALUES (p_store, v_cursor_at, 0, v_cursor_at, true, v_started, clock_timestamp(), 0, v_pairs, v_written)
    ON CONFLICT (store) DO UPDATE
       SET cursor_at = EXCLUDED.cursor_at, cursor_seq = 0, as_of = EXCLUDED.as_of, feed_drained = true,
           last_run_started_at = EXCLUDED.last_run_started_at, last_run_finished_at = EXCLUDED.last_run_finished_at,
           last_run_changes = 0, last_run_pairs = EXCLUDED.last_run_pairs,
           last_run_rows_written = EXCLUDED.last_run_rows_written;

    RETURN v_written;
END;
$$;

------------------------------------------------------------------------
-- Status on the primary, one row per registered store.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.materialized_permissions_status()
RETURNS TABLE (
    store                 text,
    as_of                 timestamptz,  -- every change performed before this is reflected
    staleness             interval,     -- statement_timestamp() - as_of
    feed_drained          boolean,
    pending_due           bigint,       -- deferred deltas claimable now
    pending_deferred      bigint,       -- deferred deltas not yet due (expiries ahead)
    last_run_started_at   timestamptz,
    last_run_finished_at  timestamptz,
    last_run_changes      integer,
    last_run_pairs        integer,
    last_run_rows_written integer
)
LANGUAGE sql STABLE SECURITY DEFINER AS $$
    SELECT s.store, s.as_of, statement_timestamp() - s.as_of, s.feed_drained,
           (SELECT count(*) FROM authz.permissions_refresh_queue q
             WHERE q.store_id = st.id AND q.due_at <= statement_timestamp()),
           (SELECT count(*) FROM authz.permissions_refresh_queue q
             WHERE q.store_id = st.id AND q.due_at >  statement_timestamp()),
           s.last_run_started_at, s.last_run_finished_at,
           s.last_run_changes, s.last_run_pairs, s.last_run_rows_written
      FROM authz.materialized_refresh_state s
      JOIN authz.stores st ON st.name = s.store
     ORDER BY s.store;
$$;

-- The pre-changefeed design queued whole objects from a trigger on
-- authz.tuples; the audit changefeed is the source now.
DROP TRIGGER  IF EXISTS trg_queue_permissions_refresh ON authz.tuples;
DROP FUNCTION IF EXISTS authz._queue_permissions_refresh();
DROP FUNCTION IF EXISTS authz._sweep_materialized_subjects(integer);
DROP FUNCTION IF EXISTS authz.process_permissions_refresh_queue();

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
        ALTER FUNCTION authz._mp_prepare_pairs()                                      OWNER TO authz_owner;
        ALTER FUNCTION authz._mp_blast_radius()                                       OWNER TO authz_owner;
        ALTER FUNCTION authz._derive_pairs()                                          OWNER TO authz_owner;
        ALTER FUNCTION authz._refresh_permissions_for_object(integer, integer, text) OWNER TO authz_owner;
        ALTER FUNCTION authz.refresh_materialized_permissions(interval, int)         OWNER TO authz_owner;
        ALTER FUNCTION authz.refresh_all_materialized_permissions(text, interval)    OWNER TO authz_owner;
        ALTER FUNCTION authz.materialized_permissions_status()                       OWNER TO authz_owner;
    END IF;
END;
$$;

-- Internal helpers are not for app roles.
REVOKE ALL ON FUNCTION authz._mp_prepare_pairs()                                      FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._mp_blast_radius()                                       FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._derive_pairs()                                          FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._refresh_permissions_for_object(integer, integer, text) FROM PUBLIC;
