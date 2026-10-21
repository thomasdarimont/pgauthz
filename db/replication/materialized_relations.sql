-- Materialized permissions: a flat, denormalized table that app databases
-- can subscribe to without needing the authz schema or functions — the
-- pgauthz equivalent of a hosted "permissions index".
--
-- Three tables travel together (publication authz_derived):
--
--   authz.materialized_relations  (store, user_type, user_id, permission, object_type, object_id)
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
-- is registered by refresh_all_materialized_relations(), which takes the
-- initial snapshot and records a (performed_at, seq) cursor just before it.
-- A worker — SELECT authz.refresh_materialized_relations(), run from
-- pg_cron, on LISTEN authz_changes (the audit log's own doorbell), or in a
-- loop — pulls one lag-gated page of the feed per registered store, resumes
-- from the stored cursor after a crash, and for each delta re-derives only
-- the (subject, object) pairs whose answer can have changed (the snapshot
-- refresh_all takes is the same computation over every tuple of the store,
-- so registration costs what the grants cost, not objects × subjects):
--
--   objects  = the delta's object plus every object that reaches it through
--              tuples (reverse closure over tuple edges, full depth, cycle
--              safe); an object-wildcard delta ('*') seeds every object of
--              the type
--   subjects = the delta's own subject, always; when the subject is a
--              userset (team#member) the userset's members, and when it is an
--              object reference (a parent folder, a manager, a
--              classification — any type the model defines relations on)
--              everyone holding any relation on that object — both resolved
--              by the engine's reverse expansion, authz.list_subjects, gates
--              off; every known subject of the type only for a
--              subject-wildcard delta, when list_subjects reports a wildcard,
--              or for a manual whole-object entry
--   relations = every relation of the object's type
--
-- Each pair's allowed relations are recomputed and DIFFED against the stored
-- rows, so the table only ever receives real inserts and deletes (a CDC
-- consumer sees deltas). Objects that lost their last tuple and subjects
-- that lost theirs are delisted and lose their rows (they are wildcard
-- covered from then on); a subject or object that BECOMES known stops
-- being wildcard covered, so it is derived against every object (subject)
-- that carries a '*' row of its type — the two known-state transitions.
--
-- NO ROW IS SKIPPED. The feed is ordered by (performed_at = the writing
-- transaction's start, seq) and a transaction may commit long after it
-- started. Each run captures ONE absolute, exclusive cutoff —
-- authz.watch_safe_until(p_lag): now - p_lag, capped at the start of the
-- oldest transaction still open on this database, the worker's own
-- included — and reads every store's feed with it (p_until), so the cutoff
-- cannot drift while the run works and a worker called inside an explicit
-- transaction cannot advance past rows that transaction may still write.
-- READ COMMITTED ONLY. The cutoff comes from pg_stat_activity, which is not
-- MVCC, while the feed is read through the transaction's snapshot. Under
-- READ COMMITTED every query inside these VOLATILE functions takes a fresh
-- snapshot after the cutoff was captured, so a transaction that committed
-- before the capture is visible and one still open is excluded by the
-- cutoff. Under REPEATABLE READ or SERIALIZABLE the snapshot predates the
-- capture: a transaction that committed in between is invisible, yet no
-- longer open, and its rows would be skipped forever. Both entry points
-- therefore refuse to run in any other isolation level.
-- OPERATIONAL LIMIT: any long-open transaction on the database, read-only
-- ones included (an analytics query, a connection left idle in
-- transaction), holds the cutoff back and with it every revocation; the
-- status shows last_run_gate and oldest_open_txn_age, the subscriber has
-- permissions_fresh(store, max_staleness) to refuse a stale copy. Set
-- idle_in_transaction_session_timeout on application roles. A consumer that
-- needs bounded revocation latency independent of unrelated workloads needs
-- a commit-ordered source (logical decoding) — not provided here. p_until on
-- the worker overrides the cutoff for controlled replays and tests; it
-- forfeits the guarantee.
--
-- STRUCTURAL CHANGES. A removed type (TYPE_REMOVED in the feed, or tuple
-- deltas whose type no longer resolves) cannot be mapped to pairs; the
-- worker rebuilds that store in the same run. A retired store
-- (STORE_RETIRED) is dropped from the derived tables and deregistered. A
-- store DELETED physically (delete_store) is invalidated SYNCHRONOUSLY: a
-- trigger on authz.stores drops its rows and registration in the deleting
-- transaction (they replicate atomically with it), so a store recreated
-- under the same name never inherits its predecessor's permissions; the
-- worker also drops any registration whose store_id no longer exists, for
-- leftovers from before this trigger. Registration (refresh_all), the
-- worker's cleanup and the trigger serialize per store name on an advisory
-- transaction lock, and cleanup only removes the incarnation it identified
-- — a concurrent re-registration is never undone. Deletion and the snapshot
-- order themselves on the engine's store-wide lock, taken BEFORE the store
-- name is resolved (delete_store exclusively, refresh_all shared): a
-- deletion waits for a running snapshot and then invalidates it; a snapshot
-- that meets a deletion in flight waits and then finds the name gone; the
-- worker try-locks and skips, so it never waits (see Locks below). The
-- subscriber's check_permission() requires a registration row for the
-- store, so even a stale row of an unregistered incarnation answers false.
-- Model changes (rules, restrictions) are not in the tuple feed: run
-- refresh_all_materialized_relations(store) after applying one.
--
-- EXPIRY. The feed reports writes, not the passing of time, so for every
-- inserted tuple that carries expires_at the worker files a deferred delta
-- in authz.materialized_refresh_queue, due at that instant; refresh_all files
-- one per expiring tuple of the store. When it falls due the tuple is
-- already invisible to the engine and the rows it granted are withdrawn.
--
-- FRESHNESS. authz.materialized_refresh_state (one row per registered store,
-- replicated) carries the cursor and `as_of`: every change performed before
-- as_of is reflected. authz.materialized_relations_status() on the primary,
-- authz.permissions_as_of(store) on the subscriber. The feed's stability lag
-- (p_lag, default 1 s; see watch_changes) bounds how soon a change can be
-- picked up; the oldest open transaction can push the gate further out
-- (NO ROW IS SKIPPED above).
--
-- KIND. Every row says whether its relation is a permission (can_read: what a
-- subject may DO) or a relation (member, parent: what it IS), from the
-- relation's declared kind (MODEL_DESIGN.md, "Relation kinds"; default
-- relation; infer_relation_kinds(store, true) declares the obvious ones). An
-- application that only asks "may X do Y?" reads `WHERE is_permission` — or
-- subscribes with that in its row filter if it wants the rows kept away
-- entirely. Re-declaring a kind afterwards needs
-- refresh_all_materialized_relations(store).
--
-- NAMESPACES. Rows of materialized_relations and materialized_objects carry
-- the object type's namespace ('' when it has none), so an application can
-- subscribe to its own object types only through a row-filtered publication
-- (setup-publication.sql, authz_derived_<ns>); the derivation itself stays
-- store-wide — a team in a shared namespace grants access to documents in the
-- application's — and materialized_subjects / materialized_refresh_state are
-- published whole (known subjects are a store-wide notion). Changing a type's
-- namespace afterwards needs refresh_all_materialized_relations(store). The
-- worker's LOGIN role is what the engine's namespace check sees in
-- list_subjects: grant it authz_namespace_bypass (roles.sql) or read access to
-- every namespace, otherwise the expansion falls back to every known subject
-- (correct, slow). A publication is a volume boundary, not a security one:
-- any replication role that may read the tables may subscribe to any
-- publication — isolate tenants with stores.
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
-- to it; re-running roles.sql does the same. EXECUTE on every function is
-- revoked from PUBLIC and granted to authz_admin when that role exists; the
-- worker role needs only EXECUTE on refresh_materialized_relations(). Every
-- function pins search_path = pg_catalog, pg_temp.

------------------------------------------------------------------------
-- Rename from the first version (authz.materialized_permissions, its
-- partitions, the queue): the table carries relations of both kinds, so
-- it is named after the generic one. Idempotent; a no-op on a fresh install.
------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    IF to_regclass('authz.materialized_permissions') IS NOT NULL
       AND to_regclass('authz.materialized_relations') IS NULL THEN
        ALTER TABLE authz.materialized_permissions RENAME TO materialized_relations;
        ALTER TABLE authz.materialized_relations RENAME CONSTRAINT materialized_permissions_pkey TO materialized_relations_pkey;
        FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'authz' AND c.relname ~ '^materialized_permissions_[0-9]+$' LOOP
            EXECUTE format('ALTER TABLE authz.%I RENAME TO %I', r.relname,
                           replace(r.relname, 'materialized_permissions_', 'materialized_relations_'));
        END LOOP;
    END IF;
    -- the name column was `permission`; the table holds both kinds
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'authz' AND table_name = 'materialized_relations' AND column_name = 'permission') THEN
        ALTER TABLE authz.materialized_relations RENAME COLUMN permission TO relation;
    END IF;
    IF to_regclass('authz.permissions_refresh_queue') IS NOT NULL
       AND to_regclass('authz.materialized_refresh_queue') IS NULL THEN
        ALTER TABLE authz.permissions_refresh_queue RENAME TO materialized_refresh_queue;
    END IF;
END;
$$;
DROP FUNCTION IF EXISTS authz.refresh_materialized_permissions(interval, int, timestamptz);
DROP FUNCTION IF EXISTS authz.refresh_materialized_permissions(interval, int);
DROP FUNCTION IF EXISTS authz.refresh_all_materialized_permissions(text, interval, timestamptz);
DROP FUNCTION IF EXISTS authz.refresh_all_materialized_permissions(text, interval);
DROP FUNCTION IF EXISTS authz.refresh_all_materialized_permissions(text);
DROP FUNCTION IF EXISTS authz.materialized_permissions_status();
DROP FUNCTION IF EXISTS authz._refresh_permissions_for_object(integer, integer, text);

------------------------------------------------------------------------
-- The derived relations table: one row per (subject, relation, object)
-- the engine would answer yes to — permissions (can_read) and relations
-- (member, parent) alike, told apart by is_permission.
-- Hash-partitioned by (store, user_id) for partition pruning on the
-- primary access pattern: "can user X do Y on Z?"
------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.materialized_relations (
    store         text    NOT NULL,
    user_type     text    NOT NULL,
    user_id       text    NOT NULL,
    relation    text    NOT NULL,
    object_type   text    NOT NULL,
    object_id     text    NOT NULL,
    namespace     text    NOT NULL DEFAULT '',   -- the object type's namespace ('' = none); in the key so a
                                                 -- publication row filter may name it (replica identity rule)
    is_permission boolean NOT NULL DEFAULT false, -- the relation's declared kind: true = permission (can_read),
                                                 -- false = relation (member, parent). boolean, not an enum: a
                                                 -- user-defined type cannot appear in a publication row filter
    refreshed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (store, user_id, user_type, relation, object_type, object_id, namespace, is_permission)
) PARTITION BY HASH (store, user_id);

-- 8 hash partitions (same modulus as the document tuple partitions).
CREATE TABLE IF NOT EXISTS authz.materialized_relations_0 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 0);
CREATE TABLE IF NOT EXISTS authz.materialized_relations_1 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 1);
CREATE TABLE IF NOT EXISTS authz.materialized_relations_2 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 2);
CREATE TABLE IF NOT EXISTS authz.materialized_relations_3 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 3);
CREATE TABLE IF NOT EXISTS authz.materialized_relations_4 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 4);
CREATE TABLE IF NOT EXISTS authz.materialized_relations_5 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 5);
CREATE TABLE IF NOT EXISTS authz.materialized_relations_6 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 6);
CREATE TABLE IF NOT EXISTS authz.materialized_relations_7 PARTITION OF authz.materialized_relations FOR VALUES WITH (MODULUS 8, REMAINDER 7);

------------------------------------------------------------------------
-- The side tables of the wildcard contract (see header): every subject
-- and every object that has at least one tuple in the store. A '*' row
-- in materialized_relations applies only to entities NOT listed here.
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
    namespace     text    NOT NULL DEFAULT '',
    refreshed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (store, object_type, object_id, namespace)
);

-- Upgrade of tables created before the namespace column: add it to the key.
-- Rows written before carry '' — run refresh_all_materialized_relations()
-- per store afterwards so they get their namespace.
DO $$
BEGIN
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
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'authz' AND table_name = 'materialized_objects' AND column_name = 'namespace') THEN
        ALTER TABLE authz.materialized_objects ADD COLUMN namespace text NOT NULL DEFAULT '';
        ALTER TABLE authz.materialized_objects DROP CONSTRAINT materialized_objects_pkey;
        ALTER TABLE authz.materialized_objects ADD PRIMARY KEY (store, object_type, object_id, namespace);
    END IF;
END;
$$;

------------------------------------------------------------------------
-- Deferred deltas: one row per expiring tuple, due at its expiry (filed
-- by the worker from the feed and by refresh_all). Claimed and deleted
-- by the worker when due. Manual whole-object entries (subject columns
-- NULL) are accepted too and re-derive the object for every subject.
------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.materialized_refresh_queue (
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
ALTER TABLE authz.materialized_refresh_queue
    ADD COLUMN IF NOT EXISTS relation      integer,
    ADD COLUMN IF NOT EXISTS user_type     integer,
    ADD COLUMN IF NOT EXISTS user_id       text,
    ADD COLUMN IF NOT EXISTS user_relation integer,
    ADD COLUMN IF NOT EXISTS op            text,
    ADD COLUMN IF NOT EXISTS due_at        timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE INDEX IF NOT EXISTS idx_materialized_refresh_queue_due ON authz.materialized_refresh_queue (due_at);

------------------------------------------------------------------------
-- Per-store cursor and freshness. Replicated with the permissions, so
-- the subscriber can tell how stale its copy may be.
------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.materialized_refresh_state (
    store                 text PRIMARY KEY,
    store_id              integer,                -- the registered incarnation; a store deleted and recreated
                                                 -- under the same name gets a new id and must be registered anew
    cursor_at             timestamptz NOT NULL,   -- watch_changes cursor: last (performed_at, seq) applied
    cursor_seq            bigint      NOT NULL DEFAULT 0,
    as_of                 timestamptz NOT NULL,   -- every change performed before this instant is reflected
    feed_drained          boolean     NOT NULL DEFAULT true,  -- the last page was not full
    last_run_started_at   timestamptz,
    last_run_finished_at  timestamptz,
    last_run_changes      integer NOT NULL DEFAULT 0,  -- feed rows + due deferred rows, this store
    last_run_pairs        integer NOT NULL DEFAULT 0,  -- (subject, object) pairs re-derived, this store
    last_run_rows_written integer NOT NULL DEFAULT 0,  -- permission rows inserted + deleted, this store
    last_run_gate         interval                     -- stability gate used: max(p_lag, age of the oldest open transaction)
);
-- Upgrade of a state table created before last_run_gate / store_id existed (silent on a fresh install).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'authz' AND table_name = 'materialized_refresh_state'
                      AND column_name = 'last_run_gate') THEN
        ALTER TABLE authz.materialized_refresh_state ADD COLUMN last_run_gate interval;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'authz' AND table_name = 'materialized_refresh_state'
                      AND column_name = 'store_id') THEN
        ALTER TABLE authz.materialized_refresh_state ADD COLUMN store_id integer;
        UPDATE authz.materialized_refresh_state s SET store_id = st.id FROM authz.stores st WHERE st.name = s.store;
    END IF;
END;
$$;

------------------------------------------------------------------------
-- Session work tables. Created under the definer role (the same role the
-- engine's memo table uses), truncated on every run.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._mp_prepare_pairs()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- Dropped and recreated every run, not IF NOT EXISTS + TRUNCATE: a
    -- long-lived worker session would otherwise keep a work table in the
    -- shape of the code it was created by, and a reload that adds a column
    -- would fail with "INSERT has more expressions than target columns".
    DROP TABLE IF EXISTS _mp_pairs, _mp_claimed, _mp_written, _mp_objects, _mp_subjects, _mp_want,
                         _mp_known, _mp_known_built, _mp_principal, _mp_subject_types, _mp_expanded,
                         _mp_ref_subjects, _mp_closure, _mp_frontier, _mp_next, _mp_feed, _mp_page;
    CREATE TEMP TABLE _mp_pairs (
        store_id    integer NOT NULL,
        object_type integer NOT NULL,
        object_id   text    NOT NULL,
        user_type   integer NOT NULL,
        user_id     text    NOT NULL,
        PRIMARY KEY (store_id, object_type, object_id, user_type, user_id));
    CREATE TEMP TABLE _mp_claimed (
        id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        store_id      integer, object_type integer, object_id text, relation integer,
        user_type     integer, user_id text, user_relation integer, op text);
    CREATE INDEX _mp_claimed_user ON _mp_claimed (store_id, user_type, user_id);
    CREATE TEMP TABLE _mp_written (store text, n integer);
END;
$$;

------------------------------------------------------------------------
-- Locks. Two advisory transaction locks per store NAME (the unit the
-- derived rows are keyed by), always in this order:
--
--   1. the engine's store-wide lock (store.sql _lock_store_lifecycle,
--      tuples.sql checked writes): retire_store / delete_store hold it
--      EXCLUSIVELY from their first statement to their commit; checked
--      writers and refresh_all hold it SHARED. So whoever holds it in any
--      mode knows no deletion is half-way through, and resolving the store
--      name AFTER taking it yields the live incarnation (or "Unknown store").
--   2. the derived-rows lock (_mp_lock_store): refresh_all (registration),
--      the deletion trigger and the worker's cleanup serialize on it.
--
-- The worker never WAITS for either (it try-locks both per store and skips
-- the store for this run when it cannot have them): it holds ACCESS SHARE
-- on the tuple partitions it read earlier in the same transaction, and a
-- deletion's partition DDL waits for exactly those — a blocking wait by the
-- worker would close the cycle. The deleter holds lock 1 before any DDL;
-- refresh_all holds it shared before reading a tuple; so the two can only
-- ever wait on each other in one direction.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._mp_lock_store(p_store text)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_advisory_xact_lock(hashtext('authz.materialized_relations:' || p_store));
$$;

-- Both locks, non-blocking, in order, and the store still registered; true
-- when this transaction holds both. The store-wide lock is taken SHARED (the
-- worker reads; it must only step aside for a deletion or an exclusive
-- checked write in flight). A store whose registration went between the
-- worker's listing and this call is not claimed either: nothing to do for
-- it, and locks held on it would only make a re-registration wait.
CREATE OR REPLACE FUNCTION authz._mp_try_lock_store(p_store text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- Sequential on purpose (SQL AND does not promise evaluation order), and
    -- inside a subtransaction: a transaction-level advisory lock cannot be
    -- released explicitly, but rolling back the subtransaction that took it
    -- does — so a failed second lock does not leave the first one held for
    -- the rest of the worker's run (a deletion would wait on it for nothing).
    BEGIN
        IF NOT pg_try_advisory_xact_lock_shared(hashtextextended(p_store || ':*', 0)) THEN
            RETURN false;
        END IF;
        IF NOT pg_try_advisory_xact_lock(hashtext('authz.materialized_relations:' || p_store)) THEN
            RAISE EXCEPTION USING ERRCODE = 'lock_not_available';   -- undo the shared lock
        END IF;
        IF NOT EXISTS (SELECT 1 FROM authz.materialized_refresh_state s WHERE s.store = p_store) THEN
            RAISE EXCEPTION USING ERRCODE = 'lock_not_available';   -- gone meanwhile: undo both
        END IF;
        RETURN true;
    EXCEPTION WHEN lock_not_available THEN
        RETURN false;
    END;
END;
$$;

------------------------------------------------------------------------
-- _mp_drop_store: remove everything derived for a store name — unless the
-- registration now belongs to another incarnation than the one the caller
-- identified (p_expected_id), in which case nothing is touched. Returns
-- whether it dropped.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._mp_drop_store(p_store text, p_expected_id integer)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM authz._mp_lock_store(p_store);
    IF p_expected_id IS NOT NULL AND EXISTS (
           SELECT 1 FROM authz.materialized_refresh_state s
            WHERE s.store = p_store AND s.store_id IS DISTINCT FROM p_expected_id) THEN
        RETURN false;   -- re-registered meanwhile: that incarnation's rows are the truth
    END IF;
    DELETE FROM authz.materialized_relations     WHERE store = p_store;
    DELETE FROM authz.materialized_subjects      WHERE store = p_store;
    DELETE FROM authz.materialized_objects       WHERE store = p_store;
    DELETE FROM authz.materialized_refresh_queue q
     WHERE q.store_id = p_expected_id
        OR q.store_id IN (SELECT s.store_id FROM authz.materialized_refresh_state s WHERE s.store = p_store);
    DELETE FROM authz.materialized_refresh_state WHERE store = p_store;
    RETURN true;
END;
$$;

------------------------------------------------------------------------
-- Synchronous invalidation on physical store deletion (delete_store):
-- the derived rows go in the same transaction as the store row.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._mp_on_store_deleted()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM authz._mp_drop_store(OLD.name, OLD.id);
    RETURN OLD;
END;
$$;
DROP TRIGGER IF EXISTS trg_mp_store_deleted ON authz.stores;
CREATE TRIGGER trg_mp_store_deleted
    AFTER DELETE ON authz.stores
    FOR EACH ROW EXECUTE FUNCTION authz._mp_on_store_deleted();

------------------------------------------------------------------------
-- _mp_require_read_committed: see header, READ COMMITTED ONLY.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._mp_require_read_committed(p_what text)
RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION '% requires READ COMMITTED (transaction isolation is %): the feed is read through this transaction''s snapshot, '
                        'and a change committed between that snapshot and the cutoff would be skipped for good',
            p_what, current_setting('transaction_isolation')
            USING ERRCODE = 'invalid_transaction_state',
                  HINT = 'Run the worker in its own READ COMMITTED transaction (autocommit).';
    END IF;
END;
$$;

------------------------------------------------------------------------
-- _derive_pairs: re-derive every (subject, object) pair in _mp_pairs.
--
--   1. resolve every object and every subject of the pairs — names and
--      whether it still has tuples — BEFORE any pruning, so an object and a
--      subject that vanished in the same change are both seen
--   2. known-state transitions: a subject (object) that is about to become
--      known stops inheriting the '*' rows of its type — add the pairs that
--      materialize what it inherited so far
--   3. objects without tuples are delisted and lose all their rows (the
--      '*' rows, if any, answer for them from now on); the rest are listed
--   4. subjects without tuples likewise
--   5. each remaining pair is decided for every relation of the object's
--      type through authz._decide with an empty gate list (graph only, no
--      request context), and the result is diffed against the stored rows:
--      rows no longer allowed are deleted, new ones inserted
--
-- Returns the pairs decided and the rows written (inserts + deletes);
-- _mp_written holds the rows written per store.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._derive_pairs(OUT pairs integer, OUT rows_written integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    TRUNCATE _mp_written;

    -- 1. resolve
    CREATE TEMP TABLE IF NOT EXISTS _mp_objects (
        store_id integer, object_type integer, object_id text,
        store text, type_name text, namespace text, has_tuples boolean,
        PRIMARY KEY (store_id, object_type, object_id));
    CREATE TEMP TABLE IF NOT EXISTS _mp_subjects (
        store_id integer, user_type integer, user_id text,
        store text, type_name text, has_tuples boolean,
        PRIMARY KEY (store_id, user_type, user_id));
    TRUNCATE _mp_objects, _mp_subjects;

    INSERT INTO _mp_objects
    SELECT DISTINCT p.store_id, p.object_type, p.object_id, s.name, ot.name, COALESCE(ot.namespace, ''),
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

    -- 2. known-state transitions
    --    subject becoming known: × every object carrying a '*'-subject row of its type
    INSERT INTO _mp_pairs (store_id, object_type, object_id, user_type, user_id)
    SELECT DISTINCT su.store_id, ot.id, mp.object_id, su.user_type, su.user_id
      FROM _mp_subjects su
      JOIN authz.materialized_relations mp
        ON mp.store = su.store AND mp.user_type = su.type_name AND mp.user_id = '*'
      JOIN authz.types ot ON ot.store_id = su.store_id AND ot.name = mp.object_type
     WHERE su.has_tuples AND su.user_id <> '*'
       AND NOT EXISTS (SELECT 1 FROM authz.materialized_subjects ms
                        WHERE ms.store = su.store AND ms.user_type = su.type_name AND ms.user_id = su.user_id)
    ON CONFLICT DO NOTHING;
    --    object becoming known: × every subject holding a '*'-object row of its type
    INSERT INTO _mp_pairs (store_id, object_type, object_id, user_type, user_id)
    SELECT DISTINCT o.store_id, o.object_type, o.object_id, ut.id, mp.user_id
      FROM _mp_objects o
      JOIN authz.materialized_relations mp
        ON mp.store = o.store AND mp.object_type = o.type_name AND mp.object_id = '*'
      JOIN authz.types ut ON ut.store_id = o.store_id AND ut.name = mp.user_type
     WHERE o.has_tuples AND o.object_id <> '*'
       AND NOT EXISTS (SELECT 1 FROM authz.materialized_objects mo
                        WHERE mo.store = o.store AND mo.object_type = o.type_name AND mo.object_id = o.object_id)
    ON CONFLICT DO NOTHING;
    --    the other side of the added pairs may be new to the work tables
    INSERT INTO _mp_objects
    SELECT DISTINCT p.store_id, p.object_type, p.object_id, s.name, ot.name, COALESCE(ot.namespace, ''),
           EXISTS (SELECT 1 FROM authz.tuples t
                    WHERE t.store_id = p.store_id AND t.object_type = p.object_type
                      AND t.object_id = p.object_id)
      FROM _mp_pairs p
      JOIN authz.stores s  ON s.id  = p.store_id
      JOIN authz.types  ot ON ot.id = p.object_type
    ON CONFLICT DO NOTHING;
    INSERT INTO _mp_subjects
    SELECT DISTINCT p.store_id, p.user_type, p.user_id, s.name, ut.name,
           EXISTS (SELECT 1 FROM authz.tuples t
                    WHERE t.store_id = p.store_id AND t.user_type = p.user_type
                      AND t.user_id = p.user_id AND t.user_relation IS NULL)
      FROM _mp_pairs p
      JOIN authz.stores s  ON s.id  = p.store_id
      JOIN authz.types  ut ON ut.id = p.user_type
    ON CONFLICT DO NOTHING;

    -- 3. objects without tuples
    WITH d AS (
        DELETE FROM authz.materialized_relations mp
         USING _mp_objects o
         WHERE NOT o.has_tuples
           AND mp.store = o.store AND mp.object_type = o.type_name AND mp.object_id = o.object_id
        RETURNING mp.store)
    INSERT INTO _mp_written SELECT d.store, count(*) FROM d GROUP BY d.store;

    DELETE FROM authz.materialized_objects mo
     USING _mp_objects o
     WHERE NOT o.has_tuples
       AND mo.store = o.store AND mo.object_type = o.type_name AND mo.object_id = o.object_id;

    -- (a row with a stale namespace — the type moved — goes with the delist above: match on the key without it)
    DELETE FROM authz.materialized_objects mo
     USING _mp_objects o
     WHERE o.has_tuples
       AND mo.store = o.store AND mo.object_type = o.type_name AND mo.object_id = o.object_id
       AND mo.namespace <> o.namespace;
    INSERT INTO authz.materialized_objects (store, object_type, object_id, namespace)
    SELECT o.store, o.type_name, o.object_id, o.namespace FROM _mp_objects o
     WHERE o.has_tuples AND o.object_id <> '*'
    ON CONFLICT (store, object_type, object_id, namespace) DO NOTHING;

    DELETE FROM _mp_pairs p
     USING _mp_objects o
     WHERE NOT o.has_tuples
       AND p.store_id = o.store_id AND p.object_type = o.object_type AND p.object_id = o.object_id;

    -- 4. subjects without tuples
    WITH d AS (
        DELETE FROM authz.materialized_relations mp
         USING _mp_subjects su
         WHERE NOT su.has_tuples
           AND mp.store = su.store AND mp.user_type = su.type_name AND mp.user_id = su.user_id
        RETURNING mp.store)
    INSERT INTO _mp_written SELECT d.store, count(*) FROM d GROUP BY d.store;

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

    -- 5. decide and diff
    CREATE TEMP TABLE IF NOT EXISTS _mp_want (
        store text, user_type text, user_id text, relation text,
        object_type text, object_id text, namespace text, is_permission boolean, allowed boolean);
    TRUNCATE _mp_want;
    INSERT INTO _mp_want
    SELECT o.store, su.type_name, p.user_id, r.name, o.type_name, p.object_id, o.namespace,
           COALESCE(r.metadata->>'kind', 'relation') = 'permission',
           authz._decide(p.store_id, p.user_type, p.user_id, r.id, p.object_type, p.object_id,
                         NULL, false, '[]'::jsonb)
      FROM _mp_pairs p
      JOIN _mp_objects  o  ON o.store_id = p.store_id AND o.object_type = p.object_type AND o.object_id = p.object_id
      JOIN _mp_subjects su ON su.store_id = p.store_id AND su.user_type = p.user_type AND su.user_id = p.user_id
      JOIN (SELECT DISTINCT m.store_id, m.object_type, m.relation FROM authz.models m) m
        ON m.store_id = p.store_id AND m.object_type = p.object_type
      JOIN authz.relations r ON r.id = m.relation;

    WITH d AS (
        DELETE FROM authz.materialized_relations mp
         USING _mp_pairs p
          JOIN _mp_objects  o  ON o.store_id = p.store_id AND o.object_type = p.object_type AND o.object_id = p.object_id
          JOIN _mp_subjects su ON su.store_id = p.store_id AND su.user_type = p.user_type AND su.user_id = p.user_id
         WHERE mp.store = o.store AND mp.object_type = o.type_name AND mp.object_id = p.object_id
           AND mp.user_type = su.type_name AND mp.user_id = p.user_id
           AND NOT EXISTS (SELECT 1 FROM _mp_want w
                            WHERE w.allowed
                              AND w.store = mp.store AND w.user_type = mp.user_type AND w.user_id = mp.user_id
                              AND w.object_type = mp.object_type AND w.object_id = mp.object_id
                              AND w.relation = mp.relation
                              AND w.namespace = mp.namespace          -- a row under the type's old namespace is stale too,
                              AND w.is_permission = mp.is_permission) -- as is one under the relation's old kind
        RETURNING mp.store)
    INSERT INTO _mp_written SELECT d.store, count(*) FROM d GROUP BY d.store;

    WITH i AS (
        INSERT INTO authz.materialized_relations (store, user_type, user_id, relation, object_type, object_id, namespace, is_permission)
        SELECT w.store, w.user_type, w.user_id, w.relation, w.object_type, w.object_id, w.namespace, w.is_permission
          FROM _mp_want w WHERE w.allowed
        ON CONFLICT DO NOTHING
        RETURNING store)
    INSERT INTO _mp_written SELECT i.store, count(*) FROM i GROUP BY i.store;

    SELECT COALESCE(sum(w.n), 0)::integer INTO rows_written FROM _mp_written w;
END;
$$;

------------------------------------------------------------------------
-- _mp_ensure_known: the store's known-subject set (every direct subject,
-- '*' included), built once per run and only when a delta needs it.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._mp_ensure_known(p_store_id integer)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM _mp_known_built b WHERE b.store_id = p_store_id) THEN RETURN; END IF;
    INSERT INTO _mp_known
    SELECT DISTINCT p_store_id, t.user_type, t.user_id
      FROM authz.tuples t
     WHERE t.store_id = p_store_id AND t.user_relation IS NULL
    ON CONFLICT DO NOTHING;
    INSERT INTO _mp_known_built VALUES (p_store_id);
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
--
-- Subjects of a userset or object-reference delta come from the engine's
-- own reverse expansion (list_subjects, gates off): the members of the
-- userset, or everyone holding any relation on the referenced object. On
-- the 50 k-user drive store that is ~51 subjects in ~50 ms where "every
-- known subject" was 50,018 pairs and 2.2 minutes. The store-wide known set
-- is built only for a subject-wildcard delta, a wildcard reported by
-- list_subjects, or a manual whole-object entry.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._mp_blast_radius()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r   record;
    rel record;
    st  record;
    sub record;
BEGIN
    -- gates are per-principal history, not part of a precomputed row
    PERFORM set_config('authz.gates_mode', 'off', true);

    CREATE TEMP TABLE IF NOT EXISTS _mp_known (
        store_id integer, user_type integer, user_id text,
        PRIMARY KEY (store_id, user_type, user_id));
    CREATE TEMP TABLE IF NOT EXISTS _mp_known_built (store_id integer PRIMARY KEY);
    CREATE TEMP TABLE IF NOT EXISTS _mp_principal (
        store_id integer, user_type integer,
        PRIMARY KEY (store_id, user_type));
    CREATE TEMP TABLE IF NOT EXISTS _mp_subject_types (
        store_id integer, type_id integer, type_name text,
        PRIMARY KEY (store_id, type_id));
    CREATE TEMP TABLE IF NOT EXISTS _mp_expanded (
        delta_id bigint, store_id integer, user_type integer, user_id text,
        PRIMARY KEY (delta_id, store_id, user_type, user_id));
    CREATE TEMP TABLE IF NOT EXISTS _mp_ref_subjects (   -- expansion of one referenced object / userset
        store_id integer, ref_type integer, ref_id text, ref_relation integer,
        user_type integer, user_id text,
        PRIMARY KEY (store_id, ref_type, ref_id, ref_relation, user_type, user_id));
    CREATE TEMP TABLE IF NOT EXISTS _mp_closure (
        delta_id bigint, store_id integer, object_type integer, object_id text,
        PRIMARY KEY (delta_id, store_id, object_type, object_id));
    CREATE TEMP TABLE IF NOT EXISTS _mp_frontier (
        delta_id bigint, store_id integer, object_type integer, object_id text);
    CREATE INDEX IF NOT EXISTS _mp_frontier_obj ON _mp_frontier (store_id, object_type, object_id);
    CREATE TEMP TABLE IF NOT EXISTS _mp_next (LIKE _mp_frontier);
    TRUNCATE _mp_known, _mp_known_built, _mp_principal, _mp_subject_types, _mp_expanded,
             _mp_ref_subjects, _mp_closure, _mp_frontier, _mp_next;

    -- principal subject types: no relation is defined on the type in the
    -- MODEL, so no tuple can ever make one of its members an edge (a userset
    -- source, a parent, a manager). Decided from the model, not from the
    -- current tuples: a batch that deletes the last tuple on a type must not
    -- turn that type into a principal while its deltas are being processed.
    FOR r IN SELECT DISTINCT c.store_id, c.user_type FROM _mp_claimed c WHERE c.user_type IS NOT NULL LOOP
        IF NOT EXISTS (SELECT 1 FROM authz.models m
                        WHERE m.store_id = r.store_id AND m.object_type = r.user_type)
           AND NOT EXISTS (SELECT 1 FROM authz.tuples t
                            WHERE t.store_id = r.store_id AND t.object_type = r.user_type) THEN
            INSERT INTO _mp_principal VALUES (r.store_id, r.user_type) ON CONFLICT DO NOTHING;
        END IF;
    END LOOP;

    -- the types that appear as direct subjects in each store (what list_subjects enumerates)
    FOR r IN SELECT DISTINCT c.store_id FROM _mp_claimed c LOOP
        INSERT INTO _mp_subject_types
        SELECT DISTINCT r.store_id, t.user_type, ty.name
          FROM authz.tuples t JOIN authz.types ty ON ty.id = t.user_type
         WHERE t.store_id = r.store_id AND t.user_relation IS NULL
        ON CONFLICT DO NOTHING;
    END LOOP;

    -- userset and object-reference deltas: who can reach the referenced
    -- object? The userset's own relation, or every relation the model
    -- defines on the referenced type, for every subject type of the store —
    -- expanded ONCE per distinct reference (a snapshot has many tuples per
    -- team or folder), then joined back to the deltas.
    FOR r IN
        SELECT DISTINCT c.store_id, s.name AS store, c.user_type, ut.name AS utype, c.user_id,
               c.user_relation, ur.name AS urel
          FROM _mp_claimed c
          JOIN authz.stores    s  ON s.id  = c.store_id
          JOIN authz.types     ut ON ut.id = c.user_type
     LEFT JOIN authz.relations ur ON ur.id = c.user_relation
         WHERE c.user_type IS NOT NULL AND c.user_id <> '*'
           AND (c.user_relation IS NOT NULL
                OR NOT EXISTS (SELECT 1 FROM _mp_principal pr
                                WHERE pr.store_id = c.store_id AND pr.user_type = c.user_type))
    LOOP
        FOR rel IN
            SELECT r.urel AS name WHERE r.urel IS NOT NULL
            UNION
            SELECT rl.name FROM authz.models m JOIN authz.relations rl ON rl.id = m.relation
             WHERE r.urel IS NULL AND m.store_id = r.store_id AND m.object_type = r.user_type
        LOOP
            FOR st IN SELECT t.type_id, t.type_name FROM _mp_subject_types t WHERE t.store_id = r.store_id LOOP
                BEGIN
                    FOR sub IN
                        SELECT ls.subject_id, ls.is_wildcard
                          FROM authz.list_subjects(r.store, st.type_name, rel.name, r.utype, r.user_id) ls
                    LOOP
                        IF sub.is_wildcard THEN
                            -- "everyone of this type": the known ones need authoritative rows,
                            -- the '*' pseudo-subject answers for the unknown ones
                            PERFORM authz._mp_ensure_known(r.store_id);
                            INSERT INTO _mp_ref_subjects
                            SELECT r.store_id, r.user_type, r.user_id, COALESCE(r.user_relation, 0), k.user_type, k.user_id
                              FROM _mp_known k WHERE k.store_id = r.store_id AND k.user_type = st.type_id
                            ON CONFLICT DO NOTHING;
                            INSERT INTO _mp_ref_subjects
                            VALUES (r.store_id, r.user_type, r.user_id, COALESCE(r.user_relation, 0), st.type_id, '*')
                            ON CONFLICT DO NOTHING;
                        ELSE
                            INSERT INTO _mp_ref_subjects
                            VALUES (r.store_id, r.user_type, r.user_id, COALESCE(r.user_relation, 0), st.type_id, sub.subject_id)
                            ON CONFLICT DO NOTHING;
                        END IF;
                    END LOOP;
                EXCEPTION WHEN OTHERS THEN
                    -- the expansion is an optimisation; on any surprise fall back to every known subject of the type
                    PERFORM authz._mp_ensure_known(r.store_id);
                    INSERT INTO _mp_ref_subjects
                    SELECT r.store_id, r.user_type, r.user_id, COALESCE(r.user_relation, 0), k.user_type, k.user_id
                      FROM _mp_known k WHERE k.store_id = r.store_id AND k.user_type = st.type_id
                    ON CONFLICT DO NOTHING;
                END;
            END LOOP;
        END LOOP;
    END LOOP;
    INSERT INTO _mp_expanded
    SELECT c.id, c.store_id, rs.user_type, rs.user_id
      FROM _mp_claimed c
      JOIN _mp_ref_subjects rs ON rs.store_id = c.store_id AND rs.ref_type = c.user_type
                              AND rs.ref_id = c.user_id AND rs.ref_relation = COALESCE(c.user_relation, 0)
    ON CONFLICT DO NOTHING;

    -- subject-wildcard and whole-object deltas need the store-wide set
    FOR r IN SELECT DISTINCT c.store_id FROM _mp_claimed c
              WHERE c.user_type IS NULL OR (c.user_relation IS NULL AND c.user_id = '*') LOOP
        PERFORM authz._mp_ensure_known(r.store_id);
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
    -- frontier object as their subject (usersets, parent references). The
    -- edges are the current tuples PLUS the batch's own deltas: a deleted
    -- edge is exactly the path a withdrawn permission came through, and a
    -- subject whose membership and whose team's reference both vanished in
    -- one batch is reached only by walking the deleted reference.
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
            WITH ins AS (
                INSERT INTO _mp_closure
                SELECT f.delta_id, c.store_id, c.object_type, c.object_id
                  FROM _mp_frontier f
                  JOIN _mp_claimed c ON c.store_id = r.store_id
                                    AND c.user_type = r.object_type AND c.user_id = r.object_id
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
            -- whole-object entry (manual): every known subject
            SELECT c.id, c.store_id, k.user_type, k.user_id
              FROM _mp_claimed c
              JOIN _mp_known k ON k.store_id = c.store_id
             WHERE c.user_type IS NULL
            UNION
            -- userset members / holders of a relation on the referenced object
            SELECT e.delta_id, e.store_id, e.user_type, e.user_id FROM _mp_expanded e
           ) s ON s.delta_id = cl.delta_id
    ON CONFLICT DO NOTHING;
END;
$$;

------------------------------------------------------------------------
-- refresh_materialized_relations: the worker. For every registered
-- store, pull one page of authz.watch_changes after the stored cursor
-- (p_limit rows, before the run's fixed cutoff = watch_safe_until(p_lag),
-- or p_until when given), file deferred deltas for inserted tuples that expire,
-- claim the deferred deltas that fell due, compute the blast radius,
-- re-derive, record cursor and as_of. A page carrying TYPE_REMOVED, or
-- tuple deltas whose type no longer resolves, rebuilds that store instead;
-- STORE_RETIRED drops the store from the derived tables. Returns the
-- number of pairs re-derived; call again while any store's feed_drained
-- is false.
--
-- Deferred rows are claimed and deleted in one statement, FOR UPDATE SKIP
-- LOCKED; an aborted run rolls everything back, including the cursor, so
-- the page is replayed. One worker is the intended deployment: two workers
-- would pull the same page (a wasted but harmless double derivation).
------------------------------------------------------------------------
DROP FUNCTION IF EXISTS authz.refresh_materialized_relations(interval, int);  -- pre-cutoff signature (same name)
CREATE OR REPLACE FUNCTION authz.refresh_materialized_relations(
    p_lag   interval    DEFAULT '1 second',
    p_limit int         DEFAULT 1000,
    p_until timestamptz DEFAULT NULL      -- override the cutoff (tests, controlled replays); forfeits the guarantee
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_started    timestamptz := clock_timestamp();
    v_cutoff     timestamptz := COALESCE(p_until, authz.watch_safe_until(p_lag));
    v_gate       interval    := v_started - v_cutoff;
    v_state      record;
    v_n          integer;
    v_tuple_rows integer;
    v_last_at    timestamptz;
    v_last_seq   bigint;
    v_pairs      integer := 0;
    v_written    integer := 0;
    v_rebuild    text[] := '{}';
    v_rebuild_id integer[] := '{}';
    v_i          integer;
    v_name       text;
BEGIN
    PERFORM authz._mp_require_read_committed('refresh_materialized_relations');
    PERFORM authz._mp_prepare_pairs();
    CREATE TEMP TABLE IF NOT EXISTS _mp_feed (
        store text, store_id integer, changes integer,
        last_at timestamptz, last_seq bigint, drained boolean);
    TRUNCATE _mp_feed;
    CREATE TEMP TABLE IF NOT EXISTS _mp_page (
        seq bigint, action text, performed_at timestamptz,
        user_type text, user_id text, user_relation text,
        relation text, object_type text, object_id text);

    FOR v_name IN
        SELECT s.store FROM authz.materialized_refresh_state s ORDER BY s.store
    LOOP
        -- never wait (see Locks): a deletion, a registration or an exclusive
        -- checked write owns this store right now — its cursor stays, next run
        IF NOT authz._mp_try_lock_store(v_name) THEN
            CONTINUE;
        END IF;

        -- Re-read the registration UNDER the locks (READ COMMITTED: a fresh
        -- snapshot): the list above predates them, and a re-registration may
        -- have committed in between; cursor and incarnation are the current
        -- ones now, and the locks keep them so until this transaction ends.
        -- (A registration gone meanwhile was already declined by the try-lock;
        -- NOT FOUND here is a safety net.)
        SELECT s.store, s.cursor_at, s.cursor_seq, s.store_id AS registered_id, st.id AS store_id
          INTO v_state
          FROM authz.materialized_refresh_state s
     LEFT JOIN authz.stores st ON st.id = s.store_id        -- by id: a recreated name is a new store
         WHERE s.store = v_name;
        IF NOT FOUND THEN
            CONTINUE;
        END IF;

        -- deleted (or deleted and recreated) before the deletion trigger existed:
        -- nothing in the feed will ever say so; drop it — this incarnation only
        IF v_state.store_id IS NULL THEN
            PERFORM authz._mp_drop_store(v_state.store, v_state.registered_id);
            CONTINUE;
        END IF;

        TRUNCATE _mp_page;
        INSERT INTO _mp_page
        SELECT w.seq, w.action, w.performed_at, w.user_type, w.user_id, w.user_relation,
               w.relation, w.object_type, w.object_id
          FROM authz.watch_changes(v_state.store, v_state.cursor_at, v_state.cursor_seq, p_limit,
                                   p_until => v_cutoff) w;

        IF EXISTS (SELECT 1 FROM _mp_page pg WHERE pg.action = 'STORE_RETIRED') THEN
            PERFORM authz._mp_drop_store(v_state.store, v_state.registered_id);
            CONTINUE;
        END IF;

        SELECT pg.performed_at, pg.seq INTO v_last_at, v_last_seq
          FROM _mp_page pg ORDER BY pg.performed_at DESC, pg.seq DESC LIMIT 1;

        -- tuple deltas; names resolve against the current dictionaries
        SELECT count(*) INTO v_tuple_rows FROM _mp_page pg WHERE pg.action IN ('INSERT', 'UPDATE', 'DELETE');
        INSERT INTO _mp_claimed (store_id, object_type, object_id, relation, user_type, user_id, user_relation, op)
        SELECT v_state.store_id, ot.id, pg.object_id, r.id, ut.id, pg.user_id, ur.id, pg.action
          FROM _mp_page pg
          JOIN authz.types     ot ON ot.store_id = v_state.store_id AND ot.name = pg.object_type
          JOIN authz.relations r  ON r.store_id  = v_state.store_id AND r.name  = pg.relation
          JOIN authz.types     ut ON ut.store_id = v_state.store_id AND ut.name = pg.user_type
     LEFT JOIN authz.relations ur ON ur.store_id = v_state.store_id AND ur.name = pg.user_relation
         WHERE pg.action IN ('INSERT', 'UPDATE', 'DELETE');
        GET DIAGNOSTICS v_n = ROW_COUNT;

        -- structural change (a type was removed): the deltas cannot be
        -- mapped to pairs — rebuild the store instead of advancing past them
        IF v_n < v_tuple_rows OR EXISTS (SELECT 1 FROM _mp_page pg WHERE pg.action = 'TYPE_REMOVED') THEN
            v_rebuild    := v_rebuild    || v_state.store;
            v_rebuild_id := v_rebuild_id || v_state.store_id;
            DELETE FROM _mp_claimed c WHERE c.store_id = v_state.store_id;
            CONTINUE;
        END IF;

        -- inserted tuples that will expire: file the deferred delta.
        -- statement_timestamp(), like the RLS expiry policy: every tuple the
        -- derivation below can see is filed.
        INSERT INTO authz.materialized_refresh_queue
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
           AND NOT EXISTS (SELECT 1 FROM authz.materialized_refresh_queue q
                            WHERE q.op = 'EXPIRE' AND q.due_at = t.expires_at
                              AND q.store_id = t.store_id AND q.object_type = t.object_type
                              AND q.object_id = t.object_id AND q.relation = t.relation
                              AND q.user_type = t.user_type AND q.user_id = t.user_id
                              AND q.user_relation IS NOT DISTINCT FROM t.user_relation);

        INSERT INTO _mp_feed VALUES (
            v_state.store, v_state.store_id, v_tuple_rows,
            COALESCE(v_last_at, v_state.cursor_at), COALESCE(v_last_seq, v_state.cursor_seq),
            (SELECT count(*) FROM _mp_page) < p_limit);
    END LOOP;

    -- deferred deltas that fell due (expiries, manual entries) — of the
    -- stores this run holds the locks for; a skipped store's rows stay due
    WITH claimed AS (
        DELETE FROM authz.materialized_refresh_queue
         WHERE id IN (SELECT q.id FROM authz.materialized_refresh_queue q
                       WHERE q.due_at <= statement_timestamp()
                         AND q.store_id IN (SELECT f.store_id FROM _mp_feed f)
                       FOR UPDATE SKIP LOCKED)
         RETURNING store_id, object_type, object_id, relation, user_type, user_id, user_relation, op)
    INSERT INTO _mp_claimed (store_id, object_type, object_id, relation, user_type, user_id, user_relation, op)
    SELECT store_id, object_type, object_id, relation, user_type, user_id, user_relation, op FROM claimed;
    UPDATE _mp_feed f SET changes = f.changes + d.n
      FROM (SELECT c.store_id, count(*) AS n FROM _mp_claimed c
             WHERE c.op NOT IN ('INSERT', 'UPDATE', 'DELETE') GROUP BY c.store_id) d
     WHERE d.store_id = f.store_id;
    -- a store about to be rebuilt needs no pair work
    DELETE FROM _mp_claimed c
     WHERE c.store_id IN (SELECT st.id FROM authz.stores st WHERE st.name = ANY (v_rebuild));

    IF EXISTS (SELECT 1 FROM _mp_claimed) THEN
        PERFORM authz._mp_blast_radius();
        SELECT d.pairs, d.rows_written INTO v_pairs, v_written FROM authz._derive_pairs() d;
    END IF;

    UPDATE authz.materialized_refresh_state s
       SET cursor_at             = f.last_at,
           cursor_seq            = f.last_seq,
           feed_drained          = f.drained,
           as_of                 = GREATEST(s.as_of, CASE WHEN f.drained THEN v_cutoff ELSE f.last_at END),
           last_run_started_at   = v_started,
           last_run_finished_at  = clock_timestamp(),
           last_run_changes      = f.changes,
           last_run_pairs        = COALESCE((SELECT count(*) FROM _mp_pairs p WHERE p.store_id = f.store_id), 0),
           last_run_rows_written = COALESCE((SELECT sum(w.n) FROM _mp_written w WHERE w.store = f.store), 0),
           last_run_gate         = v_gate
      FROM _mp_feed f
     WHERE f.store = s.store AND s.store_id = f.store_id;   -- the incarnation this run read

    -- structural change: rebuild (its cursor is this run's cutoff). Both
    -- locks are held and the incarnation is the one the loop saw — the
    -- internal snapshot, not the public entry point (which would WAIT for
    -- the store-wide lock, see Locks)
    FOR v_i IN 1 .. coalesce(array_length(v_rebuild, 1), 0) LOOP
        PERFORM authz._mp_snapshot_store(v_rebuild[v_i], v_rebuild_id[v_i], v_cutoff, v_started, v_gate);
    END LOOP;

    RETURN v_pairs;
END;
$$;

------------------------------------------------------------------------
-- Whole-object re-derivation (every known subject × this object).
-- Kept for manual repair; the worker computes finer pairs itself.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._refresh_relations_for_object(
    p_store_id    integer,
    p_object_type integer,
    p_object_id   text
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
-- refresh_all_materialized_relations: register a store for incremental
-- refresh (or rebuild it): clear its derived rows, take the cursor at the
-- safe cutoff (watch_safe_until(p_lag): the stability lag before now, or
-- the oldest open transaction, whichever is earlier — never later than this
-- transaction's own start, so a write committing while the snapshot runs is
-- replayed, never missed), derive the blast radius of every tuple of the
-- store, file a deferred delta for every expiring tuple. Returns the rows
-- written.
------------------------------------------------------------------------
DROP FUNCTION IF EXISTS authz.refresh_all_materialized_relations(text);            -- pre-changefeed signature
DROP FUNCTION IF EXISTS authz.refresh_all_materialized_relations(text, interval);  -- pre-cutoff signature
CREATE OR REPLACE FUNCTION authz.refresh_all_materialized_relations(
    p_store text,
    p_lag   interval    DEFAULT '1 second',
    p_until timestamptz DEFAULT NULL      -- override the cutoff (tests, controlled replays); forfeits the guarantee
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_store_id  integer;
    v_started   timestamptz;
    v_cursor_at timestamptz;
BEGIN
    PERFORM authz._mp_require_read_committed('refresh_all_materialized_relations');
    -- Locks FIRST, in order (see Locks), and only then resolve the name: a
    -- delete_store in flight holds the store-wide lock exclusively from its
    -- first statement, so after this returns the deletion has committed
    -- ("Unknown store") or has not begun (and now waits for this snapshot).
    PERFORM pg_advisory_xact_lock_shared(hashtextextended(p_store || ':*', 0));
    PERFORM authz._mp_lock_store(p_store);
    v_store_id  := authz._s(p_store);
    v_started   := clock_timestamp();
    v_cursor_at := LEAST(COALESCE(p_until, authz.watch_safe_until(p_lag)), transaction_timestamp());
    RETURN authz._mp_snapshot_store(p_store, v_store_id, v_cursor_at, v_started, v_started - v_cursor_at);
END;
$$;

------------------------------------------------------------------------
-- _mp_snapshot_store: the snapshot itself — caller holds both locks and
-- has resolved the incarnation (refresh_all; the worker's rebuild).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._mp_snapshot_store(
    p_store     text,
    p_store_id  integer,
    p_cursor_at timestamptz,
    p_started   timestamptz,
    p_gate      interval
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_pairs     integer; v_written integer;
BEGIN
    DELETE FROM authz.materialized_relations WHERE store = p_store;
    DELETE FROM authz.materialized_subjects    WHERE store = p_store;
    DELETE FROM authz.materialized_objects     WHERE store = p_store;
    DELETE FROM authz.materialized_refresh_queue WHERE store_id = p_store_id;

    -- the snapshot is the blast radius of every tuple of the store, taken
    -- as an insert: every (subject, object) pair a grant can reach, and
    -- nothing else — linear in the grants, not objects × subjects
    PERFORM authz._mp_prepare_pairs();
    INSERT INTO _mp_claimed (store_id, object_type, object_id, relation, user_type, user_id, user_relation, op)
    SELECT t.store_id, t.object_type, t.object_id, t.relation, t.user_type, t.user_id, t.user_relation, 'SNAPSHOT'
      FROM authz.tuples t WHERE t.store_id = p_store_id;
    PERFORM authz._mp_blast_radius();
    SELECT d.pairs, d.rows_written INTO v_pairs, v_written FROM authz._derive_pairs() d;

    INSERT INTO authz.materialized_refresh_queue
        (store_id, object_type, object_id, relation, user_type, user_id, user_relation, op, due_at)
    SELECT t.store_id, t.object_type, t.object_id, t.relation, t.user_type, t.user_id, t.user_relation,
           'EXPIRE', t.expires_at
      FROM authz.tuples t
     WHERE t.store_id = p_store_id AND t.expires_at IS NOT NULL;   -- visible ⇒ not yet expired (RLS)

    INSERT INTO authz.materialized_refresh_state
        (store, store_id, cursor_at, cursor_seq, as_of, feed_drained,
         last_run_started_at, last_run_finished_at, last_run_changes, last_run_pairs, last_run_rows_written, last_run_gate)
    VALUES (p_store, p_store_id, p_cursor_at, 0, p_cursor_at, true, p_started, clock_timestamp(), 0, v_pairs, v_written, p_gate)
    ON CONFLICT (store) DO UPDATE
       SET store_id = EXCLUDED.store_id,
           cursor_at = EXCLUDED.cursor_at, cursor_seq = 0, as_of = EXCLUDED.as_of, feed_drained = true,
           last_run_started_at = EXCLUDED.last_run_started_at, last_run_finished_at = EXCLUDED.last_run_finished_at,
           last_run_changes = 0, last_run_pairs = EXCLUDED.last_run_pairs,
           last_run_rows_written = EXCLUDED.last_run_rows_written, last_run_gate = EXCLUDED.last_run_gate;

    RETURN v_written;
END;
$$;

------------------------------------------------------------------------
-- Status on the primary, one row per registered store.
------------------------------------------------------------------------
DROP FUNCTION IF EXISTS authz.materialized_relations_status();  -- return type changed
CREATE FUNCTION authz.materialized_relations_status()
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
    last_run_rows_written integer,
    last_run_gate         interval,     -- run start - cutoff at the last run (≥ p_lag; larger when a transaction was open)
    oldest_open_txn_age   interval      -- now: the next run's gate will be at least this
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT s.store, s.as_of, statement_timestamp() - s.as_of, s.feed_drained,
           (SELECT count(*) FROM authz.materialized_refresh_queue q
             WHERE q.store_id = st.id AND q.due_at <= statement_timestamp()),
           (SELECT count(*) FROM authz.materialized_refresh_queue q
             WHERE q.store_id = st.id AND q.due_at >  statement_timestamp()),
           s.last_run_started_at, s.last_run_finished_at,
           s.last_run_changes, s.last_run_pairs, s.last_run_rows_written, s.last_run_gate,
           (SELECT clock_timestamp() - min(a.xact_start) FROM pg_stat_activity a
             WHERE a.datname = current_database() AND a.pid <> pg_backend_pid() AND a.xact_start IS NOT NULL)
      FROM authz.materialized_refresh_state s
 LEFT JOIN authz.stores st ON st.id = s.store_id
     ORDER BY s.store;
$$;

-- An existing publication from the first version listed the permissions
-- table's leaf partitions and knew no state table: point it at the four
-- current tables, published through their roots. (A rename does not break
-- a publication — it tracks relations by OID — but the subscriber must be
-- renamed too; see db/replication/upgrade-derived-tables.sql.)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'authz_derived') THEN
        ALTER PUBLICATION authz_derived SET TABLE
            authz.materialized_relations, authz.materialized_subjects,
            authz.materialized_objects, authz.materialized_refresh_state;
        ALTER PUBLICATION authz_derived SET (publish_via_partition_root = true);
    END IF;
END;
$$;

-- The pre-changefeed design queued whole objects from a trigger on
-- authz.tuples; the audit changefeed is the source now.
DROP TRIGGER  IF EXISTS trg_queue_permissions_refresh ON authz.tuples;
DROP FUNCTION IF EXISTS authz._queue_permissions_refresh();
DROP FUNCTION IF EXISTS authz._sweep_materialized_subjects(integer);
DROP FUNCTION IF EXISTS authz.process_materialized_refresh_queue();

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
               AND (c.relname LIKE 'materialized\_%' OR c.relname = 'materialized_refresh_queue')
        LOOP
            EXECUTE format('ALTER TABLE %s OWNER TO authz_owner', r.obj);
        END LOOP;
        ALTER FUNCTION authz._mp_prepare_pairs()                                      OWNER TO authz_owner;
        ALTER FUNCTION authz._mp_require_read_committed(text)                         OWNER TO authz_owner;
        ALTER FUNCTION authz._mp_lock_store(text)                                     OWNER TO authz_owner;
        ALTER FUNCTION authz._mp_try_lock_store(text)                                 OWNER TO authz_owner;
        ALTER FUNCTION authz._mp_snapshot_store(text, integer, timestamptz, timestamptz, interval) OWNER TO authz_owner;
        ALTER FUNCTION authz._mp_drop_store(text, integer)                            OWNER TO authz_owner;
        ALTER FUNCTION authz._mp_on_store_deleted()                                   OWNER TO authz_owner;
        ALTER FUNCTION authz._mp_blast_radius()                                       OWNER TO authz_owner;
        ALTER FUNCTION authz._mp_ensure_known(integer)                                OWNER TO authz_owner;
        ALTER FUNCTION authz._derive_pairs()                                          OWNER TO authz_owner;
        ALTER FUNCTION authz._refresh_relations_for_object(integer, integer, text) OWNER TO authz_owner;
        ALTER FUNCTION authz.refresh_materialized_relations(interval, int, timestamptz)      OWNER TO authz_owner;
        ALTER FUNCTION authz.refresh_all_materialized_relations(text, interval, timestamptz) OWNER TO authz_owner;
        ALTER FUNCTION authz.materialized_relations_status()                       OWNER TO authz_owner;
    END IF;
END;
$$;

------------------------------------------------------------------------
-- Privileges: SECURITY DEFINER entry points are not for app roles.
-- PostgreSQL grants EXECUTE to PUBLIC on creation; take it back from every
-- function here and hand the three public ones to authz_admin when that
-- role exists (roles.sql). The worker role needs EXECUTE on
-- refresh_materialized_relations only.
------------------------------------------------------------------------
REVOKE ALL ON FUNCTION authz._mp_prepare_pairs()                                      FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._mp_require_read_committed(text)                         FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._mp_lock_store(text)                                     FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._mp_try_lock_store(text)                                 FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._mp_snapshot_store(text, integer, timestamptz, timestamptz, interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._mp_drop_store(text, integer)                            FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._mp_on_store_deleted()                                   FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._mp_blast_radius()                                       FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._mp_ensure_known(integer)                                FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._derive_pairs()                                          FROM PUBLIC;
REVOKE ALL ON FUNCTION authz._refresh_relations_for_object(integer, integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION authz.refresh_materialized_relations(interval, int, timestamptz)      FROM PUBLIC;
REVOKE ALL ON FUNCTION authz.refresh_all_materialized_relations(text, interval, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION authz.materialized_relations_status()                       FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authz_admin') THEN
        GRANT EXECUTE ON FUNCTION authz.refresh_materialized_relations(interval, int, timestamptz)      TO authz_admin;
        GRANT EXECUTE ON FUNCTION authz.refresh_all_materialized_relations(text, interval, timestamptz) TO authz_admin;
        GRANT EXECUTE ON FUNCTION authz.materialized_relations_status()                    TO authz_admin;
    END IF;
END;
$$;
