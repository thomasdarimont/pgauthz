-- Admin / maintenance API: redundant-tuple detection and cleanup.
--
-- Split out of access.sql so the read API stays purely read: find_redundant_tuples
-- is read-only analysis, but cleanup_redundant_tuples WRITES (it calls
-- delete_tuple). Part of the WRITE profile — not loaded into a read-only
-- deployment.
--
-- Depends on: access_internal.sql (authz._check_access), core_internal.sql
-- (authz._s/_t/_r, authz._eval_condition), schema.sql (authz._tuple_key), and
-- tuples.sql (authz.delete_tuple, used by cleanup).

------------------------------------------------------------------------
-- find_redundant_tuples: identifies direct tuples that are already
-- granted by another rule path (computed, TTU, or userset expansion).
--
-- For each direct, non-userset tuple in the store, the function
-- temporarily hides it and checks whether _check_access still returns
-- true. If it does, the tuple is redundant — the user already has
-- access through another path.
--
-- This is an admin/maintenance function meant to be run periodically,
-- not on the hot path. Cost is O(N) check_access calls where N is the
-- number of direct tuples in scope.
--
-- Parameters:
--   p_store       — store name
--   p_object_type — optional: limit scan to one object type (NULL = all)
--   p_relation    — optional: limit scan to one relation (NULL = all)
--   context       — optional: request context for conditional tuples
--
-- Returns one row per redundant tuple with the user, relation, object,
-- and the tuple's creation timestamp.
--
-- Example:
--   SELECT * FROM authz.find_redundant_tuples('demo');
--   SELECT * FROM authz.find_redundant_tuples('demo', 'document', 'can_read');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.find_redundant_tuples(
    p_store       text,
    p_object_type text DEFAULT NULL,
    p_relation    text DEFAULT NULL,
    context       jsonb DEFAULT NULL
) RETURNS TABLE (
    user_type   text,
    user_id     text,
    relation    text,
    object_type text,
    object_id   text,
    created_at  timestamptz
)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_object_type integer;
    v_relation    integer;
    tpl           record;
    v_still_ok    boolean;
    v_exclude     authz._tuple_key;
BEGIN
    IF p_object_type IS NOT NULL THEN
        v_object_type := authz._t(v_store_id, p_object_type);
    END IF;
    IF p_relation IS NOT NULL THEN
        v_relation := authz._r(v_store_id, p_relation);
    END IF;

    -- Scan all direct, non-userset tuples in scope.
    FOR tpl IN
        SELECT t.store_id, t.user_type, t.user_id, t.relation,
               t.object_type, t.object_id, t.created_at,
               t.condition_id, t.condition_context
          FROM authz.tuples t
         WHERE t.store_id      = v_store_id
           AND t.user_relation IS NULL
           AND t.user_id      != '*'   -- skip wildcards: they're foundational, not redundant
           AND t.object_id    != '*'   -- same for object wildcards (privileged grants)
           AND (v_object_type IS NULL OR t.object_type = v_object_type)
           AND (v_relation    IS NULL OR t.relation    = v_relation)
    LOOP
        -- If the tuple has a condition that doesn't pass with the given
        -- context, it's not currently granting access — skip it.
        IF tpl.condition_id IS NOT NULL THEN
            IF NOT authz._eval_condition(tpl.condition_id, tpl.condition_context, context) THEN
                CONTINUE;
            END IF;
        END IF;

        -- Check if access is still granted when this specific tuple is excluded.
        -- The exclude propagates through the entire recursive check, causing
        -- _eval_direct to skip the direct match for this exact tuple while
        -- still evaluating all other paths (computed, TTU, usersets).
        v_exclude := ROW(tpl.user_type, tpl.user_id, tpl.relation,
                         tpl.object_type, tpl.object_id)::authz._tuple_key;

        v_still_ok := authz._check_access(
            v_store_id, tpl.user_type, tpl.user_id,
            tpl.relation, tpl.object_type, tpl.object_id,
            context,
            false,   -- p_has_ctx_tuples
            0,       -- p_depth
            NULL,    -- p_trace
            v_exclude
        );

        IF v_still_ok THEN
            user_type   := (SELECT t.name FROM authz.types t     WHERE t.id = tpl.user_type);
            user_id     := tpl.user_id;
            relation    := (SELECT r.name FROM authz.relations r WHERE r.id = tpl.relation);
            object_type := (SELECT t.name FROM authz.types t     WHERE t.id = tpl.object_type);
            object_id   := tpl.object_id;
            created_at  := tpl.created_at;
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;

------------------------------------------------------------------------
-- cleanup_redundant_tuples: finds and optionally deletes direct tuples
-- that are already granted by another rule path.
--
-- Wraps find_redundant_tuples. By default performs a dry run (p_dry_run
-- = true) that only lists what would be deleted. Set p_dry_run = false
-- to actually delete the redundant tuples.
--
-- Deleted tuples are recorded in the audit trail via delete_tuple with
-- p_performed_by = 'cleanup_redundant_tuples'.
--
-- Parameters:
--   p_store       — store name
--   p_object_type — optional: limit to one object type (NULL = all)
--   p_relation    — optional: limit to one relation (NULL = all)
--   p_context     — optional: request context for conditional tuples
--   p_dry_run     — if true (default), only list; if false, delete
--
-- Returns one row per redundant tuple found (or deleted), with a
-- boolean indicating whether it was actually removed.
--
-- Example:
--   SELECT * FROM authz.cleanup_redundant_tuples('demo');
--   SELECT * FROM authz.cleanup_redundant_tuples('demo', p_dry_run := false);
--   SELECT * FROM authz.cleanup_redundant_tuples('demo', 'document', 'can_read');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.cleanup_redundant_tuples(
    p_store       text,
    p_object_type text    DEFAULT NULL,
    p_relation    text    DEFAULT NULL,
    p_context     jsonb   DEFAULT NULL,
    p_dry_run     boolean DEFAULT true
) RETURNS TABLE (
    user_type   text,
    user_id     text,
    relation    text,
    object_type text,
    object_id   text,
    created_at  timestamptz,
    deleted     boolean
)
LANGUAGE plpgsql AS $$
DECLARE
    tpl record;
    v_deleted boolean;
BEGIN
    FOR tpl IN
        SELECT r.user_type, r.user_id, r.relation,
               r.object_type, r.object_id, r.created_at
          FROM authz.find_redundant_tuples(p_store, p_object_type, p_relation, p_context) r
    LOOP
        v_deleted := false;

        IF NOT p_dry_run THEN
            PERFORM authz.delete_tuple(p_store,
                tpl.user_type, tpl.user_id, tpl.relation,
                tpl.object_type, tpl.object_id,
                p_performed_by := 'cleanup_redundant_tuples');
            v_deleted := true;
        END IF;

        user_type   := tpl.user_type;
        user_id     := tpl.user_id;
        relation    := tpl.relation;
        object_type := tpl.object_type;
        object_id   := tpl.object_id;
        created_at  := tpl.created_at;
        deleted     := v_deleted;
        RETURN NEXT;
    END LOOP;
END;
$$;

------------------------------------------------------------------------
-- cleanup_expired_tuples: reclaim storage from expired grants.
--
-- Expired tuples already grant NOTHING (row-level security hides them from
-- every read path the moment expires_at passes) — this is garbage
-- collection, not revocation. Deletions run through the ordinary audit
-- trigger, so history is preserved and time-travel stays exact: the replay
-- honors expires_at against the asked timestamp, and the cleanup DELETE is
-- just a later event.
--
-- p_store NULL = all stores (scheduled maintenance); p_grace keeps recently
-- expired rows around (debugging/inspection via the audit log).
--
--   SELECT authz.cleanup_expired_tuples();                     -- everything expired
--   SELECT authz.cleanup_expired_tuples('tenant_a', '7 days'); -- one store, 7d grace
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.cleanup_expired_tuples(
    p_store        text DEFAULT NULL,
    p_grace        interval DEFAULT '0',
    p_performed_by text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer;
    v_count    integer;
BEGIN
    PERFORM set_config('authz.performed_by', COALESCE(p_performed_by, ''), true);
    IF p_store IS NOT NULL THEN
        v_store_id := authz._s(p_store);
    END IF;

    -- The escape is required: the WHERE reads expires_at, which folds the
    -- SELECT policy in — without it the expired rows are invisible even to
    -- their own cleanup.
    PERFORM set_config('authz.tuples_include_expired', 'on', true);
    DELETE FROM authz.tuples t
     WHERE t.expires_at IS NOT NULL
       AND t.expires_at <= now() - p_grace
       AND (v_store_id IS NULL OR t.store_id = v_store_id);

    GET DIAGNOSTICS v_count = ROW_COUNT;  -- before the reset (a statement itself)
    PERFORM set_config('authz.tuples_include_expired', '', true);
    RETURN v_count;
END;
$$;
