-- Public model management API: type/relation registration, rule management,
-- and namespace access control.
-- All functions accept text parameters and resolve IDs internally.
--
-- Depends on: engine/core_internal.sql

------------------------------------------------------------------------
-- model_register_type: registers a new object type and creates its
-- tuple partition in one call.
--
-- Parameters:
--   p_store          — store name
--   p_type_name      — the object type name (e.g. 'invoice')
--   p_hash_modulus   — number of hash sub-partitions on object_id
--                      (0 = simple partition, 8 = recommended for high-volume types)
--   p_namespace      — optional namespace for access control
--   p_description    — optional description
--   p_labels         — optional logical-grouping labels (key:value, e.g.
--                      ARRAY['group:accounting','group:sharing']); advisory only
--
-- Returns the new type's integer ID.
-- Idempotent for the partition (safe to call again), but will raise
-- a unique violation if the type name already exists in this store.
--
-- Examples:
--   SELECT authz.model_register_type('demo', 'invoice');
--   SELECT authz.model_register_type('demo', 'invoice', 8);
--   SELECT authz.model_register_type('demo', 'invoice', 8, 'accounting');
--   SELECT authz.model_register_type('demo', 'invoice', 8, 'accounting', NULL,
--                                    ARRAY['group:accounting','group:finance']);
------------------------------------------------------------------------
-- Drop the pre-labels signature so adding the trailing param doesn't leave a
-- second (5-arg) overload behind on upgraded installs.
DROP FUNCTION IF EXISTS authz.model_register_type(text, text, int, text, text);

CREATE OR REPLACE FUNCTION authz.model_register_type(
    p_store        text,
    p_type_name    text,
    p_hash_modulus int DEFAULT 0,
    p_namespace    text DEFAULT NULL,
    p_description  text DEFAULT NULL,
    p_labels       text[] DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_type_id  integer;
BEGIN
    INSERT INTO authz.types (store_id, name, namespace, description, labels)
    VALUES (v_store_id, p_type_name, p_namespace, p_description, COALESCE(p_labels, '{}'))
    RETURNING id INTO v_type_id;

    PERFORM authz._ensure_tuple_partition(v_store_id, p_type_name, p_hash_modulus);

    RETURN v_type_id;
END;
$$;

------------------------------------------------------------------------
-- model_set_type_labels: replace the logical-grouping labels on an existing
-- type. Labels are advisory key:value metadata (see migration 0003); they have
-- no access-control effect. Passing NULL/'{}' clears them.
--
-- Examples:
--   SELECT authz.model_set_type_labels('demo', 'engagement',
--              ARRAY['group:accounting','group:sharing']);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_set_type_labels(
    p_store     text,
    p_type_name text,
    p_labels    text[]
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
BEGIN
    UPDATE authz.types
       SET labels = COALESCE(p_labels, '{}')
     WHERE store_id = v_store_id AND name = p_type_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'type % not found in store %', p_type_name, p_store;
    END IF;
END;
$$;

------------------------------------------------------------------------
-- model_add_type_labels / model_remove_type_labels: incremental label edits
-- that union/subtract instead of replacing the whole set. Both are idempotent
-- (adding an existing label or removing an absent one is a no-op on the set).
--
-- Examples:
--   SELECT authz.model_add_type_labels('demo', 'engagement', ARRAY['area:reporting']);
--   SELECT authz.model_remove_type_labels('demo', 'engagement', ARRAY['area:sharing']);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_add_type_labels(
    p_store     text,
    p_type_name text,
    p_labels    text[]
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
BEGIN
    UPDATE authz.types
       SET labels = ARRAY(SELECT DISTINCT e FROM unnest(labels || COALESCE(p_labels, '{}')) AS e)
     WHERE store_id = v_store_id AND name = p_type_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'type % not found in store %', p_type_name, p_store;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION authz.model_remove_type_labels(
    p_store     text,
    p_type_name text,
    p_labels    text[]
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
BEGIN
    UPDATE authz.types
       SET labels = ARRAY(SELECT e FROM unnest(labels) AS e WHERE e <> ALL(COALESCE(p_labels, '{}')))
     WHERE store_id = v_store_id AND name = p_type_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'type % not found in store %', p_type_name, p_store;
    END IF;
END;
$$;

------------------------------------------------------------------------
-- model_remove_type: removes a type from a store's dictionary together
-- with everything the model says about it — rules on the type, type
-- restrictions where it is the object type OR the allowed subject type —
-- and its dedicated tuple partition. The relations the type's rules used
-- stay registered (other types may use them).
--
-- Fail-closed guards, in order:
--   1. Temporal gates on the type, recorded events naming it (as subject
--      or object) → always refused; drop the gates / purge the events
--      first (those are deliberate operator actions).
--   2. Tuples naming the type on either side → refused unless p_force,
--      which deletes them (expired rows too) through the audited path:
--      every removed tuple gets a DELETE audit row attributed to
--      p_performed_by / the effective role, and the changefeed is notified.
--
-- What it does NOT do: touch the audit tables. The type's history stays in
-- tuples_audit / models_audit under its integer id, but the live dictionary
-- no longer resolves that id, so audit_check_access / audit_list_* for the
-- removed type raise "Unknown type" from then on — exactly as delete_store
-- (vs retire_store) does for a whole store. For an audit-critical store,
-- keep the type registered and delete its tuples instead.
--
-- Returns a summary: {"type", "tuples_deleted", "rules_removed",
-- "restrictions_removed", "partition_dropped"}.
--
-- Examples:
--   SELECT authz.model_remove_type('demo', 'legacy_report');
--   SELECT authz.model_remove_type('demo', 'legacy_report', p_force => true);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_remove_type(
    p_store        text,
    p_type_name    text,
    p_force        boolean DEFAULT false,
    p_performed_by text    DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id     integer := authz._s(p_store);
    v_type_id      integer := authz._t(v_store_id, p_type_name);
    v_gates        int;
    v_events       bigint;
    v_tuples       bigint := 0;
    v_rules        int;
    v_restrictions int;
    v_part_name    text;
    v_part_dropped boolean := false;
BEGIN
    -- 1. Hard references: never removed implicitly.
    SELECT count(*) INTO v_gates FROM authz.model_gates g
     WHERE g.store_id = v_store_id AND g.object_type = v_type_id;
    IF v_gates > 0 THEN
        RAISE EXCEPTION 'model_remove_type: type % in store % has % temporal gate(s) — drop them first (drop_gate)',
            p_type_name, p_store, v_gates;
    END IF;
    SELECT count(*) INTO v_events FROM authz.events e
     WHERE e.store_id = v_store_id AND (e.subject_type = v_type_id OR e.object_type = v_type_id);
    IF v_events > 0 THEN
        RAISE EXCEPTION 'model_remove_type: type % in store % is named by % recorded event(s) — purge them first (purge_events)',
            p_type_name, p_store, v_events;
    END IF;

    -- 2. Tuples on either side: refuse, or (p_force) delete through the
    --    audited path. Expired rows are hidden from this count by RLS but
    --    deleted by the helper; the count reported is the helper's.
    SELECT count(*) INTO v_tuples FROM authz.tuples t
     WHERE t.store_id = v_store_id AND (t.object_type = v_type_id OR t.user_type = v_type_id);
    IF v_tuples > 0 AND NOT p_force THEN
        RAISE EXCEPTION 'model_remove_type: type % in store % is referenced by % tuple(s) (as object or subject) — delete them first, or pass p_force => true to delete them',
            p_type_name, p_store, v_tuples;
    END IF;
    PERFORM set_config('authz.performed_by', COALESCE(p_performed_by, ''), true);
    v_tuples := authz._rls_delete_type_tuples(v_store_id, v_type_id);

    -- 3. Model rows that mention the type (logged to their audit tables).
    DELETE FROM authz.grant_rules g
     WHERE g.store_id = v_store_id AND g.object_type = v_type_id;
    DELETE FROM authz.type_restrictions x
     WHERE x.store_id = v_store_id
       AND (x.object_type = v_type_id OR x.allowed_user_type = v_type_id);
    GET DIAGNOSTICS v_restrictions = ROW_COUNT;
    DELETE FROM authz.models m
     WHERE m.store_id = v_store_id AND m.object_type = v_type_id;
    GET DIAGNOSTICS v_rules = ROW_COUNT;

    -- 4. The type's dedicated partition (same naming as _ensure_tuple_partition).
    v_part_name := 'tuples_' || regexp_replace(p_store, '[^a-zA-Z0-9]', '_', 'g')
                   || '_'     || regexp_replace(p_type_name, '[^a-zA-Z0-9]', '_', 'g');
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'authz' AND c.relname = v_part_name AND c.relispartition) THEN
        EXECUTE format('ALTER TABLE authz.tuples DETACH PARTITION authz.%I', v_part_name);
        EXECUTE format('DROP TABLE authz.%I', v_part_name);
        v_part_dropped := true;
    END IF;

    -- 5. The dictionary row, plus a TYPE_REMOVED marker in the audit trail
    --    (object_type keeps the now-unresolvable id, object_id carries the
    --    NAME so changefeed consumers can read it; sentinel 0/'*' elsewhere,
    --    as STORE_RETIRED). watch_changes surfaces it to every watcher.
    DELETE FROM authz.types WHERE id = v_type_id;
    INSERT INTO authz.tuples_audit (
        action, performed_at, performed_by, store_id,
        user_type, user_id, user_relation, relation, object_type, object_id,
        condition_id, condition_context
    ) VALUES (
        'TYPE_REMOVED', transaction_timestamp(),
        COALESCE(NULLIF(current_setting('authz.performed_by', true), ''), authz._effective_role()),
        v_store_id, 0, '*', NULL, 0, v_type_id, p_type_name, NULL, NULL
    );
    PERFORM pg_notify('authz_changes', v_store_id::text);

    RETURN jsonb_build_object(
        'type',                 p_type_name,
        'tuples_deleted',       v_tuples,
        'rules_removed',        v_rules,
        'restrictions_removed', v_restrictions,
        'partition_dropped',    v_part_dropped);
END;
$$;

------------------------------------------------------------------------
-- model_add_grant_rule: declare who may grant (and revoke) a relation on a
-- type through authz.grant / authz.revoke (migration 0017). The actor
-- must be ALLOWED p_requires on the same object to grant p_relation, and
-- p_requires_revoke (default: p_requires) to revoke it. Upsert: re-adding
-- changes the requirements in place (audited as DELETE + INSERT).
--
-- The sharing policy thereby lives in the model — rendered by
-- describe_model, versioned through the registry — instead of in every
-- application call site. Relations without a rule cannot be granted via
-- authz.grant at all (the writer role's write_tuple is unaffected).
--
-- Examples:
--   SELECT authz.model_add_grant_rule('docs', 'document', 'viewer', 'can_share_view');
--   SELECT authz.model_add_grant_rule('docs', 'document', 'editor', 'can_share_edit',
--                                      p_requires_revoke => 'owner');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_add_grant_rule(
    p_store           text,
    p_object_type     text,
    p_relation        text,
    p_requires        text,
    p_requires_revoke text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_type     integer := authz._t(v_store_id, p_object_type);
    v_rel      integer := authz._r(v_store_id, p_relation);
    v_req      integer := authz._r(v_store_id, p_requires);
    v_req_rev  integer := CASE WHEN p_requires_revoke IS NULL THEN NULL
                               ELSE authz._r(v_store_id, p_requires_revoke) END;
    v_id       integer;
BEGIN
    -- A rule "granting X requires X" would let anyone who holds X hand it
    -- on without a separate sharing right: almost always a mistake, and
    -- trivially expressible on purpose with a computed relation.
    IF v_req = v_rel THEN
        RAISE EXCEPTION 'model_add_grant_rule: % on % cannot require itself — use a dedicated sharing relation (e.g. can_share_%)',
            p_relation, p_object_type, p_relation;
    END IF;
    INSERT INTO authz.grant_rules (store_id, object_type, relation, requires, requires_revoke)
    VALUES (v_store_id, v_type, v_rel, v_req, v_req_rev)
    ON CONFLICT (store_id, object_type, relation) DO UPDATE
        SET requires = EXCLUDED.requires, requires_revoke = EXCLUDED.requires_revoke
      WHERE (authz.grant_rules.requires, authz.grant_rules.requires_revoke)
            IS DISTINCT FROM (EXCLUDED.requires, EXCLUDED.requires_revoke)
    RETURNING id INTO v_id;
    IF v_id IS NULL THEN
        SELECT g.id INTO v_id FROM authz.grant_rules g
         WHERE g.store_id = v_store_id AND g.object_type = v_type AND g.relation = v_rel;
    END IF;
    RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION authz.model_drop_grant_rule(
    p_store       text,
    p_object_type text,
    p_relation    text
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
BEGIN
    DELETE FROM authz.grant_rules g
     WHERE g.store_id = v_store_id
       AND g.object_type = authz._t(v_store_id, p_object_type)
       AND g.relation    = authz._r(v_store_id, p_relation);
    RETURN FOUND;
END;
$$;

------------------------------------------------------------------------
-- model_register_relation: registers a new relation name in a store.
--
-- Idempotent — returns the relation's integer ID whether it was
-- newly created or already existed.
--
-- Examples:
--   SELECT authz.model_register_relation('demo', 'can_archive');
--   SELECT authz.model_register_relation('demo', 'can_approve', 'Approval permission');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_register_relation(
    p_store       text,
    p_name        text,
    p_description text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_relation_id integer;
BEGIN
    INSERT INTO authz.relations (store_id, name, description)
    VALUES (v_store_id, p_name, p_description)
    ON CONFLICT (store_id, name) DO UPDATE SET name = EXCLUDED.name
    RETURNING id INTO v_relation_id;

    RETURN v_relation_id;
END;
$$;

------------------------------------------------------------------------
-- model_add_rule: adds a single model rule. Idempotent — duplicate
-- inserts are silently ignored (ON CONFLICT DO NOTHING).
-- Returns the rule's integer ID (existing or new).
--
-- Validates:
--   - rule_type is one of 'direct', 'computed', 'ttu'
--   - computed rules require p_computed_relation
--   - TTU rules require p_tupleset_relation and p_tupleset_computed
--   - group_op consistency: all rules in a group must use the same op
--
-- Examples:
--   SELECT authz.model_add_rule('demo', 'document', 'viewer', 'direct');
--   SELECT authz.model_add_rule('demo', 'document', 'can_read', 'computed',
--       p_computed_relation => 'viewer');
--   SELECT authz.model_add_rule('demo', 'document', 'can_read', 'ttu',
--       p_tupleset_relation => 'in_internal_space',
--       p_tupleset_computed => 'can_view');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_add_rule(
    p_store              text,
    p_object_type           text,
    p_relation              text,
    p_rule_type             text,                 -- 'direct', 'computed', 'ttu'
    p_computed_relation     text DEFAULT NULL,
    p_tupleset_relation     text DEFAULT NULL,
    p_tupleset_computed     text DEFAULT NULL,
    p_group_id              integer DEFAULT 0,
    p_group_op              text DEFAULT 'or',    -- 'or', 'intersection', 'exclusion'
    p_negated               boolean DEFAULT false,
    p_allow_object_wildcard boolean DEFAULT false -- direct rules only: permit object_id = '*' tuples
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id     integer := authz._s(p_store);
    v_object_type  integer := authz._t(v_store_id, p_object_type);
    v_relation     integer := authz._r(v_store_id, p_relation);
    v_rule_type    integer;
    v_computed_rel integer;
    v_tupleset_rel integer;
    v_tupleset_cmp integer;
    v_group_op     integer;
    v_rule_id      integer;
BEGIN
    -- Resolve rule_type
    CASE p_rule_type
        WHEN 'direct'   THEN v_rule_type := authz._rel_direct();
        WHEN 'computed' THEN v_rule_type := authz._rel_computed();
        WHEN 'ttu'      THEN v_rule_type := authz._rel_ttu();
        ELSE RAISE EXCEPTION 'Invalid rule_type: %. Must be direct, computed, or ttu', p_rule_type;
    END CASE;

    IF p_allow_object_wildcard AND v_rule_type <> authz._rel_direct() THEN
        RAISE EXCEPTION 'p_allow_object_wildcard is only allowed on direct rules';
    END IF;

    -- Resolve group_op
    CASE p_group_op
        WHEN 'or'           THEN v_group_op := authz._combine_or();
        WHEN 'intersection' THEN v_group_op := authz._combine_and();
        WHEN 'exclusion'    THEN v_group_op := authz._combine_exclusion();
        ELSE RAISE EXCEPTION 'Invalid group_op: %. Must be or, intersection, or exclusion', p_group_op;
    END CASE;

    -- Validate rule-type-specific parameters
    IF v_rule_type = authz._rel_computed() THEN
        IF p_computed_relation IS NULL THEN
            RAISE EXCEPTION 'computed rules require p_computed_relation';
        END IF;
        v_computed_rel := authz._r(v_store_id, p_computed_relation);
    ELSIF v_rule_type = authz._rel_ttu() THEN
        IF p_tupleset_relation IS NULL OR p_tupleset_computed IS NULL THEN
            RAISE EXCEPTION 'ttu rules require p_tupleset_relation and p_tupleset_computed';
        END IF;
        v_tupleset_rel := authz._r(v_store_id, p_tupleset_relation);
        v_tupleset_cmp := authz._r(v_store_id, p_tupleset_computed);
    END IF;

    -- Check group_op consistency: all rules in a group must use the same op
    IF EXISTS (
        SELECT 1 FROM authz.models
         WHERE store_id = v_store_id
           AND object_type = v_object_type
           AND relation = v_relation
           AND group_id = p_group_id
           AND group_op <> v_group_op
    ) THEN
        RAISE EXCEPTION 'group % already uses a different group_op', p_group_id;
    END IF;

    -- Insert (idempotent via unique index). Re-adding an existing rule
    -- with a different allow_object_wildcard applies the new flag.
    INSERT INTO authz.models (
        store_id, object_type, relation, rule_type,
        computed_relation, tupleset_relation, tupleset_computed,
        group_id, group_op, negated, allow_object_wildcard
    ) VALUES (
        v_store_id, v_object_type, v_relation, v_rule_type,
        v_computed_rel, v_tupleset_rel, v_tupleset_cmp,
        p_group_id, v_group_op, p_negated, p_allow_object_wildcard
    )
    ON CONFLICT (
        store_id, object_type, relation, rule_type,
        COALESCE(computed_relation, -1),
        COALESCE(tupleset_relation, -1),
        COALESCE(tupleset_computed, -1),
        group_id, negated
    ) DO UPDATE SET allow_object_wildcard = EXCLUDED.allow_object_wildcard;

    -- Return the rule ID (whether newly inserted or already existing)
    SELECT id INTO v_rule_id FROM authz.models
     WHERE store_id = v_store_id
       AND object_type = v_object_type
       AND relation = v_relation
       AND rule_type = v_rule_type
       AND COALESCE(computed_relation, -1) = COALESCE(v_computed_rel, -1)
       AND COALESCE(tupleset_relation, -1) = COALESCE(v_tupleset_rel, -1)
       AND COALESCE(tupleset_computed, -1) = COALESCE(v_tupleset_cmp, -1)
       AND group_id = p_group_id
       AND negated = p_negated;

    RETURN v_rule_id;
END;
$$;

------------------------------------------------------------------------
-- model_remove_rule: removes a single model rule by ID.
-- Returns true if the rule was deleted, false if it didn't exist.
-- Validates that the rule belongs to the specified store.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_remove_rule(
    p_store   text,
    p_rule_id integer
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_deleted  boolean;
BEGIN
    DELETE FROM authz.models
     WHERE id = p_rule_id
       AND store_id = v_store_id;

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

------------------------------------------------------------------------
-- model_remove_rules: removes all model rules for a specific
-- (object_type, relation) combination. Returns the count of deleted rules.
-- Useful when redefining how a relation is resolved.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_remove_rules(
    p_store       text,
    p_object_type text,
    p_relation    text
) RETURNS int
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_object_type integer := authz._t(v_store_id, p_object_type);
    v_relation    integer := authz._r(v_store_id, p_relation);
    v_count       int;
BEGIN
    -- Cascade: remove type restrictions for this (object_type, relation)
    DELETE FROM authz.type_restrictions
     WHERE store_id = v_store_id
       AND object_type = v_object_type
       AND relation = v_relation;

    DELETE FROM authz.models
     WHERE store_id = v_store_id
       AND object_type = v_object_type
       AND relation = v_relation;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

------------------------------------------------------------------------
-- grant_namespace_access: grants read and/or write access to a namespace
-- for a DB role. Uses INSERT ... ON CONFLICT to upsert — calling it
-- multiple times with different flags merges them (OR'd).
--
-- Examples:
--   SELECT authz.grant_namespace_access('demo', 'hr', 'app_hr', true, true);
--   SELECT authz.grant_namespace_access('demo', 'hr', 'app_portal', can_read := true);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.grant_namespace_access(
    p_store     text,
    p_namespace text,
    p_db_role   text,
    p_can_read  boolean DEFAULT false,
    p_can_write boolean DEFAULT false
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
BEGIN
    INSERT INTO authz.namespace_access (store_id, namespace, db_role, can_read, can_write)
    VALUES (v_store_id, p_namespace, p_db_role, p_can_read, p_can_write)
    ON CONFLICT (store_id, namespace, db_role) DO UPDATE
        SET can_read  = authz.namespace_access.can_read  OR EXCLUDED.can_read,
            can_write = authz.namespace_access.can_write OR EXCLUDED.can_write;
END;
$$;

------------------------------------------------------------------------
-- revoke_namespace_access: revokes read and/or write access from a
-- namespace for a DB role. When both flags become false, the row is
-- deleted automatically.
--
-- Examples:
--   SELECT authz.revoke_namespace_access('demo', 'hr', 'app_portal', can_read := true);
--   SELECT authz.revoke_namespace_access('demo', 'hr', 'app_hr', true, true);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.revoke_namespace_access(
    p_store     text,
    p_namespace text,
    p_db_role   text,
    p_can_read  boolean DEFAULT false,
    p_can_write boolean DEFAULT false
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
BEGIN
    UPDATE authz.namespace_access
       SET can_read  = can_read  AND NOT p_can_read,
           can_write = can_write AND NOT p_can_write
     WHERE store_id  = v_store_id
       AND namespace = p_namespace
       AND db_role   = p_db_role;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    -- Clean up rows with no permissions remaining
    DELETE FROM authz.namespace_access
     WHERE store_id  = v_store_id
       AND namespace = p_namespace
       AND db_role   = p_db_role
       AND NOT can_read
       AND NOT can_write;

    RETURN true;
END;
$$;

------------------------------------------------------------------------
-- model_add_type_restriction: defines which subject types can be
-- directly assigned to a relation. Idempotent (ON CONFLICT DO NOTHING).
--
-- Examples:
--   -- Allow direct user assignments:
--   SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'user');
--   -- Allow wildcard (user:*):
--   SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'user',
--       p_allow_wildcard => true);
--   -- Allow userset (group#member):
--   SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'group',
--       p_allowed_user_relation => 'member');
--   -- Wildcard viewers MUST carry the condition (OpenFGA `[user:* with cond]`):
--   SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'user',
--       p_allow_wildcard => true, p_condition => 'office_hours');
--
-- A facet with p_condition requires that condition on tuples of its shape;
-- a facet without one is OPEN (unconditioned tuples, and conditioned ones
-- with any condition, match it). To REQUIRE a condition for a shape, define
-- only conditioned facets for it. Migration 0015.
------------------------------------------------------------------------
-- Signature grew a p_condition parameter (migration 0015); drop the old
-- overload so short calls stay unambiguous on an in-place upgrade.
DROP FUNCTION IF EXISTS authz.model_add_type_restriction(text, text, text, text, text, boolean);
CREATE OR REPLACE FUNCTION authz.model_add_type_restriction(
    p_store                 text,
    p_object_type           text,
    p_relation              text,
    p_allowed_user_type     text,
    p_allowed_user_relation text DEFAULT NULL,
    p_allow_wildcard        boolean DEFAULT false,
    p_condition             text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id         integer := authz._s(p_store);
    v_object_type      integer := authz._t(v_store_id, p_object_type);
    v_relation         integer := authz._r(v_store_id, p_relation);
    v_allowed_user_type integer := authz._t(v_store_id, p_allowed_user_type);
    v_allowed_user_rel integer;
    v_condition_id     integer;
    v_id               integer;
BEGIN
    -- Wildcard and user_relation are mutually exclusive
    IF p_allow_wildcard AND p_allowed_user_relation IS NOT NULL THEN
        RAISE EXCEPTION 'allow_wildcard and allowed_user_relation cannot be combined';
    END IF;

    IF p_allowed_user_relation IS NOT NULL THEN
        v_allowed_user_rel := authz._r(v_store_id, p_allowed_user_relation);
    END IF;

    IF p_condition IS NOT NULL THEN
        SELECT c.id INTO v_condition_id
          FROM authz.conditions c
         WHERE c.store_id = v_store_id AND c.name = p_condition;
        IF v_condition_id IS NULL THEN
            RAISE EXCEPTION 'Unknown condition "%" in store "%"', p_condition, p_store
                USING HINT = 'Create it first (authz.create_condition_sql / create_condition_cel), then bind the facet.';
        END IF;
    END IF;

    INSERT INTO authz.type_restrictions (
        store_id, object_type, relation,
        allowed_user_type, allowed_user_relation, allow_wildcard, condition_id
    ) VALUES (
        v_store_id, v_object_type, v_relation,
        v_allowed_user_type, v_allowed_user_rel, p_allow_wildcard, v_condition_id
    )
    ON CONFLICT (store_id, object_type, relation, allowed_user_type,
                 COALESCE(allowed_user_relation, -1), allow_wildcard,
                 COALESCE(condition_id, -1))
    DO NOTHING;

    -- Return the restriction ID (whether newly inserted or already existing)
    SELECT id INTO v_id FROM authz.type_restrictions
     WHERE store_id = v_store_id
       AND object_type = v_object_type
       AND relation = v_relation
       AND allowed_user_type = v_allowed_user_type
       AND COALESCE(allowed_user_relation, -1) = COALESCE(v_allowed_user_rel, -1)
       AND allow_wildcard = p_allow_wildcard
       AND COALESCE(condition_id, -1) = COALESCE(v_condition_id, -1);

    RETURN v_id;
END;
$$;

------------------------------------------------------------------------
-- model_remove_type_restriction: removes a single type restriction by ID.
-- Returns true if it was deleted, false if it didn't exist.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_remove_type_restriction(
    p_store          text,
    p_restriction_id integer
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
BEGIN
    DELETE FROM authz.type_restrictions
     WHERE id = p_restriction_id
       AND store_id = v_store_id;

    RETURN FOUND;
END;
$$;

------------------------------------------------------------------------
-- model_remove_type_restrictions: removes all type restrictions for a
-- specific (object_type, relation). Returns the count of deleted rows.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_remove_type_restrictions(
    p_store       text,
    p_object_type text,
    p_relation    text
) RETURNS int
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_object_type integer := authz._t(v_store_id, p_object_type);
    v_relation    integer := authz._r(v_store_id, p_relation);
    v_count       int;
BEGIN
    DELETE FROM authz.type_restrictions
     WHERE store_id = v_store_id
       AND object_type = v_object_type
       AND relation = v_relation;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

------------------------------------------------------------------------
-- describe_model: render a store's model as readable, OpenFGA-DSL-flavored
-- text (for review/debugging — NOT a round-trippable export; see the
-- export_openfga_model roadmap item). Reconstructs each relation's expression
-- from the stored rule groups: groups are OR'd; within a group rules combine
-- with `or` / `and` / `but not` (negated rules are the excluded part). Direct
-- rules render their type restrictions as `[user, team#member, user:*]`.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._describe_type_restrictions(
    p_store_id integer, p_object_type integer, p_relation integer
) RETURNS text LANGUAGE sql STABLE AS $$
    SELECT string_agg(
               aut.name
               || CASE WHEN tr.allow_wildcard                 THEN ':*'
                       WHEN tr.allowed_user_relation IS NOT NULL THEN '#' || aur.name
                       ELSE '' END
               || CASE WHEN c.name IS NOT NULL THEN ' with ' || c.name ELSE '' END,
               -- plain type, then usersets, then wildcard; open facet before bound
               ', ' ORDER BY aut.name, tr.allow_wildcard, aur.name NULLS FIRST, c.name NULLS FIRST)
      FROM authz.type_restrictions tr
      JOIN authz.types aut          ON aut.id = tr.allowed_user_type
      LEFT JOIN authz.relations aur ON aur.id = tr.allowed_user_relation
      LEFT JOIN authz.conditions c  ON c.id   = tr.condition_id
     WHERE tr.store_id = p_store_id AND tr.object_type = p_object_type AND tr.relation = p_relation;
$$;

CREATE OR REPLACE FUNCTION authz._describe_atom(
    p_store_id integer, p_object_type integer, p_relation integer, m authz.models
) RETURNS text LANGUAGE plpgsql STABLE AS $$
BEGIN
    IF m.rule_type = authz._rel_direct() THEN
        RETURN '[' || coalesce(authz._describe_type_restrictions(p_store_id, p_object_type, p_relation), 'any') || ']';
    ELSIF m.rule_type = authz._rel_computed() THEN
        RETURN (SELECT name FROM authz.relations WHERE id = m.computed_relation);
    ELSIF m.rule_type = authz._rel_ttu() THEN
        RETURN (SELECT name FROM authz.relations WHERE id = m.tupleset_computed)
            || ' from ' || (SELECT name FROM authz.relations WHERE id = m.tupleset_relation);
    END IF;
    RETURN '?';
END;
$$;

-- Temporal gates (ADR 0012) render as `#` comment lines under the relation's
-- define line — one header per gate, one line per clause, keys in the
-- grammar's order, values as compact JSON — so the OpenFGA parser ignores
-- them. Display only: the round-trip carrier for gates is export_model.
CREATE OR REPLACE FUNCTION authz._describe_gates(
    p_store_id integer, p_object_type integer, p_relation integer, p_prefix_relation boolean
) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_out    text := '';
    g        record;
    v_clause jsonb;
    v_prim   text;
    v_line   text;
BEGIN
    FOR g IN
        SELECT mg.name, mg.spec, rl.name AS relation
          FROM authz.model_gates mg JOIN authz.relations rl ON rl.id = mg.relation
         WHERE mg.store_id = p_store_id AND mg.object_type = p_object_type AND mg.relation = p_relation
         ORDER BY mg.name
    LOOP
        v_out := v_out || '    # gate ' || CASE WHEN p_prefix_relation THEN g.relation || '/' ELSE '' END || g.name
                 || CASE WHEN (g.spec ->> 'mode') IN ('shadow', 'off') THEN ' (' || (g.spec ->> 'mode') || ')' ELSE '' END
                 || COALESCE(': ' || (g.spec ->> 'description'), '') || E'\n';
        FOR v_clause IN SELECT * FROM jsonb_array_elements(g.spec -> 'all_of') LOOP
            SELECT k INTO v_prim FROM jsonb_object_keys(v_clause) k LIMIT 1;
            SELECT string_agg(kv.key || ': ' || kv.value::text, ', '
                              ORDER BY array_position(ARRAY['window','calendar','tz','scope','action','kind','match',
                                                            'recorded_by','key','field','plus','max','min'], kv.key))
              INTO v_line
              FROM jsonb_each(v_clause -> v_prim) kv;
            v_out := v_out || '    #   ' || v_prim || '{' || COALESCE(v_line, '') || '}' || E'\n';
        END LOOP;
    END LOOP;
    RETURN v_out;
END;
$$;

CREATE OR REPLACE FUNCTION authz.describe_model(p_store text)
RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_out      text := 'store: ' || p_store || E'\n';
    v_type     record;
    v_schema   record;
    v_rel      record;
    v_grp      record;
    v_expr     text;
    v_group    text;
    v_base     text;
    v_excl     text;
BEGIN
    -- Conditions are referenced by tuples, not by rules: rendered once, up
    -- front, with their language and clock (migration 0016) so a reviewer sees
    -- which conditions trust the caller's time and which use the server's.
    FOR v_schema IN
        SELECT c.name, c.lang, c.time_source FROM authz.conditions c
         WHERE c.store_id = v_store_id ORDER BY c.name
    LOOP
        v_out := v_out || '# condition ' || v_schema.name || ' (' || v_schema.lang
                 || CASE WHEN v_schema.time_source = 'server' THEN ', server time' ELSE ', caller time' END
                 || ')' || E'\n';
    END LOOP;
    -- Payload schemas are per relation (the action vocabulary), not per type:
    -- rendered once, up front, as comment lines.
    FOR v_schema IN
        SELECT r.name, r.payload_schema FROM authz.relations r
         WHERE r.store_id = v_store_id AND r.payload_schema IS NOT NULL ORDER BY r.name
    LOOP
        v_out := v_out || '# payload schema ' || v_schema.name || ': ' || v_schema.payload_schema::text || E'\n';
    END LOOP;
    FOR v_type IN SELECT id, name FROM authz.types WHERE store_id = v_store_id ORDER BY name
    LOOP
        v_out := v_out || E'\ntype ' || v_type.name || E'\n';
        IF EXISTS (SELECT 1 FROM authz.models m WHERE m.store_id = v_store_id AND m.object_type = v_type.id) THEN
            v_out := v_out || '  relations' || E'\n';
            FOR v_rel IN
                SELECT DISTINCT r.id, r.name
                  FROM authz.models m JOIN authz.relations r ON r.id = m.relation
                 WHERE m.store_id = v_store_id AND m.object_type = v_type.id
                 ORDER BY r.name
            LOOP
                v_expr := NULL;
                FOR v_grp IN
                    SELECT group_id, min(group_op) AS group_op
                      FROM authz.models m
                     WHERE m.store_id = v_store_id AND m.object_type = v_type.id AND m.relation = v_rel.id
                     GROUP BY group_id ORDER BY group_id
                LOOP
                    IF v_grp.group_op = authz._combine_exclusion() THEN
                        SELECT string_agg(authz._describe_atom(v_store_id, v_type.id, v_rel.id, m), ' and ' ORDER BY m.id)
                          INTO v_base FROM authz.models m
                         WHERE m.store_id=v_store_id AND m.object_type=v_type.id AND m.relation=v_rel.id
                           AND m.group_id=v_grp.group_id AND NOT m.negated;
                        SELECT string_agg(authz._describe_atom(v_store_id, v_type.id, v_rel.id, m), ' and ' ORDER BY m.id)
                          INTO v_excl FROM authz.models m
                         WHERE m.store_id=v_store_id AND m.object_type=v_type.id AND m.relation=v_rel.id
                           AND m.group_id=v_grp.group_id AND m.negated;
                        v_group := coalesce(v_base, '?') || ' but not ' || coalesce(v_excl, '?');
                    ELSE
                        SELECT string_agg(authz._describe_atom(v_store_id, v_type.id, v_rel.id, m),
                                          CASE WHEN v_grp.group_op = authz._combine_and() THEN ' and ' ELSE ' or ' END
                                          ORDER BY m.id)
                          INTO v_group FROM authz.models m
                         WHERE m.store_id=v_store_id AND m.object_type=v_type.id AND m.relation=v_rel.id
                           AND m.group_id=v_grp.group_id;
                    END IF;
                    v_expr := CASE WHEN v_expr IS NULL THEN v_group ELSE v_expr || ' or ' || v_group END;
                END LOOP;
                v_out := v_out || '    define ' || v_rel.name || ': ' || v_expr || E'\n'
                         || authz._describe_gates(v_store_id, v_type.id, v_rel.id, false);
                -- Grant rule (migration 0017): who may hand this relation out.
                SELECT '    # grant requires ' || rq.name
                       || CASE WHEN g.requires_revoke IS NOT NULL THEN ' (revoke requires ' || rr.name || ')' ELSE '' END || E'\n'
                  INTO v_group
                  FROM authz.grant_rules g
                  JOIN authz.relations rq ON rq.id = g.requires
             LEFT JOIN authz.relations rr ON rr.id = g.requires_revoke
                 WHERE g.store_id = v_store_id AND g.object_type = v_type.id AND g.relation = v_rel.id;
                IF v_group IS NOT NULL THEN
                    v_out := v_out || v_group;
                END IF;
            END LOOP;
        END IF;
        -- Gates on relations that have no rules on this type (declared-vocabulary
        -- relations) have no define line to hang on: list them with the
        -- relation name so nothing is silently dropped.
        FOR v_rel IN
            SELECT DISTINCT g.relation AS id
              FROM authz.model_gates g
             WHERE g.store_id = v_store_id AND g.object_type = v_type.id
               AND NOT EXISTS (SELECT 1 FROM authz.models m
                                WHERE m.store_id = v_store_id AND m.object_type = v_type.id AND m.relation = g.relation)
             ORDER BY 1
        LOOP
            v_out := v_out || authz._describe_gates(v_store_id, v_type.id, v_rel.id, true);
        END LOOP;
    END LOOP;
    RETURN v_out;
END;
$$;

------------------------------------------------------------------------
-- model_set_payload_schema: declare (or clear, with NULL) the payload shape
-- events for an action must have (ADR 0012, migration 0014). Validated here;
-- enforced by record_event; cross-checked by add_gate. Part of the model:
-- exported, checksummed and propagated by the registry.
--
--   SELECT authz.model_set_payload_schema('bank', 'transfer', '{
--       "required": {"input.amount": "number", "input.currency": "string"},
--       "kinds": {"response": {"required": {"output.status": "string"}}}}');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_set_payload_schema(
    p_store    text,
    p_relation text,
    p_schema   jsonb
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_relation integer := authz._r(v_store_id, p_relation);
    v_schema   jsonb   := authz._event_validate_payload_schema(p_schema);
    v_changed  int;
BEGIN
    UPDATE authz.relations r
       SET payload_schema = v_schema
     WHERE r.id = v_relation AND r.payload_schema IS DISTINCT FROM v_schema;
    GET DIAGNOSTICS v_changed = ROW_COUNT;
    RETURN v_changed > 0;
END;
$$;

-- (create_condition / create_condition_sql / create_condition_cel /
--  delete_condition moved to conditions_admin.sql)
