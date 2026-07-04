-- Model registry: named, versioned model definitions shared across stores.
--
-- Multi-tenant pattern: one store per tenant (tuples isolated by
-- construction), one COMMON model published here and rolled out per store —
-- canary a new version on one tenant store, then apply it to the fleet.
--
--   export_model         — canonical, name-based JSONB snapshot of a store's
--                          live model (types, relations, rules, restrictions,
--                          conditions; NOT tuples / namespace role grants)
--   publish_model        — snapshot a store's model into the registry as the
--                          next version of a named model (immutable versions)
--   apply_model          — make a store's live model match a registry version
--                          (single store or a store list)
--   model_status         — is a store in sync with the version it applied?
--   model_rollout_status — fleet view for one model name
--   list_model_versions  — registry contents
--
-- Depends on: engine/core_internal.sql, engine/model.sql,
--             engine/conditions_admin.sql (create_condition upsert)

------------------------------------------------------------------------
-- _model_hash_modulus: recover the hash sub-partition count of a type's
-- tuple partition from the catalog (it is not stored anywhere). 0 = simple
-- partition. Mirrors _ensure_tuple_partition's naming scheme.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._model_hash_modulus(
    p_store_name text,
    p_type_name  text
) RETURNS integer
LANGUAGE sql STABLE AS $$
    SELECT COALESCE((
        SELECT CASE WHEN c.relkind = 'p'
                    THEN (SELECT count(*)::int FROM pg_catalog.pg_inherits i
                           WHERE i.inhparent = c.oid)
                    ELSE 0 END
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'authz'
           AND c.relispartition
           AND c.relname = 'tuples_'
               || regexp_replace(p_store_name, '[^a-zA-Z0-9]', '_', 'g')
               || '_'
               || regexp_replace(p_type_name, '[^a-zA-Z0-9]', '_', 'g')
    ), 0);
$$;

------------------------------------------------------------------------
-- _model_checksum: sha256 over a definition with physical-layout fields
-- (hash_modulus) stripped — partition layout may legitimately differ per
-- store (a big tenant gets more sub-partitions) and must not read as
-- model drift. jsonb normalizes key order, and export_model emits every
-- array deterministically ordered, so the text rendering is canonical.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._model_checksum(p_def jsonb) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT encode(sha256(convert_to((
        jsonb_set(p_def, '{types}', (
            SELECT COALESCE(jsonb_agg(t - 'hash_modulus' ORDER BY t->>'name'),
                            '[]'::jsonb)
              FROM jsonb_array_elements(COALESCE(p_def->'types', '[]'::jsonb)) t
        ))
    )::text, 'UTF8')), 'hex');
$$;

------------------------------------------------------------------------
-- export_model: canonical, name-based JSONB snapshot of a store's model.
--
-- Everything is keyed by NAME (integer ids differ across stores) and every
-- array is deterministically ordered, so equal models produce byte-equal
-- definitions. Included: types (namespace, description, labels,
-- hash_modulus), relations, rules, type restrictions, conditions.
-- Excluded: tuples (per-tenant data) and namespace_access (DB-role grants
-- are deployment-specific, not part of the model).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.export_model(p_store text) RETURNS jsonb
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
BEGIN
    RETURN jsonb_build_object(
        'format', 1,
        'types', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                       'name',         t.name,
                       'namespace',    t.namespace,
                       'description',  t.description,
                       'labels',       (SELECT COALESCE(jsonb_agg(to_jsonb(l) ORDER BY l), '[]'::jsonb)
                                          FROM unnest(t.labels) AS l),
                       'hash_modulus', authz._model_hash_modulus(p_store, t.name)
                   ) ORDER BY t.name)
              FROM authz.types t
             WHERE t.store_id = v_store_id), '[]'::jsonb),
        'relations', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                       'name',        r.name,
                       'description', r.description
                   ) ORDER BY r.name)
              FROM authz.relations r
             WHERE r.store_id = v_store_id), '[]'::jsonb),
        'rules', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                       'object_type', ot.name,
                       'relation',    rl.name,
                       'rule_type',   CASE m.rule_type
                                          WHEN authz._rel_direct()   THEN 'direct'
                                          WHEN authz._rel_computed() THEN 'computed'
                                          ELSE 'ttu' END,
                       'computed_relation', cr.name,
                       'tupleset_relation', tr.name,
                       'tupleset_computed', tc.name,
                       'group_id',    m.group_id,
                       'group_op',    CASE m.group_op
                                          WHEN authz._combine_and()       THEN 'intersection'
                                          WHEN authz._combine_exclusion() THEN 'exclusion'
                                          ELSE 'or' END,
                       'negated',               m.negated,
                       'allow_object_wildcard', m.allow_object_wildcard
                   ) ORDER BY ot.name, rl.name, m.group_id, m.rule_type,
                              COALESCE(cr.name, ''), COALESCE(tr.name, ''),
                              COALESCE(tc.name, ''), m.negated)
              FROM authz.models m
              JOIN authz.types     ot ON ot.id = m.object_type
              JOIN authz.relations rl ON rl.id = m.relation
              LEFT JOIN authz.relations cr ON cr.id = m.computed_relation
              LEFT JOIN authz.relations tr ON tr.id = m.tupleset_relation
              LEFT JOIN authz.relations tc ON tc.id = m.tupleset_computed
             WHERE m.store_id = v_store_id), '[]'::jsonb),
        'type_restrictions', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                       'object_type',           ot.name,
                       'relation',              rl.name,
                       'allowed_user_type',     ut.name,
                       'allowed_user_relation', ur.name,
                       'allow_wildcard',        x.allow_wildcard
                   ) ORDER BY ot.name, rl.name, ut.name, COALESCE(ur.name, ''), x.allow_wildcard)
              FROM authz.type_restrictions x
              JOIN authz.types     ot ON ot.id = x.object_type
              JOIN authz.relations rl ON rl.id = x.relation
              JOIN authz.types     ut ON ut.id = x.allowed_user_type
              LEFT JOIN authz.relations ur ON ur.id = x.allowed_user_relation
             WHERE x.store_id = v_store_id), '[]'::jsonb),
        'conditions', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                       'name',             c.name,
                       'expression',       c.expression,
                       'lang',             c.lang,
                       'required_context', c.required_context
                   ) ORDER BY c.name)
              FROM authz.conditions c
             WHERE c.store_id = v_store_id), '[]'::jsonb)
    );
END;
$$;

------------------------------------------------------------------------
-- publish_model: snapshot p_from_store's live model into the registry as
-- the next version of p_name. Idempotent: republishing an unchanged model
-- returns the existing latest version instead of minting a new one.
-- Versions are immutable — there is no update path, only the next version.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.publish_model(
    p_name        text,
    p_from_store  text,
    p_description text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_def        jsonb;
    v_sum        text;
    v_latest     integer;
    v_latest_sum text;
BEGIN
    -- Serialize version assignment per model name.
    PERFORM pg_advisory_xact_lock(hashtextextended('authz.model_registry:' || p_name, 0));

    v_def := authz.export_model(p_from_store);
    v_sum := authz._model_checksum(v_def);

    SELECT r.version, r.checksum INTO v_latest, v_latest_sum
      FROM authz.model_registry r
     WHERE r.name = p_name
     ORDER BY r.version DESC
     LIMIT 1;

    IF v_latest_sum = v_sum THEN
        RETURN v_latest;  -- unchanged — no new version
    END IF;

    INSERT INTO authz.model_registry (name, version, definition, checksum, description)
    VALUES (p_name, COALESCE(v_latest, 0) + 1, v_def, v_sum, p_description);

    RETURN COALESCE(v_latest, 0) + 1;
END;
$$;

------------------------------------------------------------------------
-- apply_model: make p_store's live model match registry version
-- p_name/p_version (NULL = latest). Returns the applied version number.
--
-- Sync semantics (all inside one transaction, so a failed apply changes
-- nothing):
--   - types:      added/updated (namespace, description, labels; new types
--                  get their tuple partition with the definition's
--                  hash_modulus). A type present in the store but ABSENT
--                  from the definition is an ERROR — there is no automated
--                  type removal (a type owns a tuple partition; retire it
--                  manually first).
--   - relations:  added/updated; stale relations are removed, but only if
--                  no tuple still references them (tuples have no FK on
--                  relations, so an unguarded delete would silently orphan
--                  tuples — fail instead and let the operator clean up).
--   - rules / type restrictions: exact diff — stale rows removed, missing
--                  rows added (via model_add_rule / model_add_type_restriction,
--                  so validation stays engaged and models_audit records the
--                  change for time-travel).
--   - conditions: upserted (create_condition) / removed (delete_condition —
--                  tuples referencing a removed condition deny, fail closed).
--
-- After syncing, the store's live model is re-exported and its checksum
-- verified against the registry version — apply is self-checking; a
-- mismatch aborts the transaction.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.apply_model(
    p_store   text,
    p_name    text,
    p_version integer DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_version  integer;
    v_sum      text;
    v_def      jsonb;
    v_extra    text;
    v_row      jsonb;
    v_rel      record;
    v_live_sum text;
BEGIN
    SELECT r.version, r.checksum, r.definition INTO v_version, v_sum, v_def
      FROM authz.model_registry r
     WHERE r.name = p_name
       AND (p_version IS NULL OR r.version = p_version)
     ORDER BY r.version DESC
     LIMIT 1;
    IF v_version IS NULL THEN
        RAISE EXCEPTION 'apply_model: no registry entry for model % version %',
            p_name, COALESCE(p_version::text, '(latest)');
    END IF;
    IF (v_def->>'format')::int IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'apply_model: unsupported definition format % (expected 1)',
            v_def->>'format';
    END IF;

    -- Strict: no automated type removal.
    SELECT string_agg(t.name, ', ' ORDER BY t.name) INTO v_extra
      FROM authz.types t
     WHERE t.store_id = v_store_id
       AND t.name NOT IN (SELECT x->>'name' FROM jsonb_array_elements(v_def->'types') x);
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'apply_model: store % has types not in model %/%: % — '
            'type removal is not automated (a type owns a tuple partition); '
            'remove them manually before applying', p_store, p_name, v_version, v_extra;
    END IF;

    -- Types: add new (with partition), update metadata on existing.
    FOR v_row IN SELECT * FROM jsonb_array_elements(v_def->'types')
    LOOP
        IF EXISTS (SELECT 1 FROM authz.types t
                    WHERE t.store_id = v_store_id AND t.name = v_row->>'name') THEN
            UPDATE authz.types t
               SET namespace   = v_row->>'namespace',
                   description = v_row->>'description',
                   labels      = COALESCE(ARRAY(SELECT jsonb_array_elements_text(v_row->'labels')), '{}')
             WHERE t.store_id = v_store_id AND t.name = v_row->>'name';
        ELSE
            PERFORM authz.model_register_type(
                p_store, v_row->>'name',
                COALESCE((v_row->>'hash_modulus')::int, 0),
                v_row->>'namespace', v_row->>'description',
                COALESCE(ARRAY(SELECT jsonb_array_elements_text(v_row->'labels')), '{}'));
        END IF;
    END LOOP;

    -- Relations: upsert (model_register_relation is idempotent).
    FOR v_row IN SELECT * FROM jsonb_array_elements(v_def->'relations')
    LOOP
        PERFORM authz.model_register_relation(p_store, v_row->>'name', v_row->>'description');
        UPDATE authz.relations r
           SET description = v_row->>'description'
         WHERE r.store_id = v_store_id AND r.name = v_row->>'name'
           AND r.description IS DISTINCT FROM (v_row->>'description');
    END LOOP;

    -- Rules: delete stale first (a group whose operator changed must be
    -- emptied before re-adding, or model_add_rule's group-op consistency
    -- check rejects the new rows), then add every desired rule (idempotent;
    -- ON CONFLICT refreshes allow_object_wildcard).
    WITH want AS (
        SELECT authz._t(v_store_id, r->>'object_type') AS object_type,
               authz._r(v_store_id, r->>'relation')    AS relation,
               CASE r->>'rule_type'
                   WHEN 'direct'   THEN authz._rel_direct()
                   WHEN 'computed' THEN authz._rel_computed()
                   WHEN 'ttu'      THEN authz._rel_ttu() END AS rule_type,
               CASE WHEN r->>'computed_relation' IS NULL THEN NULL
                    ELSE authz._r(v_store_id, r->>'computed_relation') END AS computed_relation,
               CASE WHEN r->>'tupleset_relation' IS NULL THEN NULL
                    ELSE authz._r(v_store_id, r->>'tupleset_relation') END AS tupleset_relation,
               CASE WHEN r->>'tupleset_computed' IS NULL THEN NULL
                    ELSE authz._r(v_store_id, r->>'tupleset_computed') END AS tupleset_computed,
               (r->>'group_id')::int AS group_id,
               CASE r->>'group_op'
                   WHEN 'intersection' THEN authz._combine_and()
                   WHEN 'exclusion'    THEN authz._combine_exclusion()
                   ELSE authz._combine_or() END AS group_op,
               (r->>'negated')::boolean AS negated
          FROM jsonb_array_elements(v_def->'rules') r
    )
    DELETE FROM authz.models m
     WHERE m.store_id = v_store_id
       AND NOT EXISTS (
           SELECT 1 FROM want w
            WHERE w.object_type = m.object_type
              AND w.relation    = m.relation
              AND w.rule_type   = m.rule_type
              AND COALESCE(w.computed_relation, -1) = COALESCE(m.computed_relation, -1)
              AND COALESCE(w.tupleset_relation, -1) = COALESCE(m.tupleset_relation, -1)
              AND COALESCE(w.tupleset_computed, -1) = COALESCE(m.tupleset_computed, -1)
              AND w.group_id = m.group_id
              AND w.group_op = m.group_op
              AND w.negated  = m.negated);

    FOR v_row IN SELECT * FROM jsonb_array_elements(v_def->'rules')
    LOOP
        PERFORM authz.model_add_rule(
            p_store, v_row->>'object_type', v_row->>'relation', v_row->>'rule_type',
            v_row->>'computed_relation', v_row->>'tupleset_relation', v_row->>'tupleset_computed',
            (v_row->>'group_id')::int, COALESCE(v_row->>'group_op', 'or'),
            COALESCE((v_row->>'negated')::boolean, false),
            COALESCE((v_row->>'allow_object_wildcard')::boolean, false));
    END LOOP;

    -- Type restrictions: exact diff (delete stale, add all desired).
    WITH want AS (
        SELECT authz._t(v_store_id, r->>'object_type')       AS object_type,
               authz._r(v_store_id, r->>'relation')          AS relation,
               authz._t(v_store_id, r->>'allowed_user_type') AS allowed_user_type,
               CASE WHEN r->>'allowed_user_relation' IS NULL THEN NULL
                    ELSE authz._r(v_store_id, r->>'allowed_user_relation') END AS allowed_user_relation,
               COALESCE((r->>'allow_wildcard')::boolean, false) AS allow_wildcard
          FROM jsonb_array_elements(v_def->'type_restrictions') r
    )
    DELETE FROM authz.type_restrictions x
     WHERE x.store_id = v_store_id
       AND NOT EXISTS (
           SELECT 1 FROM want w
            WHERE w.object_type       = x.object_type
              AND w.relation          = x.relation
              AND w.allowed_user_type = x.allowed_user_type
              AND COALESCE(w.allowed_user_relation, -1) = COALESCE(x.allowed_user_relation, -1)
              AND w.allow_wildcard    = x.allow_wildcard);

    FOR v_row IN SELECT * FROM jsonb_array_elements(v_def->'type_restrictions')
    LOOP
        PERFORM authz.model_add_type_restriction(
            p_store, v_row->>'object_type', v_row->>'relation',
            v_row->>'allowed_user_type', v_row->>'allowed_user_relation',
            COALESCE((v_row->>'allow_wildcard')::boolean, false));
    END LOOP;

    -- Stale relations: removable only when nothing references them anymore.
    -- Rules/restrictions were just synced; tuples have NO FK on relations,
    -- so guard explicitly instead of silently orphaning tuple rows.
    FOR v_rel IN
        SELECT r.id, r.name FROM authz.relations r
         WHERE r.store_id = v_store_id
           AND r.name NOT IN (SELECT x->>'name' FROM jsonb_array_elements(v_def->'relations') x)
    LOOP
        IF EXISTS (SELECT 1 FROM authz.tuples t
                    WHERE t.store_id = v_store_id
                      AND (t.relation = v_rel.id OR t.user_relation = v_rel.id)) THEN
            RAISE EXCEPTION 'apply_model: relation % is not in model %/% but tuples still '
                'reference it in store % — delete those tuples first',
                v_rel.name, p_name, v_version, p_store;
        END IF;
        DELETE FROM authz.relations r WHERE r.id = v_rel.id;
    END LOOP;

    -- Conditions: upsert desired (create_condition validates + audits),
    -- remove stale (fail closed: tuples referencing a removed condition deny).
    FOR v_rel IN
        SELECT c.name FROM authz.conditions c
         WHERE c.store_id = v_store_id
           AND c.name NOT IN (SELECT x->>'name' FROM jsonb_array_elements(v_def->'conditions') x)
    LOOP
        PERFORM authz.delete_condition(p_store, v_rel.name);
    END LOOP;
    FOR v_row IN SELECT * FROM jsonb_array_elements(v_def->'conditions')
    LOOP
        PERFORM authz.create_condition(
            p_store, v_row->>'name', v_row->>'expression',
            v_row->>'lang', v_row->'required_context');
    END LOOP;

    -- Record the applied state.
    INSERT INTO authz.store_model_state (store_id, model_name, model_version, applied_checksum,
                                         applied_at, applied_by)
    VALUES (v_store_id, p_name, v_version, v_sum, now(), current_user)
    ON CONFLICT (store_id) DO UPDATE
        SET model_name       = EXCLUDED.model_name,
            model_version    = EXCLUDED.model_version,
            applied_checksum = EXCLUDED.applied_checksum,
            applied_at       = EXCLUDED.applied_at,
            applied_by       = EXCLUDED.applied_by;

    -- Self-check: the live model must now BE the definition.
    v_live_sum := authz._model_checksum(authz.export_model(p_store));
    IF v_live_sum <> v_sum THEN
        RAISE EXCEPTION 'apply_model: post-apply checksum mismatch for store % '
            '(live %, expected % for %/%) — apply aborted',
            p_store, v_live_sum, v_sum, p_name, v_version;
    END IF;

    RETURN v_version;
END;
$$;

------------------------------------------------------------------------
-- apply_model (fleet variant): apply one registry version to several
-- stores. The version is resolved ONCE up front (latest at call time), so
-- a concurrent publish cannot split the fleet across versions mid-rollout.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.apply_model(
    p_stores  text[],
    p_name    text,
    p_version integer DEFAULT NULL
) RETURNS TABLE (store text, version integer)
LANGUAGE plpgsql AS $$
DECLARE
    v_version integer;
    v_store   text;
BEGIN
    SELECT max(r.version) INTO v_version
      FROM authz.model_registry r
     WHERE r.name = p_name
       AND (p_version IS NULL OR r.version = p_version);
    IF v_version IS NULL THEN
        RAISE EXCEPTION 'apply_model: no registry entry for model % version %',
            p_name, COALESCE(p_version::text, '(latest)');
    END IF;

    FOREACH v_store IN ARRAY p_stores
    LOOP
        store   := v_store;
        version := authz.apply_model(v_store, p_name, v_version);
        RETURN NEXT;
    END LOOP;
END;
$$;

------------------------------------------------------------------------
-- model_status: which registry model+version a store claims, and whether
-- its live model still matches (drift detection). Unmanaged stores (no
-- apply_model yet) return a row with NULL model fields and their live
-- checksum, so tooling can still fingerprint them.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_status(p_store text)
RETURNS TABLE (
    model_name        text,
    model_version     integer,
    applied_at        timestamptz,
    applied_by        text,
    in_sync           boolean,
    live_checksum     text,
    expected_checksum text
)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_live     text    := authz._model_checksum(authz.export_model(p_store));
BEGIN
    RETURN QUERY
    SELECT s.model_name, s.model_version, s.applied_at, s.applied_by,
           (v_live = r.checksum), v_live, r.checksum
      FROM authz.store_model_state s
      JOIN authz.model_registry r
        ON r.name = s.model_name AND r.version = s.model_version
     WHERE s.store_id = v_store_id;

    IF NOT FOUND THEN
        RETURN QUERY SELECT NULL::text, NULL::integer, NULL::timestamptz,
                            NULL::text, NULL::boolean, v_live, NULL::text;
    END IF;
END;
$$;

------------------------------------------------------------------------
-- model_rollout_status: fleet view for one model name — every store bound
-- to it, the version it runs, the registry's latest version, and whether
-- the store is still in sync with what it applied.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_rollout_status(p_name text)
RETURNS TABLE (
    store          text,
    model_version  integer,
    latest_version integer,
    in_sync        boolean,
    applied_at     timestamptz
)
LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN QUERY
    SELECT st.name, s.model_version,
           (SELECT max(r2.version) FROM authz.model_registry r2 WHERE r2.name = p_name),
           authz._model_checksum(authz.export_model(st.name)) = r.checksum,
           s.applied_at
      FROM authz.store_model_state s
      JOIN authz.stores st ON st.id = s.store_id
      JOIN authz.model_registry r
        ON r.name = s.model_name AND r.version = s.model_version
     WHERE s.model_name = p_name
       AND st.deleted_at IS NULL
     ORDER BY st.name;
END;
$$;

------------------------------------------------------------------------
-- list_model_versions: registry contents (all models, or one by name).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.list_model_versions(p_name text DEFAULT NULL)
RETURNS TABLE (
    name        text,
    version     integer,
    checksum    text,
    description text,
    created_at  timestamptz,
    created_by  text
)
LANGUAGE sql STABLE AS $$
    SELECT r.name, r.version, r.checksum, r.description, r.created_at, r.created_by
      FROM authz.model_registry r
     WHERE p_name IS NULL OR r.name = p_name
     ORDER BY r.name, r.version;
$$;
