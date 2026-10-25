-- Model-rule integrity: the write-time validation trigger on authz.models.
--
-- Idempotent code (CREATE OR REPLACE, incl. the trigger — PostgreSQL 14+) so it
-- re-applies on every deploy. Kept in the substrate profile because it is tied
-- to the authz.models table structure and is harmless on a read-only replica
-- (it only fires on local model writes; logical-replication apply does not fire
-- it). Moved out of schema.sql so that file is pure structural DDL.
--
-- Depends on: schema.sql (authz.models).

-- Validation: exclusion groups must keep at least one base (non-negated)
-- rule. A negated-only group has no base requirement and would grant
-- access to everyone who is not excluded (fail-open). Negated rules are
-- only meaningful in exclusion groups.
-- AFTER ROW triggers fire once the full statement has completed, so a
-- single INSERT adding base and negated rules together passes; adding
-- rules one by one requires the base rule first.
CREATE OR REPLACE FUNCTION authz._check_exclusion_group_has_base(
    p_store_id    integer,
    p_object_type integer,
    p_relation    integer,
    p_group_id    integer
) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM authz.models m
         WHERE m.store_id    = p_store_id
           AND m.object_type = p_object_type
           AND m.relation    = p_relation
           AND m.group_id    = p_group_id
           AND m.negated
    ) AND NOT EXISTS (
        SELECT 1 FROM authz.models m
         WHERE m.store_id    = p_store_id
           AND m.object_type = p_object_type
           AND m.relation    = p_relation
           AND m.group_id    = p_group_id
           AND NOT m.negated
    ) THEN
        RAISE EXCEPTION 'exclusion group % has no base (non-negated) rule — a negated-only group would grant access to everyone not excluded',
            p_group_id;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION authz._validate_model_group() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('INSERT', 'UPDATE') AND NEW.negated
       AND NEW.group_op <> 2 THEN  -- 2 = exclusion (authz._combine_exclusion)
        RAISE EXCEPTION 'negated rules are only allowed in exclusion groups';
    END IF;

    IF TG_OP IN ('INSERT', 'UPDATE') AND NEW.allow_object_wildcard
       AND NEW.rule_type <> 1 THEN  -- 1 = direct (authz._rel_direct)
        RAISE EXCEPTION 'allow_object_wildcard is only allowed on direct rules';
    END IF;

    -- Check the affected group(s): NEW's group, and on UPDATE/DELETE also
    -- OLD's group (an update may move the last base rule elsewhere).
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        PERFORM authz._check_exclusion_group_has_base(
            NEW.store_id, NEW.object_type, NEW.relation, NEW.group_id);
    END IF;
    IF TG_OP = 'DELETE'
       OR (TG_OP = 'UPDATE' AND (OLD.store_id, OLD.object_type, OLD.relation, OLD.group_id)
           IS DISTINCT FROM (NEW.store_id, NEW.object_type, NEW.relation, NEW.group_id)) THEN
        PERFORM authz._check_exclusion_group_has_base(
            OLD.store_id, OLD.object_type, OLD.relation, OLD.group_id);
    END IF;

    RETURN NULL;
END;
$$;

CREATE OR REPLACE TRIGGER trg_models_validate_group
    AFTER INSERT OR UPDATE OR DELETE ON authz.models
    FOR EACH ROW EXECUTE FUNCTION authz._validate_model_group();

------------------------------------------------------------------------
-- Tuple guard (migration 0019): a tuple can only name an assignable
-- relation. A permission (relations.metadata.kind = 'permission') is derived
-- by computed / ttu rules and is never granted directly — the chokepoint for
-- write_tuple(s), write_tuples_checked, grant and the RLS bypass helpers alike.
------------------------------------------------------------------------
-- SECURITY DEFINER like the gate validator: the rule lookup must work for
-- whoever runs the INSERT.
CREATE OR REPLACE FUNCTION authz._tuple_relation_kind_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_name text;
BEGIN
    -- A permission may be granted directly when its model says so (a direct
    -- rule on this object type: `run: [agent]`); without one a tuple could
    -- never be matched, so it is refused with the relation it should go on.
    SELECT r.name INTO v_name
      FROM authz.relations r
     WHERE r.store_id = NEW.store_id AND r.id = NEW.relation
       AND r.metadata->>'kind' = 'permission'
       AND NOT EXISTS (SELECT 1 FROM authz.models m
                        WHERE m.store_id = NEW.store_id AND m.object_type = NEW.object_type
                          AND m.relation = NEW.relation AND m.rule_type = authz._rel_direct());
    IF v_name IS NOT NULL THEN
        RAISE EXCEPTION 'relation % is a permission without a direct rule on this type: it is derived, not granted by a tuple', v_name
            USING HINT = 'Grant the relation the permission is derived from, or add a direct rule if it should be grantable.';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_tuples_relation_kind
    BEFORE INSERT OR UPDATE OF relation ON authz.tuples
    FOR EACH ROW EXECUTE FUNCTION authz._tuple_relation_kind_guard();

------------------------------------------------------------------------
-- Relation cap (migration 0025): a relation declared with max_direct on
-- the object type takes at most that many live direct tuples per object.
-- Enforced here, on the row, so every write path — write_tuple, the batch
-- writers, write_tuples_checked, grant / apply_grants and the RLS bypass
-- helpers — refuses the (N+1)th assignment with ONE error: SQLSTATE 'ZA001'
-- (an implementation-defined class; pgauthzd maps it to 409 relation_full),
-- the DETAIL carrying the cap and the count.
--
-- Concurrency: the count runs under the per-object advisory lock the checked
-- paths already take (same key: store name, type name, object id), so two
-- writers racing past the cap serialize and the second counts the first —
-- exact under READ COMMITTED (the count is a fresh snapshot taken after the
-- wait; a REPEATABLE READ transaction would count on its older snapshot).
-- The batch writers pre-take the locks of every capped object in a stable
-- order (_lock_capped_objects), so two batches cannot deadlock here.
--
-- Counted: live rows (RLS hides expired ones; the filter says so) on this
-- object and relation, EXCLUDING the subject being written — an identical
-- re-grant (upsert) or the reactivation of an expired row does not consume
-- a slot. A userset subject (team:x#member) is one assignment. Wildcards are
-- refused: user:* makes the holder set unbounded, object_id '*' would put a
-- holder on every object of the type. A row-level BEFORE trigger sees the
-- rows a multi-row INSERT already processed, so a batch that overshoots the
-- cap fails on the first row over it.
------------------------------------------------------------------------
-- The constraint lookup must work for whoever runs the INSERT: SECURITY
-- DEFINER (owned by authz_owner, roles.sql).
CREATE OR REPLACE FUNCTION authz._tuple_relation_cap_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_max    integer;
    v_count  integer;
    v_store  text;
    v_type   text;
    v_rel    text;
BEGIN
    SELECT c.max_direct INTO v_max
      FROM authz.relation_constraints c
     WHERE c.store_id = NEW.store_id AND c.object_type = NEW.object_type
       AND c.relation = NEW.relation AND c.max_direct IS NOT NULL;
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;
    SELECT s.name, t.name, r.name INTO v_store, v_type, v_rel
      FROM authz.stores s, authz.types t, authz.relations r
     WHERE s.id = NEW.store_id AND t.id = NEW.object_type AND r.id = NEW.relation;
    IF NEW.user_id = '*' OR NEW.object_id = '*' THEN
        RAISE EXCEPTION 'relation % on % is capped (max_direct %): a wildcard tuple is unbounded and cannot be written',
            v_rel, v_type, v_max
            USING ERRCODE = 'check_violation',
                  HINT = 'Drop the constraint (model_drop_relation_constraint) to allow wildcard grants on this relation.';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(v_store || ':' || v_type || ':' || NEW.object_id, 0));
    SELECT count(*) INTO v_count
      FROM (SELECT 1
              FROM authz.tuples t
             WHERE t.store_id = NEW.store_id AND t.object_type = NEW.object_type
               AND t.object_id = NEW.object_id AND t.relation = NEW.relation
               AND (t.expires_at IS NULL OR t.expires_at > statement_timestamp())
               AND NOT (t.user_type = NEW.user_type AND t.user_id = NEW.user_id
                        AND COALESCE(t.user_relation, 0) = COALESCE(NEW.user_relation, 0))
             LIMIT v_max) x;
    IF v_count >= v_max THEN
        RAISE EXCEPTION 'relation % on %:% is full: % of % active direct assignments (max_direct)',
            v_rel, v_type, NEW.object_id, v_count, v_max
            USING ERRCODE = 'ZA001',
                  DETAIL = format('{"code": "relation_full", "object_type": %s, "object_id": %s, "relation": %s, "max_direct": %s, "direct_count": %s}',
                                  to_json(v_type), to_json(NEW.object_id), to_json(v_rel), v_max, v_count),
                  HINT = 'Revoke an assignment first, or raise max_direct in the model (model_set_relation_constraint).';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_tuples_relation_cap
    BEFORE INSERT ON authz.tuples
    FOR EACH ROW EXECUTE FUNCTION authz._tuple_relation_cap_guard();

-- _lock_capped_objects: the batch writers' deadlock avoidance — take the
-- per-object advisory lock of every object in the batch whose relation is
-- capped, in a stable order, BEFORE the insert (the trigger re-takes a held
-- lock for free). p_objects: a JSON array of {object_type, object_id,
-- relation} by name; objects of uncapped relations are skipped.
CREATE OR REPLACE FUNCTION authz._lock_capped_objects(p_store text, p_store_id integer, p_objects jsonb)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_obj record;
BEGIN
    FOR v_obj IN
        SELECT DISTINCT e->>'object_type' AS ot, e->>'object_id' AS oid
          FROM jsonb_array_elements(p_objects) e
          JOIN authz.types     t ON t.store_id = p_store_id AND t.name = e->>'object_type'
          JOIN authz.relations r ON r.store_id = p_store_id AND r.name = e->>'relation'
          JOIN authz.relation_constraints c
            ON c.store_id = p_store_id AND c.object_type = t.id AND c.relation = r.id AND c.max_direct IS NOT NULL
         ORDER BY 1, 2
    LOOP
        PERFORM pg_advisory_xact_lock(hashtextextended(p_store || ':' || v_obj.ot || ':' || v_obj.oid, 0));
    END LOOP;
END;
$$;
