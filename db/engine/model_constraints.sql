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
