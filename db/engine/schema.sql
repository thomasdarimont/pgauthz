-- Optimized authorization schema.
-- Key optimizations:
--   1. Integer IDs for type/relation names (smaller rows, faster comparisons)
--   2. Partitioned tuples table by object_type (partition pruning)
--   3. Covering partial indexes tuned to check_access query patterns
--   4. Contextual tuples + conditions for ABAC / time-based authorization
--   5. Multi-store support for parallel models

DROP SCHEMA IF EXISTS authz CASCADE;
CREATE SCHEMA authz;

-- Restricted role for evaluating condition expressions.
-- Has zero table/function access — can only evaluate pure SQL expressions
-- (operators, casts) with parameterized context values.
-- Prevents malicious expressions from reading/modifying data.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_eval') THEN
        CREATE ROLE authz_eval NOLOGIN;
    END IF;
END
$$;
GRANT authz_eval TO authz;

-- Stores: independent authorization namespaces.
-- Each store has its own model rules, tuples, and conditions.
CREATE TABLE authz.stores (
    id          smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name        text UNIQUE NOT NULL,
    description text
);

-- Lookup tables: type and relation names -> smallint IDs.
-- Scoped per store — each store has its own independent set of types/relations.
-- IDs are globally unique (IDENTITY) so they can be used in the partitioned
-- tuples table without ambiguity.
CREATE TABLE authz.types (
    id          smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    store_id    smallint NOT NULL REFERENCES authz.stores(id),
    name        text NOT NULL,
    namespace   text,              -- NULL = unrestricted, any writer can manage tuples
    description text,
    UNIQUE (store_id, name),
    UNIQUE (id, store_id)          -- composite FK target: same-store references only
);

-- Namespace-based access control.
-- Maps a namespace to a PostgreSQL role with read/write permissions for
-- object types in that namespace. When a type has a non-NULL namespace,
-- only DB users who are members of a granted role (with the appropriate
-- permission) can read or write tuples for it.
-- Types with namespace = NULL remain unrestricted (backward compatible).
CREATE TABLE authz.namespace_access (
    store_id    smallint NOT NULL REFERENCES authz.stores(id),
    namespace   text NOT NULL,
    db_role     text NOT NULL,
    can_read    boolean NOT NULL DEFAULT false,
    can_write   boolean NOT NULL DEFAULT false,
    PRIMARY KEY (store_id, namespace, db_role)
);

CREATE TABLE authz.relations (
    id          smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    store_id    smallint NOT NULL REFERENCES authz.stores(id),
    name        text NOT NULL,
    description text,
    UNIQUE (store_id, name),
    UNIQUE (id, store_id)          -- composite FK target: same-store references only
);

-- Conditions: named expressions evaluated at check time.
-- Scoped per store. `lang` tags the expression language; the executor is
-- dispatched in authz._eval_condition_expr:
--   'sql' — built-in, dependency-free, runs in the zero-privilege authz_eval
--           sandbox. The default; needs nothing extra.
--   'cel' — Common Expression Language, evaluated by an OPTIONAL extension
--           (the cel_eval_bool / cel_compile_check function contract, e.g. the
--           Rust/pgrx extensions/pg-cel). lang='cel' rows can only be written
--           when that evaluator is installed (enforced at write time); without
--           it the engine is unaffected and 'sql' keeps working.
-- Further languages (cedar, rego, …) plug in the same way: widen this CHECK
-- and add a branch in authz._eval_condition_expr.
--
-- For lang = 'sql' the expression is a SQL boolean expression that can reference:
--   $1 = request-time context (passed by caller)
--   $2 = tuple-stored context (from condition_context JSONB)
-- For lang = 'cel' the expression is a CEL boolean expression over two
--   variables: request.* (request-time context) and stored.* (tuple context).
CREATE TABLE authz.conditions (
    id               smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    store_id         smallint NOT NULL REFERENCES authz.stores(id),
    name             text NOT NULL,
    expression       text NOT NULL,
    -- Allowed values mirror authz._cond_lang_sql() / authz._cond_lang_cel()
    -- (literals here because the CHECK/DEFAULT resolve before those helpers
    -- load; keep the two in sync).
    lang             text NOT NULL DEFAULT 'sql' CHECK (lang IN ('sql', 'cel')),
    required_context jsonb,
    UNIQUE (store_id, name)
);

-- Reject a condition whose expression cannot compile. A malformed or
-- unresolvable expression (SQLSTATE class 42 — syntax error, unknown
-- function/column/table, type mismatch, or an attempt to touch a table
-- the sandbox can't see) would otherwise insert successfully and then
-- silently fail closed (deny) at every check. We test-compile it once at
-- write time in the same sandbox used at check time: _exec_condition runs
-- as the zero-privilege authz_eval role, so validating an untrusted
-- expression cannot itself do harm. Empty context is passed, so only
-- compile-time errors are caught; data-dependent runtime errors (class 22,
-- e.g. a cast that fails only on certain inputs) are legitimate and remain
-- deny-at-check, not write-time rejections.
--
-- SECURITY DEFINER so the trigger (whoever runs the INSERT) can reach
-- _exec_condition; the expression still executes only as authz_eval.
CREATE OR REPLACE FUNCTION authz._validate_condition_expression() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    -- Validation is language-specific (SQL test-compiles by executing; CEL
    -- parse/type-checks via the evaluator). Dispatch on NEW.lang; the CHECK
    -- constraint restricts lang to the known set, so the ELSE is defensive.
    CASE NEW.lang
        WHEN authz._cond_lang_sql() THEN
            BEGIN
                PERFORM authz._exec_condition(NEW.expression, '{}'::jsonb, '{}'::jsonb);
            EXCEPTION
                WHEN syntax_error_or_access_rule_violation THEN  -- SQLSTATE class 42
                    RAISE EXCEPTION 'condition "%" has an invalid expression: %', NEW.name, SQLERRM
                        USING ERRCODE = 'invalid_parameter_value',
                              HINT = 'Expression must be a valid SQL boolean over $1 (request) and $2 (stored) context.';
            END;
        WHEN authz._cond_lang_cel() THEN
            -- CEL needs the optional evaluator extension (cel_eval_bool /
            -- cel_compile_check contract, e.g. extensions/pg-cel). Refuse to
            -- store a lang='cel' condition that could never be evaluated:
            -- gate on the contract function existing (works for any provider).
            IF to_regprocedure('authz.cel_compile_check(text)') IS NULL THEN
                RAISE EXCEPTION 'condition "%" uses lang=cel but no CEL evaluator is installed', NEW.name
                    USING ERRCODE = 'feature_not_supported',
                          HINT = 'Install a CEL evaluator extension (e.g. pg_cel from extensions/pg-cel) to enable CEL conditions.';
            END IF;
            -- Compile-check the expression up front; the evaluator raises on a
            -- malformed expression, mirroring the 'sql' write-time guard. This
            -- is a PARSE check only — undeclared variables, type mismatches, and
            -- bad value formats (e.g. a Postgres interval where CEL duration()
            -- wants "2h") are not caught here; they surface at evaluation and
            -- deny. Use authz.validate_condition to exercise them with sample
            -- context.
            BEGIN
                PERFORM authz.cel_compile_check(NEW.expression);
            EXCEPTION
                WHEN OTHERS THEN
                    RAISE EXCEPTION 'condition "%" has an invalid CEL expression: %', NEW.name, SQLERRM
                        USING ERRCODE = 'invalid_parameter_value',
                              HINT = 'Expression must be a valid CEL boolean over request.* and stored.*';
            END;
        ELSE
            RAISE EXCEPTION 'condition "%" uses unsupported language "%"', NEW.name, NEW.lang
                USING ERRCODE = 'feature_not_supported',
                      HINT = 'Supported condition languages: sql, cel.';
    END CASE;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_conditions_validate_expression
    BEFORE INSERT OR UPDATE ON authz.conditions
    FOR EACH ROW EXECUTE FUNCTION authz._validate_condition_expression();

-- Internal composite type for identifying a specific direct tuple.
-- Used by find_redundant_tuples to exclude a tuple from access checks
-- without requiring write access (replica-safe).
CREATE TYPE authz._tuple_key AS (
    user_type   smallint,
    user_id     text,
    relation    smallint,
    object_type smallint,
    object_id   text
);

-- Composite type for batch access checks.
-- Used by check_access_batch to evaluate multiple access checks in one call.
CREATE TYPE authz.access_check AS (
    user_type     text,
    user_id       text,
    relation      text,
    object_type   text,
    object_id     text
);

-- Result type for batch access checks.
-- Extends access_check with the decision boolean.
CREATE TYPE authz.access_check_result AS (
    user_type     text,
    user_id       text,
    relation      text,
    object_type   text,
    object_id     text,
    decision      boolean
);

-- Composite type for contextual tuples passed at check time.
CREATE TYPE authz.tuple_input AS (
    user_type     text,
    user_id       text,
    user_relation text,
    relation      text,
    object_type   text,
    object_id     text
);

-- Relationship tuples: the core data store.
-- Partitioned by object_type for partition pruning on every check_access call.
CREATE TABLE authz.tuples (
    store_id          smallint NOT NULL,
    user_type         smallint NOT NULL,
    user_id           text NOT NULL,
    user_relation     smallint,          -- NULL for direct users, set for usersets
    relation          smallint NOT NULL,
    object_type       smallint NOT NULL,
    object_id         text NOT NULL,
    condition_id      smallint,          -- NULL = unconditional, references authz.conditions
    condition_context jsonb,             -- stored context for condition evaluation (e.g. grant_time, grant_duration)
    created_at        timestamptz NOT NULL DEFAULT now()
) PARTITION BY LIST (object_type);

-- Default partition catches any type not explicitly partitioned.
CREATE TABLE authz.tuples_default PARTITION OF authz.tuples DEFAULT;

-- Unique constraint (must include partition key).
CREATE UNIQUE INDEX idx_tuples_unique
    ON authz.tuples (store_id, object_type, object_id, relation, user_type, user_id, COALESCE(user_relation::int, 0));

-- Pattern 1: direct tuple lookup — the hot path of check_access.
-- "Is there a tuple (user -> relation -> object) with no userset?"
CREATE INDEX idx_tuples_direct
    ON authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    WHERE user_relation IS NULL;

-- Pattern 2: userset expansion.
-- "Which usersets grant <relation> on <object>?"
-- INCLUDE avoids heap lookup — index-only scan.
CREATE INDEX idx_tuples_userset
    ON authz.tuples (store_id, object_type, object_id, relation)
    INCLUDE (user_type, user_id, user_relation)
    WHERE user_relation IS NOT NULL;

-- Pattern 3: reverse lookup — used by list_objects and write validation.
CREATE INDEX idx_tuples_user
    ON authz.tuples (store_id, user_type, user_id)
    INCLUDE (relation, object_type, object_id);

-- Model resolution rules with integer IDs. Scoped per store.
--
-- Rules for the same relation are organized into groups (group_id).
-- Within a group, rules are combined using the group operator (group_op):
--   0 = OR  (default) — any rule match grants access
--   1 = AND           — all rules must match (intersection)
--   2 = BUT NOT       — base rules must match AND negated rules must NOT (exclusion)
-- Groups themselves are OR'd: if any group grants access, the check passes.
CREATE TABLE authz.models (
    id                 smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    store_id           smallint NOT NULL REFERENCES authz.stores(id),
    object_type        smallint NOT NULL,
    relation           smallint NOT NULL,
    rule_type          smallint NOT NULL,  -- 1=direct, 2=computed, 3=tuple_to_userset
    computed_relation  smallint,
    tupleset_relation  smallint,
    tupleset_computed  smallint,
    group_id           smallint NOT NULL DEFAULT 0,
    group_op           smallint NOT NULL DEFAULT 0,  -- 0=or, 1=intersection, 2=exclusion
    negated            boolean  NOT NULL DEFAULT false,
    -- Privileged grants: when true, this DIRECT rule's relation may
    -- carry object-wildcard tuples (object_id = '*': the subject holds
    -- the relation on EVERY object of the type). Default-deny — see
    -- write_tuple gating.
    allow_object_wildcard boolean NOT NULL DEFAULT false,
    -- Composite FKs: every referenced type/relation must exist AND
    -- belong to the same store as the rule. NULL columns skip the
    -- check (MATCH SIMPLE), so optional references stay optional.
    FOREIGN KEY (object_type,       store_id) REFERENCES authz.types     (id, store_id),
    FOREIGN KEY (relation,          store_id) REFERENCES authz.relations (id, store_id),
    FOREIGN KEY (computed_relation, store_id) REFERENCES authz.relations (id, store_id),
    FOREIGN KEY (tupleset_relation, store_id) REFERENCES authz.relations (id, store_id),
    FOREIGN KEY (tupleset_computed, store_id) REFERENCES authz.relations (id, store_id)
);

CREATE INDEX idx_models_lookup
    ON authz.models (store_id, object_type, relation);

-- Validation: exclusion groups must keep at least one base (non-negated)
-- rule. A negated-only group has no base requirement and would grant
-- access to everyone who is not excluded (fail-open). Negated rules are
-- only meaningful in exclusion groups.
-- AFTER ROW triggers fire once the full statement has completed, so a
-- single INSERT adding base and negated rules together passes; adding
-- rules one by one requires the base rule first.
CREATE OR REPLACE FUNCTION authz._check_exclusion_group_has_base(
    p_store_id    smallint,
    p_object_type smallint,
    p_relation    smallint,
    p_group_id    smallint
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

CREATE TRIGGER trg_models_validate_group
    AFTER INSERT OR UPDATE OR DELETE ON authz.models
    FOR EACH ROW EXECUTE FUNCTION authz._validate_model_group();

-- Unique constraint on all business columns. Uses COALESCE to handle NULLs
-- (PostgreSQL UNIQUE treats NULLs as distinct, which would allow duplicates).
CREATE UNIQUE INDEX idx_models_unique ON authz.models (
    store_id, object_type, relation, rule_type,
    COALESCE(computed_relation, -1),
    COALESCE(tupleset_relation, -1),
    COALESCE(tupleset_computed, -1),
    group_id, negated
);

-- Human-readable view of model rules (resolves integer IDs to names).
CREATE VIEW authz.models_view AS
SELECT
    mr.id,
    s.name  AS store,
    t.name  AS object_type,
    r.name  AS relation,
    CASE mr.rule_type
        WHEN 1 THEN 'direct'
        WHEN 2 THEN 'computed'
        WHEN 3 THEN 'ttu'
    END AS rule_type,
    cr.name AS computed_relation,
    tr.name AS tupleset_relation,
    tc.name AS tupleset_computed,
    mr.group_id,
    CASE mr.group_op
        WHEN 0 THEN 'or'
        WHEN 1 THEN 'intersection'
        WHEN 2 THEN 'exclusion'
    END AS group_op,
    mr.negated,
    mr.allow_object_wildcard
  FROM authz.models mr
  JOIN authz.stores s    ON s.id  = mr.store_id
  JOIN authz.types t     ON t.id  = mr.object_type
  JOIN authz.relations r ON r.id  = mr.relation
  LEFT JOIN authz.relations cr ON cr.id = mr.computed_relation
  LEFT JOIN authz.relations tr ON tr.id = mr.tupleset_relation
  LEFT JOIN authz.relations tc ON tc.id = mr.tupleset_computed;

-- Type restrictions: constrain which subject types can be directly assigned
-- to a relation. If no restrictions are defined for a (store, object_type, relation),
-- any type is allowed (backward compatible). Only applies to direct rules.
CREATE TABLE authz.type_restrictions (
    id                    smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    store_id              smallint NOT NULL REFERENCES authz.stores(id),
    object_type           smallint NOT NULL,
    relation              smallint NOT NULL,
    allowed_user_type     smallint NOT NULL,
    allowed_user_relation smallint,          -- NULL = direct user, non-NULL = userset
    allow_wildcard        boolean NOT NULL DEFAULT false,
    -- Composite FKs: same-store references only (see authz.models).
    FOREIGN KEY (object_type,           store_id) REFERENCES authz.types     (id, store_id),
    FOREIGN KEY (relation,              store_id) REFERENCES authz.relations (id, store_id),
    FOREIGN KEY (allowed_user_type,     store_id) REFERENCES authz.types     (id, store_id),
    FOREIGN KEY (allowed_user_relation, store_id) REFERENCES authz.relations (id, store_id)
);

-- Expression-based unique constraint (COALESCE needed to handle NULL user_relation).
-- Must be a CREATE UNIQUE INDEX, not an inline UNIQUE constraint.
CREATE UNIQUE INDEX idx_type_restrictions_unique
    ON authz.type_restrictions (store_id, object_type, relation, allowed_user_type,
                                COALESCE(allowed_user_relation, -1), allow_wildcard);

CREATE INDEX idx_type_restrictions_lookup
    ON authz.type_restrictions (store_id, object_type, relation);

-- Human-readable view of type restrictions (resolves integer IDs to names).
CREATE VIEW authz.type_restrictions_view AS
SELECT
    tr.id,
    s.name  AS store,
    ot.name AS object_type,
    r.name  AS relation,
    aut.name AS allowed_user_type,
    aur.name AS allowed_user_relation,
    tr.allow_wildcard
  FROM authz.type_restrictions tr
  JOIN authz.stores s     ON s.id  = tr.store_id
  JOIN authz.types ot     ON ot.id = tr.object_type
  JOIN authz.relations r  ON r.id  = tr.relation
  JOIN authz.types aut    ON aut.id = tr.allowed_user_type
  LEFT JOIN authz.relations aur ON aur.id = tr.allowed_user_relation;
