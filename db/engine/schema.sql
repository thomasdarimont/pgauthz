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

-- (Condition write-time validation trigger moved to conditions_admin.sql,
--  loaded with the write profile.)

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

-- (Model-rule validation: _check_exclusion_group_has_base / _validate_model_group
--  + trigger moved to model_constraints.sql.)

-- Unique constraint on all business columns. Uses COALESCE to handle NULLs
-- (PostgreSQL UNIQUE treats NULLs as distinct, which would allow duplicates).
CREATE UNIQUE INDEX idx_models_unique ON authz.models (
    store_id, object_type, relation, rule_type,
    COALESCE(computed_relation, -1),
    COALESCE(tupleset_relation, -1),
    COALESCE(tupleset_computed, -1),
    group_id, negated
);

-- (models_view moved to views.sql.)

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

-- (type_restrictions_view moved to views.sql.)
