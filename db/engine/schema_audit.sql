-- Audit / time-travel schema: the immutable change-log TABLES (structure only).
--
-- Split out of schema.sql so a READ-ONLY deployment (substrate + read API, e.g.
-- an app database fed by replication — see db/replication/) can omit it: the
-- audit log lives centrally, and a read replica needs neither the audit tables
-- nor the write-side triggers. A full deployment loads this right after
-- schema.sql. The audit trigger functions, triggers, and views are idempotent
-- code in audit_triggers.sql (loaded with the audit profile after this file).
--
-- Pure structural DDL: this file is the audit half of the baseline migration
-- (see docs/adr/0001-schema-migrations.md). Keep it free of functions/triggers.

-- Audit log: records all tuple inserts and deletes (populated by a trigger on
-- authz.tuples; see audit_triggers.sql).
-- Partitioned by RANGE on performed_at for efficient time-based queries
-- and easy retention management (DROP old partitions instead of DELETE).
CREATE TABLE authz.tuples_audit (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    -- Monotonic event order. performed_at is the TRANSACTION timestamp
    -- (transaction_timestamp), so every change in one transaction shares
    -- one value — time-travel sees a transaction's effect atomically,
    -- never a partial mid-transaction state. seq then orders the events
    -- within that shared timestamp, so replay always applies the
    -- later-recorded event last (the last-event-wins tiebreaker).
    seq               bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
    action            text NOT NULL,  -- 'INSERT' or 'DELETE'
    performed_at      timestamptz NOT NULL DEFAULT now(),
    performed_by      text NOT NULL DEFAULT current_user,
    store_id          smallint NOT NULL,
    user_type         smallint NOT NULL,
    user_id           text NOT NULL,
    user_relation     smallint,
    relation          smallint NOT NULL,
    object_type       smallint NOT NULL,
    object_id         text NOT NULL,
    condition_id      smallint,
    condition_context jsonb,
    PRIMARY KEY (id, performed_at)
) PARTITION BY RANGE (performed_at);

-- Default partition catches any rows not covered by explicit partitions.
CREATE TABLE authz.tuples_audit_default PARTITION OF authz.tuples_audit DEFAULT;

CREATE INDEX idx_tuples_audit_lookup
    ON authz.tuples_audit (store_id, object_type, object_id, user_type, user_id);

CREATE INDEX idx_tuples_audit_time
    ON authz.tuples_audit (performed_at);

-- Watch / changefeed cursor: (store_id, performed_at, seq) supports the
-- watch_changes scan `WHERE store_id = ? AND (performed_at, seq) > (?, ?)
-- ORDER BY performed_at, seq`, with partition pruning on performed_at.
CREATE INDEX idx_tuples_audit_watch
    ON authz.tuples_audit (store_id, performed_at, seq);

-- Replay index: matches the DISTINCT ON key of _build_audit_snapshot so
-- point-in-time reconstruction scans the events in order instead of
-- sorting the store's full audit history on every call.
CREATE INDEX idx_tuples_audit_replay
    ON authz.tuples_audit (store_id, user_type, user_id, COALESCE(user_relation, 0),
                           relation, object_type, object_id, performed_at DESC, seq DESC);

-- Model change log: versions model rules so time-travel queries
-- (audit_check_access) resolve against the rule set as it was at a past
-- timestamp, not the current model. Mirrors tuples_audit: append-only,
-- one row per rule INSERT/DELETE (an UPDATE is split into DELETE+INSERT),
-- with a seq tiebreaker so replay applies the later event last. The model
-- is tiny and low-churn, so this table is not partitioned.
CREATE TABLE authz.models_audit (
    seq               bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
    action            text NOT NULL,  -- 'INSERT' or 'DELETE'
    performed_at      timestamptz NOT NULL DEFAULT now(),
    performed_by      text NOT NULL DEFAULT current_user,
    model_id          smallint NOT NULL,  -- authz.models.id of the rule
    store_id          smallint NOT NULL,
    object_type       smallint NOT NULL,
    relation          smallint NOT NULL,
    rule_type         smallint NOT NULL,
    computed_relation smallint,
    tupleset_relation smallint,
    tupleset_computed smallint,
    group_id          smallint NOT NULL,
    group_op          smallint NOT NULL,
    negated           boolean  NOT NULL,
    allow_object_wildcard boolean NOT NULL,
    PRIMARY KEY (seq)
);

-- Replay index: matches the DISTINCT ON key of _build_model_snapshot (a
-- rule's business identity = the idx_models_unique columns) plus recency,
-- so point-in-time reconstruction scans in order instead of sorting the
-- store's full model history on every call.
CREATE INDEX idx_models_audit_replay
    ON authz.models_audit (
        store_id, object_type, relation, rule_type,
        COALESCE(computed_relation, -1),
        COALESCE(tupleset_relation, -1),
        COALESCE(tupleset_computed, -1),
        group_id, negated, performed_at DESC, seq DESC
    );

-- Condition change log: versions condition expressions so time-travel
-- queries evaluate conditional grants against the expression that was in
-- effect at a past timestamp, not the current one. Mirrors models_audit:
-- append-only, one row per INSERT/DELETE (an UPDATE is split into
-- DELETE+INSERT), seq tiebreaker. A condition's replay identity is its
-- id — stable across in-place edits, and what tuples reference via
-- condition_id.
CREATE TABLE authz.conditions_audit (
    seq              bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
    action           text NOT NULL,  -- 'INSERT' or 'DELETE'
    performed_at     timestamptz NOT NULL DEFAULT now(),
    performed_by     text NOT NULL DEFAULT current_user,
    condition_id     smallint NOT NULL,  -- authz.conditions.id
    store_id         smallint NOT NULL,
    name             text NOT NULL,
    expression       text NOT NULL,
    lang             text NOT NULL DEFAULT 'sql',  -- no CHECK: history records whatever was in effect
    required_context jsonb,
    PRIMARY KEY (seq)
);

-- Replay index: reconstruct a condition's expression as of a timestamp.
CREATE INDEX idx_conditions_audit_replay
    ON authz.conditions_audit (condition_id, performed_at DESC, seq DESC);
