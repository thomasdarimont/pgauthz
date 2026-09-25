-- 0010_events.sql
--
-- The action log: authz.events (ADR 0012, temporal gates phase 1).
--
-- A store-scoped, append-only record of what a principal ACTUALLY DID, as
-- asserted by a trusted recorder (the application/PEP) through the dedicated
-- record API — independent of any decision pgauthz made. It is neither the
-- decision log (pgauthzd metrics/logs) nor the audit trail (*_audit records
-- graph mutations). Phase 2 evaluates model gates ("at most N transfers per
-- hour", "only if approved within 1h") over this table; phase 1 ships the log
-- and its ingestion contract on their own.
--
-- Integer type/relation ids as in authz.tuples (ADR 0004): subject_type and
-- object_type are authz.types ids, action is an authz.relations id — an action
-- must be declared as a relation of the store before it can be recorded (the
-- model is the action vocabulary; unknown actions fail loud at record time).
-- Types and relations are append-only registries, so events never dangle.
--
-- Monthly RANGE partitions on occurred_at like tuples_audit (retention =
-- partition drop; authz.ensure_event_partitions / drop_event_partitions_before
-- in db/engine/events_admin.sql). The default partition is the fail-safe.
CREATE TABLE authz.events (
    store_id      integer     NOT NULL REFERENCES authz.stores(id),
    -- Insert order within a timestamp; a tiebreaker/cursor component, NOT the
    -- global order (occurred_at is). Assigned at INSERT, not commit — see
    -- the tuples_audit.seq note; list_events pages by (occurred_at, seq).
    seq           bigint      NOT NULL GENERATED ALWAYS AS IDENTITY,
    -- Optional client idempotency key (at-least-once queues, client retries):
    -- unique per store; a duplicate delivery is ON CONFLICT DO NOTHING and
    -- reported, never a second row. The partition key must be part of the
    -- unique index, so the key is only stable together with occurred_at —
    -- record_event therefore requires occurred_at whenever event_id is given
    -- (a re-delivery of one message carries the message's own timestamp).
    event_id      text,
    subject_type  integer     NOT NULL,   -- who acted: a concrete principal, never a userset
    subject_id    text        NOT NULL,
    action        integer     NOT NULL,   -- the relation id (= AuthZEN action.name)
    object_type   integer,                -- what it acted on (NULL: the action has no object)
    object_id     text,
    -- 1=request (about to act), 2=response (completed, outcome in payload.output),
    -- 3=denied (the PEP got/enforced a deny and wants the attempt on record).
    -- Closed set — mirrors authz._event_kind_*(); keep in sync.
    kind          smallint    NOT NULL CHECK (kind IN (1, 2, 3)),
    -- The authz-relevant projection of the action (input.* / output.*), never
    -- the domain object. Bounded by authz.max_context_bytes at record time.
    payload       jsonb       NOT NULL DEFAULT '{}',
    -- When it happened: caller-asserted (async ingestion arrives late), bounded
    -- at record time by authz.event_max_future_skew / event_max_backdate.
    occurred_at   timestamptz NOT NULL,
    -- When we learned it: the database clock, authoritative for audit.
    recorded_at   timestamptz NOT NULL DEFAULT statement_timestamp(),
    -- Who asserted it: the verified subject (pgauthzd) or the effective DB role.
    recorded_by   text        NOT NULL,
    PRIMARY KEY (store_id, occurred_at, seq),
    CHECK (object_id IS NULL OR object_type IS NOT NULL),
    -- Composite FKs as in authz.tuples: same-store references only.
    FOREIGN KEY (subject_type, store_id) REFERENCES authz.types     (id, store_id),
    FOREIGN KEY (object_type,  store_id) REFERENCES authz.types     (id, store_id),
    FOREIGN KEY (action,       store_id) REFERENCES authz.relations (id, store_id)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE authz.events_default PARTITION OF authz.events DEFAULT;

-- The gate primitives' scan (phase 2): "events of this principal for this
-- action in a time window", and the natural list_events subject filter.
CREATE INDEX idx_events_subject_window
    ON authz.events (store_id, subject_type, subject_id, action, occurred_at DESC);

-- Idempotency (partial — most events carry no key).
CREATE UNIQUE INDEX idx_events_idempotency
    ON authz.events (store_id, event_id, occurred_at)
    WHERE event_id IS NOT NULL;
