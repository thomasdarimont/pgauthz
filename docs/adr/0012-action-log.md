# ADR 0012 — The action log: history-dependent authorization over recorded actions

- **Status:** Accepted (phases 1–3 shipped)
- **Date:** 2026-09-25
- **Deciders:** maintainers
- **Relates to:** [0004](0004-integer-type-relation-ids.md) (integer ids),
  [0006](0006-models-as-data.md) (models as data), [0011](0011-opa-policy-hooks.md)
  (why this does not live in OPA hooks), `docs/SECURITY-AUDIT.md` F5 / F11 / F16

## Context

Every time notion in the engine is point-in-time: tuple expiry, a caller's
`request.current_time`, a hook's `input.evaluated_at`, time-travel replaying
the *graph*. What the engine cannot answer is **"may X do Y, given what X has
already done?"** — rate limits and quotas per principal and action, prior
approval, step-up freshness, lockout after repeated denials, agent
guardrails ("an agent may write a file only if it read it in this session").
Today's stand-in is the `under_quota` condition pattern where the caller passes
`request.usage_count` — the same trust hole as `current_time`: the PEP asserts
a counter on every check and the engine has no facts of its own.

Two gaps block a real answer: there is **no action log** (`*_audit` records
grant/revoke, pgauthzd's decision logs are not actions), and conditions cannot
read tables by design (`_exec_condition` runs as the zero-grant `authz_eval`).
The altitude is also wrong: tuple conditions are per-relationship ABAC, while
"at most 5 transfers per hour" is a per-principal/action behavioural gate that
belongs **next to the check**.

AWS Dogwood's `when temporal { … }` clause (MFOTL over an agent's tool-call
trace: `formerly within`, `count_within`, `count_distinct_within`,
`sum_within`) is the reference for the primitive set.

## Decision

Three parts, shipped in phases. **Phase 1 (this ADR's shipped scope)** is the
log and its ingestion contract; it has standalone value as a per-store,
per-principal action trail queryable next to the graph.

### 1. An action log, fed by the PEP — never by the check path

`authz.events` (migration 0010) is a store-scoped, append-only record of what
a principal **actually did**, asserted by a trusted recorder through a
dedicated write API — `authz.record_event` / `record_events_jsonb` (SQL, new
`authz_recorder` role) and `POST /pgauthz/v1/events` (pgauthzd `full` profile,
`RECORDER_ROLE` claim gate). A message-queue consumer is a reference example,
not a daemon feature.

**The check path never writes.** A PDP "allow" is not an action: the PEP may
ignore the decision, the action may fail, the check may be a dry run.
Recording inside `check_access` would count things that never happened and put
a write on the hot read path (replicas, memoization, `decision-only`
instances). The v1 design's `check_and_record` was rejected for this reason;
a PEP that needs a hard, concurrency-safe bound opts into an explicit
`reserve_event` write (phase 3) *because* it is about to act.

Consequently the engine bounds **recorded** actions. Two concurrent checks can
both see `count = 4`; an action that was allowed but never recorded is
invisible. That is the correct default — the PDP answers "given what I know
happened, may this happen?", and the PEP owns the truth about what happened.
Feeding the log reliably (idempotency keys, dead-lettering unknown actions)
is an application responsibility a PEP takes on when it adopts gates.

### 2. The model is the action vocabulary

Events carry **integer ids** like tuples (ADR 0004): `subject_type` /
`object_type` are `authz.types` ids, `action` is an `authz.relations` id. An
action must therefore be **declared as a relation** of the store before it can
be recorded — a typo fails loud at record time (FK → 400) instead of silently
creating an event stream no gate ever reads; gates, `describe_model` and the
registry validate `action` references against the model; the registry already
snapshots relations, so publishing a model propagates the vocabulary. Types
and relations are append-only registries, so events never dangle. The one
operational rule: an ingestion consumer must dead-letter unknown actions,
never drop them — a new action goes live by publishing the model first.

### 3. Trust model for recorded events

- **The recorder is trusted for its assertion**, exactly as a tuple writer is
  trusted for its tuples; a compromised recorder can fabricate an approval and
  (in phase 2) pass a gate — the same blast radius as fabricating an
  `approver` tuple. Mitigations: `recorded_by` is server-attributed and
  immutable (the F16 rules: the JWT subject is authoritative on the public
  listener, the trusted upstream's assertion is required on the callback
  listener); a gate spec may pin `recorded_by` to an allowlist; recording
  *about* an object type in a namespace requires the same `can_write`
  namespace grant tuple writes need, so per-app isolation extends to the log;
  and a **per-recorder action allowlist** (`authz.recorder_actions`,
  migration 0013, `grant_recorder_actions` / `revoke_recorder_actions`)
  narrows a role to the actions it may record — the namespace precedent:
  unrestricted until a list exists for a role the caller is a member of,
  then only the listed actions. Enforced in `record_event`, so
  `reserve_event` and the HTTP endpoints inherit it; deployment-specific,
  so excluded from `export_model`. A per-store "allowlists required" switch
  (deny-by-default for unlisted roles) is a possible tightening, not built.
- **`authz_recorder` is a security-sensitive PEP role — an operational
  contract, not a code boundary.** Events are what a recorder *claims*
  happened, and gates deny or allow on them. Whoever can record can therefore
  move a gate: satisfy a prior-approval clause with a fabricated approval,
  lock a principal out by recording denials, or exhaust a quota. The role
  belongs to enforcement points and ingestion services only — **never** to
  end-user-facing clients, browser or mobile apps, or any token an end user
  can obtain; the same rule as for `authz_writer` (which inherits it) and
  `authz_contextual_reader`. On the HTTP surface that means the
  `RECORDER_ROLE` claim is issued to service identities, not user tokens.
  Narrow further with per-recorder action allowlists (a service may record
  only the actions it owns), `recorded_by` pins in gate specs, and per-app
  roles. A compromised recorder has the blast radius of a compromised
  writer: contain it the same way (rotate its credential, purge its events
  with `purge_events` if they are known to be false, review `list_events`
  filtered by `recorded_by`).
- **Timestamps are bounded, not blindly trusted.** `occurred_at` is
  caller-asserted (asynchronous ingestion arrives late; the recorder already
  vouches *that* it happened, so trusting *when* adds no new trust) but
  rejected beyond `authz.event_max_future_skew` (default 5 s) ahead of or
  `authz.event_max_backdate` (default 24 h) behind the database clock, and
  defaults to it. `recorded_at` is the database clock, authoritative for
  audit. Windows (phase 2) evaluate over `occurred_at` on the database clock.
  This is a different boundary from F11: F11 was an unprivileged caller
  forging a GUC to bypass RLS; here a privileged recorder asserts a bounded
  fact it is already trusted for.
- **Idempotency.** `event_id` is a client key, unique per store; a
  re-delivery is reported as a duplicate, never inserted. Because a unique
  index on a partitioned table must include the partition key, the key is
  stable only together with `occurred_at` — so `event_id` **requires**
  `occurred_at` (the message's own timestamp); a retry that let it default to
  the server clock would count twice, and the engine refuses that loudly.
- **Bounded input.** Payloads are objects capped by `authz.max_context_bytes`
  (F5); a batch is atomic (one bad element records nothing, like
  `write_tuples_jsonb`); the HTTP body cap applies.
- **Append-only.** No role holds `UPDATE`/`DELETE`; a block-DML trigger
  (audit profile) is the defense in depth, honouring the same
  `authz.audit_maintenance` window the audit tables use for the partition row
  move and `delete_store` erasure. Retention is a partition drop.

### 4. Gates (phase 2) and the strict tier (phase 3) — both shipped

Gates are declarative `all_of` clauses over four fixed window primitives
(`formerly_within`, `count_within`, `count_distinct_within`, `sum_within`),
attached to an `(object_type, relation)` in a new relational table
`authz.model_gates` with a jsonb spec, evaluated by **engine code as
`authz_owner`** after the graph allows — outside the `authz_eval` sandbox (no
new grants to it) and outside OPA hooks (ADR 0011 forbids `http.send` in store
hooks, and hooks cannot write). They apply to every public entry point through
one `_decide` wrapper above the memoized graph walk, to enumeration
(`list_*` — otherwise listings would be graph-derived supersets, the problem
ADR 0011 solved), to explain (counts and thresholds only, never matched
payloads), to `check_access_detailed` (missing `$request.*` keys ⇒
`conditional`), to time-travel (a `model_gates_audit` following the
conditions precedent; events need no snapshot — the as-of filter is
`occurred_at <= p_at AND recorded_at <= p_at`), and to the model registry
(`export_model` gains `gates`; the checksum drops the key when empty so
gate-free stores do not drift). The spec grammar and failure semantics are
documented in `docs/MODEL_DESIGN.md` §17; the `_decide` seam is enforced by
a lint step in `tests/test.sh`. Phase 3, `reserve_event`, is the explicit
strict tier: under an advisory lock per `(store, subject)` — the unit every
gate counts — it takes the **full** decision (graph and gates, not gates
alone: a reserve replaces the check the PEP would otherwise make) and records
the `request` event in the same transaction; a refusal records a `denied`
event (the reserve is the attempt) unless the PEP opts out. Two consequences
were forced by the parallel-session tests: the gate evaluation clock and
recorded timestamps are `clock_timestamp()` (a statement's start time
predates the lock wait, so a `STABLE`/statement-time evaluation could not see
the previous holder's event — the strict tier over-admitted), and the count
primitives take an explicit `plus` like `sum_within` so a cap can include
the request being decided.

**Rollout without risk:** a gate spec may carry `"mode": "shadow"` — evaluated
identically, reported (explain step with `shadow: true`, detailed, reserve
outcomes, a structured `RAISE LOG` line — replica-safe, the check path still
never writes) but never denying — and the `authz.gates_mode` GUC shadows or
switches off every gate at once. Move a gate from shadow to enforce by
editing the spec; the change is versioned and propagates through the registry.

**What belongs in a gate:** a *permission* question ("may X do Y now?") that a
security or compliance owner wants to define, version, audit and enforce
centrally — separation of duties, prior approval, step-up freshness, lockout,
quotas, exfiltration brakes, agent guardrails. **What does not:** anything that
decides an *outcome* (which account to debit, whether to retry, the next
workflow state) or needs richer signals than "what did this principal do"
(fraud scoring). Gates are veto-only and non-programmable by construction;
the PEP records a minimal payload projection, not its domain object; every
rule has one owner (a gate replaces an application check or is documented as
a backstop).

### 5. Positioning

Temporal gates are **centrally managed, history-dependent veto rules over
trusted recorded actions**. They are ideal for quotas, freshness, prior
approval, lockout, separation of duties and agent guardrails. They are **not a
workflow engine** and **not a substitute for reliable PEP event recording**.
Dogwood-inspired, not Dogwood-compatible: four fixed primitives, `all_of`,
veto-only — no `since`/`until`, no nested quantifiers, no policy code.
The bounded subset is the point: it fits the authorization-engine mental model
(`graph allows AND conditions allow AND gates over recorded actions allow`)
and stays explainable, enumerable and time-travelable, which arbitrary
temporal policy code would not.

## Consequences

- **New surface (phase 3):** SQL `reserve_event` (recorder role);
  pgauthzd `POST /pgauthz/v1/events/reserve`; `_trace_begin` / `_trace_end`
  factored out of `explain_access`; the `_event_*` evaluation path is
  `VOLATILE` and clocked by `clock_timestamp()`.
- **New surface (phase 2):** tables `authz.model_gates` +
  `model_gates_audit` (migration 0011); SQL `add_gate` / `drop_gate`
  (admin), the internal `_decide` / `_decide_snapshot` seam,
  `_event_check_gates` and the `_event_*` window primitives; `export_model`
  `gates` key; `explain_access` `temporal_gate` steps and the `gate_denied`
  reason. No pgauthzd change: gates are inside the check.
- **New surface (phase 1):** table `authz.events`; SQL `record_event`,
  `record_events_jsonb`, `list_events`, `ensure_event_partitions`,
  `drop_event_partitions_before`; role `authz_recorder` (granted to
  `authz_writer`); pgauthzd `POST /pgauthz/v1/events` + `RECORDER_ROLE`;
  GUCs `authz.event_max_future_skew`, `authz.event_max_backdate`; metric
  `pgauthzd_events_recorded_total`. Engine files `events.sql` (read) and
  `events_admin.sql` (write) in the manifest; the audit partition worker is
  generalized into `_ensure_month_partition` / `_drop_month_partitions_before`
  shared by both logs.
- **Operations:** schedule `ensure_event_partitions()` next to
  `ensure_audit_partitions()`; retention via `drop_event_partitions_before`
  (fleet-wide, partition drop) and `purge_events(store, before)` (per store,
  row delete) — both **refuse a cutoff inside a live gate window** unless
  forced, since a dropped month or purged range can only *relax* a cap
  (`gate_windows` / `max_gate_window` expose the requirement); set
  `authz.event_max_backdate` to the queue's worst-case lag; `delete_store`
  purges the store's events.
- **Replication:** events replicate like everything else; a read-only install
  can list them (auditor) and, in phase 2, evaluate gates, but cannot record.
  A `decision-only` instance reading a replica sees counts lagged by
  replication — the same stale-allow class as ADR 0009 covers; recording with
  `consistency: applied` removes the recorder's own read-after-write gap.
- **Not a decision log, not the audit trail.** pgauthzd never auto-records
  decisions or denials; a PEP that wants denials on record sends
  `kind: denied`. AuthZEN 1.0 has no "report an action" verb; the native
  endpoint is the contract.
- **Payload projection is model-declared (migration 0014):**
  `authz.relations.payload_schema` — required/optional dotted paths with
  JSON types, per-kind additions, optionally closed — enforced by
  `record_event`, cross-checked by `add_gate` (a clause may only read declared
  paths; `sum_within` fields must be numbers), exported and propagated by the
  registry (emitted only when set). Relations without a schema behave as
  before.

## Alternatives considered

- **Record inside the check** (v1's `check_and_record`): rejected — counts
  non-actions, writes on the read path (see §1).
- **Pilot in OPA hooks via the native callback:** rejected — ADR 0011 forbids
  `http.send` in store hooks and strips `time.now_ns`; hooks cannot write.
- **Window helpers granted to `authz_eval`** ("one audited hole"): rejected —
  `authz_eval` has no `USAGE` on schema `authz`, and widening it is not the
  same shape as the `_rls_*` bypass helpers.
- **Free-form action strings:** rejected in favour of declared relations (§2).
- **Server clock only for `occurred_at`:** rejected — asynchronous ingestion
  arrives late; bounded caller time is the honest model (§3).
- **A `lang='dogwood'` condition language:** out of scope — Dogwood policies
  are principal/action/resource + trace and do not decompose into per-tuple
  predicates.

## Non-goals

Liveness ("must eventually approve"), full MFOTL (`since`/`until`, nested
quantifiers), obligations/advice, and replacing infrastructure request
rate-limiting: infrastructure bounds *requests*; gates (phase 2) bound
*authorized actions per principal* — a policy concern.
