# ADR 0013 — The decision log: what pgauthzd decided, and why

- **Status:** Accepted
- **Date:** 2026-09-28
- **Deciders:** maintainers
- **Relates to:** [0010](0010-metrics-observability.md) (metrics — counts,
  not records), [0012](0012-action-log.md) (the action log — what principals
  *did*, not what was decided), [0007](0007-pgauthzd-front-door.md) (pgauthzd
  is the edge), `docs/AGENTIC-AUTHORIZATION.md` §8

## Context

pgauthz keeps two records and no third. The **audit trail** records how the
graph changed (every grant and revoke, replayable with `audit_check_access`).
The **action log** records what principals actually did, reported by the PEP
(ADR 0012). Neither records a **decision**: which request was evaluated, what
the answer was, and why. Metrics (ADR 0010) count decisions by store and
outcome but keep no record of any single one.

That gap matters as soon as someone asks a question about behaviour rather
than state: *which rule permits most access to customer documents in
practice? which principal keeps being denied, and on what? did a policy
change in June widen access before anyone noticed? why was this specific
call at 14:05 denied?* The literature calls this the loop between design-time
intent and runtime behaviour — policies express intent, decision logs show
what the policies actually do, governance compares the two. It is also the
evidence an incident review needs: the request, the answer, the reason, the
policy version in effect.

Two things in the engine's design shape where such a record can live:

- **The check path never writes** (ADR 0012, decided edge case): a decision
  is not an action, and a table written on every check would double the
  cost of the hottest path and grow faster than the audit partitions.
- **The edge is pgauthzd** (ADR 0007): every external decision passes
  through the daemon, which already knows the caller (verified token
  subject, issuer, roles), the request id, the latency, and — with the
  detailed check — the decision's `state` and `reason`.

OPA, when it fronts pgauthzd, has its own decision log; the default stack is
OPA-free and has nothing.

## Decision

pgauthzd emits a **decision log**: one JSON line per decision, opt-in,
written by the daemon, never by the engine.

**Where it is emitted.** On every endpoint that produces a decision:
AuthZEN `evaluation` and `evaluations` (one line per evaluation), native
`check` and `check-batch` (one line per check), `explain`, and
`events/reserve`. Searches are not decisions and are not logged (they are
counted). Both listeners emit, labelled `listener: public|callback`, so a
decision that OPA fetched through the callback appears once, at the edge
that answered it; an OPA-fronted AuthZEN decision is labelled `via: opa`.

**What a line carries.** Stable, additive, one object per line:

| Field | Content |
|---|---|
| `ts`, `request_id`, `latency_ms` | when, which request, how long the decision took |
| `listener`, `endpoint`, `via` | `public`/`callback`; `evaluation`, `evaluations`, `check`, `check-batch`, `explain`, `reserve`; `engine`/`opa` |
| `store`, `subject`, `action`, `resource` | the PARC request as resolved (subject after the override policy) |
| `decision`, `state`, `reason` | the boolean; `allow`/`deny`/`conditional`; the engine's reason (`direct_tuple`, `gate_denied`, `intersection_unsatisfied`, …) when known |
| `missing_context`, `conditions` | for `conditional` decisions: the keys a condition or gate needed, the conditions involved |
| `gates` | for `reserve`: per-clause outcomes (gate, clause, passed) |
| `context_keys` | the **names** of the request-context keys supplied — never their values |
| `actor`, `issuer` | the authenticated caller (token subject as `type:id`, issuer) — who asked, distinct from `subject` when a PEP checks on behalf of someone |
| `error` | set when the backend failed; `decision` is then absent |

Values that could identify data beyond the authorization graph are not
logged: request-context **values** (a clearance level, an IP, a device id),
contextual tuples, event payloads, tokens. Only key names. This is the same
redaction stance as `explain_access(p_redact)`.

**Where it goes.** `DECISION_LOG=off|stdout|stderr|file:<path>` (default
`off`). Stdout/stderr are for container log pipelines; a file is opened
append-only so external rotation with copy-truncate works and the daemon
never rotates itself. There is no database sink, by design (see Context).

**How much.** `DECISION_LOG_SAMPLE` (0–1, default 1) samples **allows**;
denies, conditionals and errors are always logged — they are the rare and
interesting lines, and a sampled deny would be a missing incident record.
`DECISION_LOG_DETAIL=true` upgrades plain checks (no `X-PGAuthz-Detail`, no
`detail: true`) to the detailed evaluation *for logging only* — the caller's
response is unchanged — so every logged line carries `state` and `reason`.
The cost is the detailed check's second pass on conditional decisions;
batches stay boolean.

**How it relates to the other records.** A line names the moment and the
store; `audit_check_access(store, …, p_at => ts)` re-decides it with the
tuples, model and gates in effect then — the log is the index, time travel
is the replay. The metric `pgauthzd_check_decisions_total` and the log agree
on `state` by construction (same value, same place). `pgauthzd_decision_log_lines_total{result}`
counts logged, sampled-out and failed writes so a silent sink is visible.

## Consequences

- The intent-vs-behaviour loop becomes possible on the default stack:
  aggregate the lines by `reason` and `action`, cluster denials by subject,
  diff before and after a model publish, replay any line.
- Cost: one JSON encode and one buffered write per decision when enabled;
  with `DECISION_LOG_DETAIL` the detailed check's extra evaluation on
  conditional outcomes. Off by default, so the hot path is unchanged unless
  asked.
- Privacy: subject and resource ids are logged (they are the authorization
  graph's own identifiers, as in the audit trail); context values are not.
  Operators who consider ids sensitive route the log like the audit trail.
- Retention, shipping and rotation belong to the log pipeline, not the
  daemon.
- Not (yet) in the line: the model version in effect. The registry knows it
  per store, but reading it per decision is a round trip; a follow-up can
  cache `model_status` per store and stamp it.

## Alternatives considered

- **A decisions table in PostgreSQL.** Rejected: the check path stays
  read-only (ADR 0012), replicas could not write it, and it would outgrow
  the audit log by orders of magnitude. Ship the lines into whatever store
  the operator already has.
- **OPA decision logs only.** Rejected: OPA is opt-in; most deployments have
  no OPA, and the OPA log records OPA's view (policy input/result), not the
  engine's reason.
- **Metrics with more labels.** Rejected: subject and resource ids are
  unbounded cardinality; metrics answer "how many", not "which".
- **Log everything at debug level.** Rejected: a decision record is a
  contract (stable fields, redaction rules, sampling), not a debug print.

## Non-goals

- Logging search results (which objects a caller enumerated) — counted, not
  recorded; enumeration is already role-gated.
- Recording decisions as events in the action log — a decision is not an
  action (ADR 0012).
- Guaranteed delivery — a dropped line increments a counter; the log is
  evidence, not a ledger.
