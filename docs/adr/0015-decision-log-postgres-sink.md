# ADR 0015 — A PostgreSQL sink for the decision log

- **Status:** Accepted (implemented 2026-10-23)
- **Date:** 2026-10-23
- **Deciders:** maintainers
- **Relates to:** [0013](0013-decision-log.md) (the decision log; this ADR
  amends its "no database sink" clause), [0012](0012-action-log.md) (the
  check path stays read-only), `console/README.md` → Decisions tab,
  `docs/PRODUCTION.md` → Decision log

## Context

ADR 0013 gave pgauthzd a decision log — one JSON line per decision — and
sent it to stdout, stderr or a file, "into whatever store the operator
already has". It rejected a decisions table in PostgreSQL for three
reasons: the engine's check path must stay read-only, replicas cannot
write, and a table written on every check would outgrow the audit log.

The management console then needed a **Decisions tab**: which principal
keeps being denied, which reason permits most access, what a specific call
at 14:05 decided and why, with a hand-over into the Test tab to explain the
same question now or replay it at that instant. A tab cannot read a
container's stdout. The gap list (console gaps, item 5) named the
prerequisite plainly: a database sink.

Reading ADR 0013's objections again, they are objections to a table the
**engine** writes on the **check path** into the **engine's** database. None
of them holds for a sink that the **daemon** writes **asynchronously** into
a **separate** database with its own retention:

- the check path still never writes: the line is queued after the answer
  is sent, and inserted by a background flusher in batches;
- replicas are irrelevant: the sink is its own database (in the console
  deployments the console's own `pgauthz_console`), reached by a dedicated
  DSN, never the engine's read-only role;
- growth is bounded by sampling (ADR 0013) and by the sink's retention: daily
  partitions, dropped after `DECISION_LOG_RETENTION_DAYS`.

## Decision

`DECISION_LOG=postgres` is a fourth sink, next to stdout, stderr and file.

**Where the lines go.** `DECISION_LOG_DSN` names the sink database. The
daemon creates (idempotently, every instance at start; the first one wins)
the schema `decisionlog` and the table `decisionlog.decisions`,
range-partitioned by day on `ts`, with a default partition as the safety
net, indexed by `(store, ts)`, `(store, subject)` and `(store, resource)`.
The indexed columns are the line's PARC request, outcome (`decision`,
`state`, `reason`), caller (`actor`, `client`, `issuer`), `listener`,
`endpoint`, `via`, `request_id`, `latency_ms` and `error`; the whole line
is kept in `line jsonb`, so everything ADR 0013 defines (provenance,
hooks, context key names, gate outcomes, the contextual-tuple count) is
there without a schema change per field.

**How the lines get there.** The Logger of ADR 0013 is unchanged: one
`Log` per decision, sampling as before, `pgauthzd_decision_log_lines_total`
as before. Under it the postgres sink is an `io.Writer` with a bounded
queue (`DECISION_LOG_QUEUE`, default 10 000 lines) and a flusher that
inserts a batch (`COPY`) when 500 lines are waiting or every second. A
batch's day gets its partition before the insert. A full queue drops the
line and counts it as a failed write.

**When the database is down.** A failed insert marks the sink down: the
batch is re-queued (what fits), every further write reports the failure —
so `DECISION_LOG_REQUIRED` fails closed exactly as with a file — and tries
a synchronous flush, which is how the Logger's once-per-second probe line
becomes the recovery attempt. "Evidence" with this sink therefore means
*no decision while the sink is down*, not *fsync per line*: a crash loses at
most the queue. Deployments that need per-line durability keep the file
sink.

**Retention is the sink's.** Partitions older than
`DECISION_LOG_RETENTION_DAYS` (default 30; 0 keeps everything) are dropped
once an hour by the daemon — ADR 0013's "retention belongs to the pipeline"
still holds; with this sink the daemon is the pipeline. A late line for a
dropped day lands in the default partition.

**The console reads it.** Store → Decisions (`can_view_decisions`, modelled
since the first console release) lists a store's lines newest first with
filters (subject, resource, action, outcome, window) and keyset paging, a
summary of the window (outcomes; the reasons, actions and subjects behind
the denials; the reasons behind the allows), the full line per row, and
two hand-overs into the Test tab: explain the same question now, and replay
it at the instant it was decided (`audit_check_access`). The console reads
from its own database (`PG_DSN`) and never writes the table; without it the
tab says what to configure. In the shipped compose overlays the decision
instance's `DECISION_LOG_DSN` is the console's database; the Helm chart
takes `decisionLog.dsn`.

## Consequences

- The intent-versus-behaviour loop of ADR 0013 has a UI on the default
  stack, and an operator needs no log pipeline to get one.
- Cost on the decision path: one channel send (the JSON encode was already
  there). The flusher's inserts are off the path. Two extra connections per
  instance to the sink database.
- Operational: the sink DSN's role must be allowed to create the schema
  and tables in its database (the console's `console` role in the
  overlays); `pgauthzd doctor` pings it; `pgauthzd_decision_log_batches_total{result}`
  and `pgauthzd_decision_log_inserted_lines_total` show the flusher.
- Several instances write one table; partition creation races are
  tolerated (duplicate-object errors are ignored).
- Privacy is ADR 0013's: ids yes, context values no. The table lives in the
  console's database, which already holds sessions; protect it alike.

## Alternatives considered

- **The console tails the file/stdout sink.** Rejected: a container's
  stdout is not addressable, a file is one instance's, and neither offers
  the filters the tab needs without re-indexing.
- **A separate collector** (fluent-bit/vector → PostgreSQL). Still possible
  and unchanged for deployments that have one; rejected as the only path
  because the default stack would have no Decisions tab.
- **The engine's database.** Rejected, as in ADR 0013: a different write
  load on the primary and a table replicas would carry for nothing.

## Addendum (2026-10-24): erasure tombstones

A data-subject erasure (PRODUCTION.md → Data subject requests) deletes the
persisted lines about a person, but the sink is asynchronous: a line the
Logger accepted before the erasure may flush afterwards and resurrect the
history. `decisionlog.erasures` (store, subject type, subject id,
`erased_at`, `erased_by`) is written by the erasing side; after every batch
the sink inserts, the same transaction deletes the batch's rows a tombstone
covers — decided at or before `erased_at`, naming the person as subject or
resource. Tombstones are pruned with the retention window. The console's
erasure runs the engine first (authoritative, audited) and the decision log
second; a failure there answers 502 `partial`, and a retry completes it.
