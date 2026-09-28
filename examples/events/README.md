# Action-log ingestion demo (outbox → queue → pgauthz)

The [action log](../../docs/adr/0012-action-log.md) bounds **recorded**
actions: a temporal gate can only be as good as the feed that fills it. A lost
`response` under-counts a `sum_within`; a `response` recorded before the
action completed over-counts. This example is the reference shape for feeding
gate-relevant events reliably:

```
app tx ──▶ business effect + OUTBOX row ──▶ publisher ──▶ queue (Redis Stream)
                                                              │  consumer group, at-least-once
                                                              ▼
                                        consumer.py ──batch──▶ pgauthz  authz.record_events_jsonb
                                             │   ack on success             (or POST /pgauthz/v1/events)
                                             │   4xx / content error ──▶ dead-letter stream (+ reason), then ack
                                             │   5xx / transport ──────▶ retry with backoff, unacked
                                             └── /metrics: consumed, recorded, duplicates, dead-lettered, lag
```

The engine's half of the contract: `event_id` + `occurred_at` make a
re-delivery a **duplicate, never a second row**; a batch is **atomic**;
content errors are **4xx** (undeclared action, bad payload, recorder
allowlist, namespace), everything else 5xx. The consumer's half is above.

## The message contract (broker-neutral)

One JSON object per message, the flat `record_events_jsonb` shape:

| Key | Required | Notes |
|---|---|---|
| `subject_type`, `subject_id` | yes | a concrete principal |
| `action` | yes | a **declared relation** of the store — an unknown action is a content rejection (dead-letter), never a silent drop: publish the model before deploying the recorder |
| `occurred_at` | **yes** | the moment the action completed, set by the producer — never at publish time; with `event_id` it is the idempotency key |
| `event_id` | recommended | the producer's request id + kind (`req-7f3a/response`); the stream message id is the fallback |
| `object_type`, `object_id` | optional | the object acted on |
| `kind` | optional | `request` \| `response` (default) \| `denied` |
| `payload` | optional | the authz-relevant **projection** (`input.*`, `output.*`), not the domain object |

**The outbox rule:** write the event to the outbox **in the same transaction
as the business effect** (a completed transfer, a delivered download) and let
the publisher/consumer be the only thing that talks to pgauthz. Then a lost
event is a stuck outbox row, a late one is visible ingestion lag, and a
malformed one is a dead letter — all three observable, none silent.

## Run it

From the repo root (the `demo` store must exist — `./tests/test.sh` loads it):

```bash
./start.sh && ./init.sh && ./tests/test.sh
dc() { docker compose -f compose.yml -f compose-authzen.yml -f examples/events/compose.yml "$@"; }

dc up -d redis events-consumer
dc logs -f events-consumer
```

In another terminal:

```bash
dc run --rm events-producer --count 20                         # 20 completed downloads by alice
dc run --rm events-producer --count 1 --replay req-1           # publish twice → 1 recorded, 1 duplicate
dc run --rm events-producer --count 1 --replay req-1
dc run --rm events-producer --count 1 --action no_such_action  # content rejection → DLQ
dc exec redis redis-cli XLEN pgauthz.events.dlq
dc exec redis redis-cli XRANGE pgauthz.events.dlq - + COUNT 1  # the message + reason
```

What pgauthz saw (auditor):

```bash
dc exec -T authz-db psql -U authz -d authz -c \
  "SELECT occurred_at, recorded_at - occurred_at AS lag, action, kind, recorded_by
     FROM authz.list_events('demo', p_subject_type => 'internal_user', p_subject_id => 'alice') ORDER BY 1 DESC LIMIT 5;"
```

Consumer metrics at <http://localhost:9110/metrics>:
`pgauthz_events_consumer_{consumed,recorded,duplicates,dead_lettered,retries}_total`,
`_batch_seconds`, `_ingestion_lag_seconds` (now − `occurred_at` at record
time — a stalled publisher shows up here long before a gate misbehaves) and
`_pending` (delivered, unacknowledged). Alert on dead letters > 0 and on the
lag histogram's upper buckets; both mean a gate is counting fewer events than
happened.

## Sinks and trust

`EVENTS_SINK=sql` (default) records through `authz.record_events_jsonb` as
`authz_recorder_svc`, a dedicated login role that inherits **only**
`authz_recorder` (`db/security/roles.sql`): it can record and nothing else —
no reads, no tuple writes. `EVENTS_SINK=http` posts to pgauthzd's
`POST /stores/{store}/pgauthz/v1/events` with `EVENTS_TOKEN`, a JWT carrying
`RECORDER_ROLE` (`scripts/make-token.sh svc internal_user '["authz_recorder"]'`
mints one for the dev stack); `recorded_by` is then the token subject.

Either way the consumer holds a **PEP credential**: recorded events drive
temporal gates, so whoever can publish to the stream can move a gate. Keep
the stream's producers to your enforcement points, narrow the consumer with
`authz.grant_recorder_actions` to the actions it owns, and pin sensitive gate
clauses to `recorded_by` — see the
[ADR 0012 trust model](../../docs/adr/0012-action-log.md#3-trust-model-for-recorded-events).

## Why not record from the check?

Because an "allow" is not an action: the PEP may not act, the action may
fail, the check may be a dry run. The check path never writes (it also runs
on read replicas). Where a cap must hold exactly under concurrency, the PEP
uses `reserve_event` at the moment it acts — that is still the PEP recording,
not the decision.
