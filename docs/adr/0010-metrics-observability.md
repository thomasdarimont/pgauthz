# ADR 0010 — Metrics & observability (Prometheus)

- **Status:** Proposed
- **Date:** 2026-07-06
- **Deciders:** maintainers
- **Relates to:** [0007](0007-pgauthzd-front-door.md) (pgauthzd is the front door — the natural place to emit request/decision metrics), [0009](0009-freshness-tokens.md) (freshness/replica-lag signals)

## Context

pgauthz runs as a multi-tenant (store-per-tenant), replica-scaled authorization
front door. Operators need to answer questions that today require log-diving or
nothing at all:

- Is a specific **replica notoriously lagging** (or did a **failover** happen)?
- Is there an **increase in deny responses** — and are those *real* denials or
  ABAC condition errors/timeouts (which fail closed and masquerade as denies)?
- Is a **tenant/store or client misbehaving** (deny storms, search scraping,
  latency hogging)?
- What **version/profile is deployed**, and since when?
- What is the **latency** of the pgauthzd↔PostgreSQL and pgauthzd↔OPA hops, and
  are we near **pool saturation**?

pgauthzd emits no metrics yet. Grafana is the intended consumption surface, so a
**Prometheus** pull endpoint is the target (OpenTelemetry-compatible naming so an
OTLP bridge stays possible).

## Decision

Expose a Prometheus `/metrics` endpoint from pgauthzd on a **dedicated,
non-public** listener (`METRICS_LISTEN_ADDR`, default empty = off; never on the
client-facing listener — tenants must not scrape ops data). Instrument via one
HTTP middleware (RED) plus targeted counters/gauges at the decision, freshness,
DB, and auth boundaries. All metrics are prefixed `pgauthzd_`.

### Metric catalog

Counters end `_total`, durations are `_seconds` histograms, point-in-time values
are gauges. Naming is OpenTelemetry-friendly.

**HTTP (RED baseline — one middleware, covers most alerts):**

| Metric | Type | Labels |
|---|---|---|
| `pgauthzd_http_requests_total` | counter | `route`, `method`, `status` |
| `pgauthzd_http_request_duration_seconds` | histogram | `route`, `method` |

`route` is the **templated** pattern (`/pgauthz/v1/check`, `/stores/{store}/…`),
never the raw path.

**Authorization decisions:**

| Metric | Type | Labels |
|---|---|---|
| `pgauthzd_check_decisions_total` | counter | `store`, `decision`, `api` |
| `pgauthzd_check_batch_size` | histogram | `api` |

`decision` ∈ `allow \| deny \| conditional \| error`; `api` ∈ `native \|
authzen` — which **client surface** the check came in through. Whether OPA was
consulted is *not* a per-request label: an instance either fronts OPA or doesn't,
so it is constant per process — derive it from `build_info{opa_enabled}` combined
with `api="authzen"` rather than paying for a third value. **No
`type`/`action`/`relation` labels** (see cardinality). Splitting `conditional`
and `error` out from `deny` is deliberate — a rise in `conditional` usually means
clients stopped sending ABAC context; `error` are fail-closed denials.

**Search (graph enumeration):**

| Metric | Type | Labels |
|---|---|---|
| `pgauthzd_search_requests_total` | counter | `store`, `kind`, `result` |
| `pgauthzd_search_result_size` | histogram | `kind` |

`kind` ∈ `objects \| subjects \| actions`. Result-set size surfaces expensive
enumerations / scraping.

**Freshness & consistency (ADR 0009 — the replica-health vein):**

| Metric | Type | Labels | Answers |
|---|---|---|---|
| `pgauthzd_freshness_verdicts_total` | counter | `verdict` | lagging replica (`stale↑`), failover (`wrong_epoch↑`), stream loss (`unknown↑`) |
| `pgauthzd_freshness_fallback_total` | counter | — | primary hops (read-scaling erosion) |
| `pgauthzd_freshness_deficit_bytes` | histogram | — | *how far* behind on a stale read (`token.lsn − replay_lsn`) |
| `pgauthzd_replica_replay_lag_bytes` | gauge | — | sampled `receive_lsn − replay_lsn` |
| `pgauthzd_wal_receiver_up` | gauge | — | `pg_stat_wal_receiver.status = streaming` (0/1) |
| `pgauthzd_freshness_tokens_minted_total` | counter | — | writes opting into read-your-writes |

`verdict` ∈ `fresh \| stale \| wrong_epoch \| unknown`. **Caveat (per ADR 0009):**
`replica_replay_lag_bytes` reads ~0 for a *disconnected* standby, so always pair
it with `wal_receiver_up` to catch a stalled stream.

**Database & connection pools:**

| Metric | Type | Labels |
|---|---|---|
| `pgauthzd_db_query_duration_seconds` | histogram | `op`, `pool` |
| `pgauthzd_db_errors_total` | counter | `op`, `pool` |
| `pgauthzd_db_pool_connections` | gauge | `pool`, `state` |
| `pgauthzd_db_pool_acquire_wait_seconds` | histogram | `pool` |

`op` ∈ `check \| list \| explain \| write \| freshness`; `pool` ∈ `primary \|
replica \| fallback` (target-descriptive — an instance has `primary` **or**
`replica`[+`fallback`], never colliding within one process); `state` ∈ `acquired
\| idle \| total \| max`. Labelling query duration by `pool` quantifies the
fallback penalty (the extra primary hop) vs local replica reads and ties to the
`X-PGAuthz-Served-By` header. The small `fallback` pool is the first thing a
fallback storm exhausts — watch its `acquire_wait` p99.

**OPA (only when fronting):**

| Metric | Type | Labels |
|---|---|---|
| `pgauthzd_opa_request_duration_seconds` | histogram | — |
| `pgauthzd_opa_requests_total` | counter | `result` |

**Auth & security signals:**

| Metric | Type | Labels |
|---|---|---|
| `pgauthzd_jwt_validation_failures_total` | counter | `reason` |
| `pgauthzd_authz_denied_total` | counter | `reason` |
| `pgauthzd_requests_by_issuer_total` | counter | `issuer` |
| `pgauthzd_condition_eval_total` | counter | `result` |

`reason` (JWT) ∈ `bad_signature \| expired \| unknown_issuer \| audience \|
missing`; `reason` (authz) ∈ `writer_role \| search_role \| store_binding \|
db_role_binding \| forbidden_role`; `condition result` ∈ `allow \| deny \| error
\| timeout`. Spikes in JWT failures flag key-rotation/attacks; `authz_denied` by
reason flags privilege probing / cross-tenant attempts.

**Build & runtime info:**

| Metric | Type | Labels |
|---|---|---|
| `pgauthzd_build_info` | gauge=1 | `version`, `commit`, `go_version`, `profile`, `opa_enabled`, `freshness_enabled`, `fallback_enabled` |

Plus the standard Go/process collectors (`process_start_time_seconds` covers
"when did this deploy start").

**Engine / tenant (optional, Slice 3 — cardinality-sensitive):**
`pgauthzd_store_tuples{store}`, `pgauthzd_store_model_version{store,version}`,
`pgauthzd_expired_tuples_backlog{store}`, watch changefeed lag. Sample
periodically, not per-request.

### Cardinality policy (the load-bearing constraint)

Prometheus series = product of label values; getting this wrong takes out the
TSDB.

- **Never** label with model-defined `type` / `relation` / `action` — they are
  arbitrary, effectively unbounded. Type/action breakdowns belong in the audit
  log (which already has them), not live counters.
- `store` is allowed but can be high-cardinality with many tenants — **bucket the
  long tail into `store="other"`** above a configured top-N (or an allowlist).
- `issuer` is config-bounded → safe.
- Per-**instance** identity (which reader/replica) comes from Prometheus target
  relabeling (`instance`), not an app label — that's what makes "which replica
  lags" answerable.

### Exposition & security

- `promhttp` handler on `METRICS_LISTEN_ADDR` (e.g. `:9090`), a **separate**
  listener from the public client one. Bind to the pod/mesh network; scrape via a
  ServiceMonitor/PodMonitor. Default empty = disabled (opt-in).

## Consequences

Operators get RED dashboards, replica-lag/failover detection, tenant/client
misbehavior signals, and deploy visibility with a bounded, Grafana-native metric
set. The freshness verdict/fallback counters make ADR 0009's replica-health
observable for free. Cost: instrumentation touches the HTTP middleware, the
decision/search/freshness/auth boundaries, and adds a metrics listener; the
cardinality rules must be enforced in code (fixed label sets, `store` bucketing),
not left to callers.

### Analysis question → metric

| Question | Signal |
|---|---|
| Lagging replica? | `freshness_verdicts_total{verdict="stale"}` rate + `replica_replay_lag_bytes` (per instance) |
| Failover happened? | `freshness_verdicts_total{verdict="wrong_epoch"}` spike across readers |
| Read-scaling eroding? | `freshness_fallback_total` rate |
| Deny spike real or ABAC breakage? | `check_decisions_total{decision="deny"}` vs `condition_eval_total{result=~"error\|timeout"}` |
| Misbehaving tenant/client? | per-`store` decisions + `search_result_size` + `authz_denied_total` + `requests_by_issuer_total` |
| Near saturation? | `db_pool_acquire_wait_seconds` p99, `db_pool_connections{state="acquired"}` vs `max` |
| DB / OPA latency? | `db_query_duration_seconds`, `opa_request_duration_seconds` |
| What's deployed, since when? | `build_info`, `process_start_time_seconds` |
| Key rotation / attack? | `jwt_validation_failures_total{reason}` |

## Alternatives considered

- **OpenTelemetry / OTLP push** — heavier to operate; deferred. Metric names here
  are OTel-friendly so an OTLP exporter can be added later without renaming.
- **Metrics on the public listener** — rejected: tenants must not scrape ops data.
- **Type/action-labelled decision counters** — rejected on cardinality; use the
  audit log for that breakdown.

## Implementation slices

1. **Slice 1 (highest value / lowest effort):** HTTP RED middleware +
   `freshness_verdicts/fallback` + `build_info` + `db_pool_connections`. Answers
   lagging-replica, failover, error/deny-rate, saturation, what's-deployed.
2. **Slice 2:** per-store decisions + search, `jwt_validation_failures`,
   `authz_denied`, `condition_eval`, DB/OPA latency histograms.
3. **Slice 3:** engine/tenant gauges (tuple counts, model version, expiry
   backlog) — periodic sampling, with the `store` bucketing rule.
