# Comparison with OpenFGA

Feature-by-feature comparison with [OpenFGA](https://openfga.dev/), the
reference implementation of the model this engine speaks. The model surface
is at parity (an OpenFGA model imports as-is); the differences are in where
the engine runs (inside your PostgreSQL vs a separate service), what that
makes possible (filtering as a JOIN, time travel, temporal gates) and what
it costs (no gRPC, no hosted offering). The 2026 OpenFGA release line was
reviewed for behaviours worth adopting; the outcomes are recorded in the
[CHANGELOG](../CHANGELOG.md) (search for "OpenFGA").

## Contents

- [Authorization model — full parity](#authorization-model--full-parity)
- [This solution has, OpenFGA doesn't](#this-solution-has-openfga-doesnt)
- [OpenFGA has, this solution doesn't](#openfga-has-this-solution-doesnt)
- [When to choose this solution over OpenFGA](#when-to-choose-this-solution-over-openfga)
- [When to choose OpenFGA](#when-to-choose-openfga)

## Authorization model — full parity

| Capability | OpenFGA | This solution |
|---|---|---|
| Direct relations (`this`) | ✅ | ✅ |
| Computed relations (`computedUserset`) | ✅ | ✅ |
| Tuple-to-userset (`tupleToUserset`) | ✅ | ✅ |
| Union (OR) | ✅ | ✅ |
| Intersection (AND) | ✅ | ✅ |
| Exclusion / Difference (BUT NOT) | ✅ | ✅ * |
| Wildcard tuples (`user:*`) | ✅ | ✅ |
| Conditions (ABAC) | ✅ | ✅ |
| Contextual tuples | ✅ | ✅ |
| List objects (resource search) | ✅ | ✅ |
| List users (subject search) | ✅ | ✅ |
| Multiple stores | ✅ | ✅ |
| Type restrictions on writes | ✅ | ✅ |
| Idempotent writes/deletes | ✅ opt-in (`on_duplicate` / `on_missing: ignore`) | ✅ default ** |

\* Exclusion semantics differ in one detail: in OpenFGA, the base of a
`difference` is typically a union; here, multiple base rules in one
exclusion group are **AND-ed**. To express `(viewer OR editor) BUT NOT
blocked`, use one exclusion group per base alternative (groups are OR'd).
Exclusion groups must contain at least one base rule — negated-only
groups are rejected at write time. See
[MODEL_DESIGN.md](MODEL_DESIGN.md#exclusion-but-not) for details.

\** Duplicate writes and deletes of non-existent tuples never fail here —
no flag needed. Unlike OpenFGA's ignore mode, the outcome stays
observable: `write_tuple`/`delete_tuple` return whether anything changed,
and the batch functions return effective counts. One deliberate
difference: re-writing an existing tuple with a **different condition**
is not ignored as a duplicate — the new condition is applied (and
audited), so a grant never silently stays more or less permissive than
the caller requested.

## This solution has, OpenFGA doesn't

| Capability | Notes |
|---|---|
| **Full audit trail** | Immutable, monthly-partitioned log with `performed_by` tracking |
| **Time-travel queries** | `audit_check_access` reconstructs the tuple state, **model rules, condition expressions, and gate definitions** at any past timestamp (all four versioned via `*_audit` logs) |
| **Action log + temporal gates** | History-dependent rules *in the model*: rate limits, spend caps, prior approval, step-up freshness, lockouts, separation of duties, agent guardrails — evaluated on every check, listing, explain and time-travel path over the actions your PEP records; `reserve_event` for concurrency-exact caps. OpenFGA and SpiceDB answer only point-in-time questions — see [Temporal Gates](MODEL_DESIGN.md#17-temporal-gates-history-dependent-rules) |
| **`list_actions`** | "What can user X do on object Z?" — OpenFGA has no equivalent |
| **`explain_access`** | Structured decision explanation: resolution tree, a typed `reason` per step, a minimal `decision.reason`, and a redacted safety mode |
| **Namespace write control** | Restrict which applications can write tuples for which object types |
| **Condition validation** | Dry-run conditions before writing tuples |
| **Batch operations** | `write_tuples` / `delete_tuples` in a single statement |
| **No external service** | Pure SQL — no network hop, no separate process to operate |
| **OpenFGA import** | Import existing OpenFGA JSON models directly. `intersection` and `difference` are translated natively into rule groups; operators nested deeper than one level below `union` are rejected (never imported as a more permissive approximation) — see [MODEL_DESIGN.md](MODEL_DESIGN.md#example-how-intersectionexclusion-map-to-rule-groups) |
| **Object wildcards** | `(subject, relation, type, '*')` grants the relation on every object of the type — O(1) super-admin/auditor checks and listing. Default-deny: the direct rule must be marked `allow_object_wildcard`. OpenFGA wildcards are subject-side only |

## OpenFGA has, this solution doesn't

| Capability | Impact | Notes |
|---|---|---|
| **Watch API** | Low | OpenFGA can stream tuple changes. This solution provides `authz.watch_changes` (a cursored, lag-gated changefeed over the audit log) plus a `NOTIFY authz_changes` doorbell; a WebSocket/SSE transport bridge is left to the deployment. |
| **gRPC API** | Low | OpenFGA has native gRPC. This solution uses SQL directly or pgauthzd's HTTP API for HTTP access. |
| **SDK ecosystem** | Medium | OpenFGA has official SDKs for Go, JS, Python, Java, .NET. This solution requires direct SQL or HTTP calls via pgauthzd's HTTP API — simpler for teams already on PostgreSQL, but lacks the plug-and-play SDK experience. |
| **Modular models** | Low | OpenFGA 1.2 supports splitting models into modules. Less relevant here since the model is SQL rows that can be organized however you like. |

## When to choose this solution over OpenFGA

- You already run PostgreSQL and want to avoid operating another service
- You need audit trails, time-travel queries, or `explain_access` out of the box
- You need history-dependent rules — quotas, cooldowns, prior approval, separation of duties — enforced by the authorization engine rather than scattered across services
- You want the authorization engine co-located with your data (no network hop)
- Your team is comfortable with SQL and prefers it over a DSL

## When to choose OpenFGA

- You need official language SDKs and gRPC for a polyglot microservices architecture
- You want a managed/hosted authorization service (e.g., Okta FGA)
- You need a managed gRPC streaming Watch transport out of the box (this solution provides the changefeed via `watch_changes` + `NOTIFY`, but you bridge it to your transport)
- You prefer the OpenFGA DSL for defining and reviewing models
