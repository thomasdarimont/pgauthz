# ADR 0014 — Who may assert a subject: per issuer, per client, per store

- **Status:** Accepted (implemented 2026-10-17)
- **Date:** 2026-10-17
- **Deciders:** maintainers
- **Relates to:** [0007](0007-pgauthzd-front-door.md) (pgauthzd is the edge
  that resolves the subject), [0013](0013-decision-log.md) (the log records
  `actor` and `subject` separately), `docs/PRODUCTION.md` → AuthZEN subject
  policy, `pgauthzd/README.md` → Two ways to call pgauthzd

## Context

An AuthZEN request names its subject in the body. pgauthzd must decide whether
to believe it. Today that decision is one process-wide switch,
`ALLOW_SUBJECT_OVERRIDE`:

- **`false` (default, self-subject):** the verified token's subject is
  authoritative. A body subject must equal it (else `403`), a missing one is
  filled from the token, a partial one is a `400`. The caller can only ask
  about itself. The same rule guards `performed_by` on writes and
  `recorded_by` on the action log, so nobody can stamp another user into the
  audit trail.
- **`true` (trusted PEP):** the body subject wins, per item in a batch. The
  caller is an enforcement point asking on behalf of its users — the classic
  PDP deployment, and what the OpenID conformance suite exercises. Trust moves
  from the subject claim to the credential: *any* token the instance accepts
  may ask about *any* subject in *any* store the issuer is bound to, and may
  attribute writes and recorded actions to them.

Both modes are sound. The switch is too coarse. Real deployments mix callers:
a document service with its own workload identity that pre-authorizes for its
users in the `documents` store, a browser-facing BFF that forwards end-user
tokens, an HR system that must never assert anyone's identity in the `hr`
store even though it may read it. Today the operator's choices are to run one
instance per trust level, or to flip the flag and rely on the per-issuer
`stores` binding alone — which says *where* an issuer's tokens may ask, not
*whether they may speak for others there*.

Two pieces of the existing design point at the answer. `JWT_ISSUERS` already
carries per-issuer trust that is exactly this kind of statement: `stores`
(which stores the issuer's tokens may touch), `db_roles` (which per-app DB
roles they may claim) and `client_db_roles` (a per-issuer `azp` → role map,
because a client id is only meaningful within its issuer). And the decision
log (ADR 0013) already distinguishes the authenticated `actor` from the decided
`subject`, so an assertion is attributable after the fact — provided the
actor is identified, which a credential without a user subject is not today.

## Decision

Subject assertion becomes a **per-issuer, per-client, per-store** permission,
declared next to the other issuer bindings. `ALLOW_SUBJECT_OVERRIDE` keeps its
meaning as the coarse switch; the new setting is the middle ground between
"nobody" and "everybody".

### Configuration

Each entry of `JWT_ISSUERS` may carry `pep_clients`: a map from client id to
the anchored store patterns (the `stores` syntax) in which tokens of that
client may assert a body subject.

```json
[{"issuer": "https://id.example.com/realms/corp",
  "audience": "authz-api",
  "jwks_url": "https://id.example.com/realms/corp/protocol/openid-connect/certs",
  "stores": ["documents", "hr", "tenant-.*"],
  "pep_clients": {
    "document-service": ["documents", "tenant-.*"],
    "pep-gateway":      [".*"]
  }}]
```

- The client is the token's `azp` claim, falling back to `client_id`
  (RFC 9068 / RFC 8693 service tokens). Keyed under the issuer, like
  `client_db_roles`, because `azp` values collide across issuers.
- Patterns are anchored regular expressions, validated at load like `stores`.
  A pattern that names a store outside the issuer's `stores` binding is a
  configuration error — assertion can never widen the store binding.
- `ALLOW_SUBJECT_OVERRIDE=true` makes the map irrelevant (everyone may assert
  everywhere the binding allows). `pgauthzd doctor` warns when both are set,
  and `DEPLOYMENT_ENVIRONMENT=production` refuses the combination, in the
  spirit of the existing `ALLOW_*` overrides.

### Semantics

One predicate decides, `mayAssertSubject(issuer, client, store)`:

| | body subject absent | body subject = token subject | body subject differs |
|---|---|---|---|
| **may assert** (flag, or listed for this store) | token subject; if the token has none → `400` (single) / `decision: false` (batch item) | that subject | **the body subject** |
| **may not assert** | token subject; none → `400` / `false` | that subject | `403` naming the client and store |

A verified token that names **no subject** (a service credential without
`sub`/`preferred_username`) is not the unauthenticated case: under "may not
assert" a body subject is a `403` like any other mismatch — before this change
such a token was the one credential that could name anyone, since the rule
"no token subject, so the body is the only source" did not distinguish it from
a deployment without tokens at all. That fallback now applies only when no
token was verified. The partial-subject rule is unchanged: an `id` without a
`type` or the reverse is a `400`, never completed from the token. A batch item that names
another subject under "may not assert" fails the whole request with `403` —
an impersonation attempt, not a malformed item (ADR 0013's reasoning for the
existing behaviour).

**The same predicate gates the write side.** `performed_by` on tuple writes
and `recorded_by` on the action log may differ from the token subject only
where the client may assert subjects for that store. Asserting *who acts* and
asserting *who asks* are the same trust, and the two resolvers must not drift:
`resolveSubjectPair` and `resolveActor` call the same function.

### Identification of the caller

The JWT middleware puts the client id (`azp`, else `client_id`) into the
request context. Beyond the predicate this closes a gap in the decision log:
a credential without a user subject — a service account without a
`subject_type`, the conformance suite's api_key — logged an empty `actor`.
Every line now carries `client` as well, so "which app asked about whom" is
answered in both modes, with no change to the meaning of `actor` or `subject`.

### What does not change

- The default stays deny: an issuer without `pep_clients` and the flag off
  behaves exactly as today. No existing deployment changes behaviour.
- The OPA path is untouched: pgauthzd resolves the subject before it calls
  OPA, so hooks and the Rego policy see the resolved subject as they do now;
  `REQUIRE_TOKEN_FOR_READS` keeps its separate role for callers that reach
  OPA directly.
- The conformance harness keeps working. Its api_key now carries
  `azp: conformance-suite`, so a deployment can list it as a PEP client for
  `authzen_cert` instead of flipping the flag; the demo stack itself keeps
  env.sh's `ALLOW_SUBJECT_OVERRIDE=true` for now, because the self-minted test
  tokens of `tests/test-authzen.sh` carry no `azp` and several of its checks
  assert for other subjects.

## Consequences

- Operators express the trust they actually have: *this* service may speak
  for users in *these* stores. Mixed deployments no longer need one instance
  per trust level.
- The IdP stays the system of record for *which* clients exist; pgauthzd only
  records what each may assert. A new PEP is a config change on both sides,
  which is right — the two statements belong to different owners.
- Three sources of truth must agree in a request: issuer, `azp`, store. The
  predicate is a single function with a table-driven test, and `doctor`
  reports the effective assertion matrix per issuer so a misconfiguration is
  visible before traffic.
- Tokens that lack `azp`/`client_id` cannot be PEP clients. End-user tokens
  from browser logins usually carry `azp`; opaque or minimal service tokens
  may not, in which case the operator falls back to the coarse flag or fixes
  the token. The error message names the missing claim.
- The decision log line grows by one field (`client`); ADR 0013's "values
  never, identifiers yes" rule holds.

## Alternatives considered

- **A role claim (`PEP_ROLE`), like `WRITER_ROLE` and `RECORDER_ROLE`.** The
  smallest change, and it moves the per-client decision into the IdP's client
  role mappers, where such decisions often already live. Rejected as the sole
  mechanism because it cannot express per-store differences without encoding
  store names into roles; it could later be added as a shorthand that enables
  assertion for an issuer's whole store binding.
- **Modelling the permission in the graph** (`client:document-service →
  may_assert → store:documents`). Self-hosting and auditable with the rest of
  the data, but it puts control-plane trust into the data plane the same
  callers write to, and costs a lookup on every request. The trust boundary
  belongs in configuration.
- **A global `azp` map** (like the single-issuer `CLIENT_DB_ROLES`). Simpler,
  but wrong for multi-issuer setups, which is exactly where the fine grain is
  needed; the per-issuer placement follows `client_db_roles`.
- **Per-store configuration in the engine** (a store setting "accepts
  asserted subjects"). The store does not know who is calling; the daemon
  does. It would also leave the write-side attribution ungoverned.

## Non-goals

- Deciding *which* subjects a PEP may assert (only alice's team, only subject
  type `customer`). That is delegation policy; the issuer's `stores` binding
  and the model's type restrictions bound it coarsely today, and ADR 0011
  hooks can veto per request. Not part of this change.
- Replacing `ALLOW_SUBJECT_OVERRIDE`. It remains the deliberate "this whole
  instance is a PDP for trusted callers" switch; the new setting refines it.
