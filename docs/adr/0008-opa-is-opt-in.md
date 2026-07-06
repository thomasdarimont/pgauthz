# ADR 0008 — OPA is opt-in; the default stack is OPA-free

- **Status:** Accepted
- **Date:** 2026-07-06
- **Deciders:** maintainers
- **Relates to:** [0007](0007-pgauthzd-front-door.md) (pgauthzd is the front door)

## Context

After ADR 0007, pgauthzd validates the JWT and answers `/access/v1` (AuthZEN) and
`/pgauthz/v1` (native) directly from PostgreSQL. OPA sits in the middle only as a
policy-as-code layer: when `OPA_URL` is set, pgauthzd forwards the token to OPA,
which evaluates Rego and calls **back** into pgauthzd's native callback for the
graph.

In practice the Rego the project ships is a pass-through: `allow` calls
`check_access`; `permitted_actions` / `accessible_objects` wrap `list_actions` /
`list_objects` — all of which pgauthzd already serves natively (AuthZEN evaluation
+ search). The engine's conditions (SQL / optional CEL) cover ABAC as data. So for
the common case OPA adds an extra network hop, a second JWT validation, and an
operational moving part without adding authorization behavior. Its unique value —
arbitrary Rego policy composition / request-shaping and the git-versioned-bundle
governance story — is real but not exercised by default.

## Decision

Make OPA **opt-in**. The default stack is OPA-free: pgauthzd answers directly from
PostgreSQL (the `decision-only` reader is the front door; the `full` writer fronts
writes), with conditions for ABAC. OPA + the OPA-fronted pgauthzd gateway are an
opt-in overlay:

- **compose:** `compose-opa.yml`, enabled by `./start.sh --opa` (or
  `PGAUTHZ_OPA=1`). The `--keycloak` / `--playground` overlays imply it.
- **Helm:** `authzen.opa.enabled` (default `false`) gates the OPA deployment, the
  OPA-fronted gateway, its ConfigMap/NetworkPolicy, and the ingress front door
  (which then routes to the direct reader).

Fronting OPA stays the orthogonal `OPA_URL` flag on a pgauthzd instance (ADR 0007);
this decision only changes the DEFAULT from on to off.

## Consequences

One fewer moving part by default: no OPA process, no extra hop, a single JWT
validation, lower latency. Policy-as-code (Rego) remains a first-class opt-in for
teams that want it.

Trade-off: no decision cache by default (OPA's bounded-TTL decision cache is off
the default path) — usually fine given sub-millisecond graph checks; a native
pgauthzd decision cache is a possible future addition for very high read volumes.

The OPA + AuthZEN-OPA integration test suites run with OPA enabled (`bootstrap.sh`
defaults it on); they skip cleanly on an OPA-free stack.
