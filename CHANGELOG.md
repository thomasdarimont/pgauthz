# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While
pre-1.0, minor versions may include breaking changes.

## [Unreleased]

### Security (review #10 — pre-production batch)
- **Watch/changefeed is role-gated and DENY BY DEFAULT on the public
  listener** (`WATCH_REQUIRED_ROLE`; the feed exposes authorization topology
  and the daemon's DB role holds `authz_auditor` to serve it — HTTP now
  decides who may ask; `"*"` opens explicitly; the trusted callback listener
  is unaffected). Native explain gains the analogous `EXPLAIN_REQUIRED_ROLE`
  (empty = open, back-compat). The dev/test stack sets
  `WATCH_REQUIRED_ROLE=authz_auditor`; the e2e suite proves ordinary 403 /
  auditor 200.
- **Multi-issuer is fail-closed**: with more than one trusted issuer, an
  issuer without stores (or, with role derivation, db_roles) bindings now
  FAILS STARTUP instead of warning past a cross-tenant hole;
  `ALLOW_UNBOUND_MULTI_ISSUER=true` is the deliberately alarming override.
  Single-issuer behavior unchanged.
- **Malformed configuration is fatal**: invalid ints/durations/booleans in
  env vars fail startup with a message naming every offender —
  `REQUIRE_STORE_BINDING=treu` can no longer silently mean `false`. Absent
  still means the documented default.
- **Sealed-cursor hardening**: AAD fields are length-prefix encoded
  (delimiter characters in ids can no longer alias field boundaries; property
  test included), the caller-context digest is the full SHA-256, and a
  cursor-sealing failure now surfaces as a 5xx instead of silently ending
  pagination as if complete.
- **OPA responses are bounded** (`OPA_MAX_RESPONSE_BYTES`, default 10 MiB):
  oversized bodies → `policy_evaluation_failed`; error-body text is truncated
  before logging.
- **CI: a required OPA integration job** (`opa-test`) runs the full stack
  with `PGAUTHZ_OPA=1`; `tests/test-opa.sh` fails (instead of skipping) when
  OPA is absent under `PGAUTHZ_CI=1`, and all four hook example suites +
  validator tiers run in CI.


## [0.14.0] - 2026-07-07

### Added

- **OPA policy hooks** ([ADR 0011](docs/adr/0011-opa-policy-hooks.md)):
  user-supplied **veto rules** riding along the standard decision pipeline —
  no allowlist entries, no pgauthzd config, no platform-file edits. Mount
  `.rego` files declaring packages under `authz.hooks.v1.<name>` (compose: one
  volume line onto the shipped `/policies/hooks` mountpoint; Helm:
  `authzen.opa.extraPoliciesConfigMap`); a hook may define
  `deny contains msg` (vetoes `allow`/`allow_detailed`/`evaluations` — a veto
  denies the whole batch, so `/evaluations` is not a bypass) and
  `deny_write contains msg` (vetoes every write operation,
  `error: denied_by_policy_hook`). Hooks can only **narrow** — the ReBAC graph
  answer still has to pass — and are fully attributed: denials carry the hook's
  package name, and `allow_detailed` reports `hooks_consulted` +
  `hook_denials`, which pgauthzd returns in the AuthZEN response context under
  `X-PGAuthz-Detail` (discarded otherwise). A deployment with no mounts is
  bit-identical to before. Reference hooks + the contract test suite live in
  `examples/opa-hooks/` (`opa test` against the real platform policies, wired
  into `test-opa.sh`); validated live against a real OPA with hooks mounted. Hooks are evaluated against a versioned, normalized input ABI
  (`pgauthz.hooks/v1` — tokens/transport invisible), declared under
  `authz.hooks.v1.<name>`, and gated by `scripts/validate-hooks.sh`
  (namespace/duplicate/platform-package/`http.send` checks — veto-only is a
  contract, not a sandbox); denials are structured `{hook, code, message}`,
  `evaluations` returns a `403 denied_by_policy_hook` on veto (not a fake
  all-false batch), and `permitted_actions` is filtered per action. **Store-scoped hooks:** the namespace
  is two-tier — `authz.hooks.v1.global.<name>` (every store) and
  `authz.hooks.v1.stores.<store>.<name>` (only that store, keyed by the
  request's store so tenants are isolated); Helm gains
  `opa.storePoliciesConfigMaps`. `/evaluations` now evaluates hooks **per item**
  (a veto rejects the batch with `evaluation_index`, not a fake all-false); a
  runtime hook error **fails the request closed** (`strict-builtin-errors` →
  `policy_evaluation_failed`, 5xx, never a phantom decision); hooks read a
  **server-derived `evaluated_at`** (time/env gates can't trust caller context);
  and `scripts/validate-hooks.sh` (`--global` / `--store <s>`) is a required
  release gate (wired into `pre-release.sh`). Fourth review round:
  **tenant isolation is now validator-ENFORCED** (a hook may reference only
  `input`, pure builtins, and its own package — no cross-package/dynamic
  `data[…]`), a server-derived **`deployment.environment`** joins the ABI for
  environment gates, hook-veto **`denials` are disclosed only under
  `X-PGAuthz-Detail`** (batch 403 + write veto), denials are ordered
  `(tier,store,hook,code,message)` with `denials_truncated`/`denial_count`, the
  Helm chart runs a deploy-time `opa check` initContainer over mounted hooks
  (store volume names sanitized), and OPA's isolated Rego eval time is recorded
  as `pgauthzd_opa_rego_eval_duration_seconds` (`OPA_EVAL_METRICS`, default on). Fifth review round:
  hook builtin **purity is pinned by a capability allowlist**
  (`opa/hooks-v1-capabilities.json`, reproducible ABI) enforced by the
  validator AND a Helm `opa check --capabilities` **initContainer**; the ADR
  now names two trust tiers (global = platform, store = delegated tenant) and
  requires **signed immutable bundles** for delegated store hooks (a mutable
  ConfigMap under `--watch` is not an isolation boundary); a **per-hook denial
  cap** (16) bounds a misbehaving hook; `strict-builtin-errors` fail-closed is
  documented + tested on every query path; and `DEPLOYMENT_ENVIRONMENT` is
  format-validated. Sixth review round:
  `http.send` is **forbidden for store hooks** (a global-only, platform-governed
  option); the validator now also rejects `data`/`input` **imports** (an
  `import data.other as x` alias would evade the body-only isolation check) —
  all checks operate on the parsed AST; the signed-bundle topology is pinned to
  a **single platform-controlled, platform-signed bundle** (a tenant can't sign
  an artifact production OPA accepts); `denial_count` is defined as the total
  **after** per-hook caps, with `denials_dropped` + `hook_output_truncated` for
  honesty; and the readiness signals are documented as non-overlapping
  (deploy-time validation ≠ deep readiness ≠ activation revision ≠ runtime
  metrics). Seventh review round:
  **enumeration refusal ships in v1, secure by default** — with any hook
  loaded, `accessible_objects`/`accessible_subjects` are refused
  (`403 enumeration_refused_with_hooks`) because hooks don’t filter
  graph-derived supersets; `ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true`
  (OPA env / `opa.allowUnfilteredEnumerationWithHooks` in Helm) opts into
  superset semantics; an unset `DEPLOYMENT_ENVIRONMENT` now forwards the
  sentinel **`unknown`** (an empty string fails *open* on equality gates —
  env gates must be allowlist-style); bundle signing pinned to exact validated
  bytes with unsigned/unknown-key/local-fallback rejection; per-hook denial
  cap documented as an output bound, not a compute bound. Eighth review round:
  enumeration refusal is **applicable-hook-scoped** (global + requested store —
  tenant B's hooks never disable tenant A's enumeration; now regression-tested);
  Rego **reserved words are blacklisted as store names** (migration 0009 —
  keyword package segments parse inconsistently across Rego tooling); Helm
  store-hook volume names get a **hash suffix**
  (`store-hooks-<40-char sanitized>-<8-char sha256>`) fixing case-collisions
  and the 63-char limit; bundle signing described correctly (signature covers
  the file set + per-file hashes, not tarball bytes) with explicit `.manifest`
  roots required; and the `"unknown"` environment sentinel is now **enforced**:
  a platform guard denial (`deployment_environment_unknown`) fires on decisions
  and writes when hooks are loaded without `DEPLOYMENT_ENVIRONMENT`
  (`ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT=true` opts out). Ninth review round
  (reviewer: final-quality): bundle **root narrowed to `authz/hooks/v1/stores`**
  (the wider root would erase separately mounted global hooks on activation),
  full `.manifest` example with `revision` + ABI metadata; **http.send
  destinations capability-enforced** via `opa/hooks-v1-http-capabilities.json`
  (pure set + `http.send` + deny-all `allow_net` template; runtime-enforced by
  OPA's capabilities file, `HOOK_HTTP_CAPABILITIES` for the validator); hook
  `<name>` segments follow the store-name rules (reserved words + ≤63,
  validator-enforced); the amendment history moved to an ADR appendix; and the
  hooks README gained a "see exactly what your hook receives" dev section
  (query `_decision_hook_input`/`_write_hook_input` directly). Tenth review round
  (final): the `allow_net` claim corrected — OPA capabilities are
  **build/check-time** validation (`opa run` takes no capabilities file), so
  the http.send model is three independent controls: build-time capabilities +
  AST validation (the validator now also **rejects non-static http.send
  destinations** — literal object + literal string `url` required), the signed
  immutable bundle, and independent runtime egress enforcement
  (NetworkPolicy/egress proxy; a blocked call fails closed via
  `strict-builtin-errors`). Eleventh review round (merge verdict): the
  config-injection mechanism is explicit (flags reach Rego only via the
  platform config module — `opa.runtime().env`, excluded from hook
  capabilities; data-injected where process env doesn't exist), and the
  validator now **statically enforces the `allow_net` host allowlist** on the
  forced-literal `http.send` destinations and **rejects
  `enable_redirect: true`** (OPA redirects verified off by default). Twelfth
  review round (merge): the `http.send` static contract is complete —
  `raise_error` must stay `true` (`false` bypasses `strict-builtin-errors`
  fail-closed via a `status_code: 0` response), `tls_insecure_skip_verify`
  must stay `false`, `timeout` must be a static non-zero bound; computed
  values rejected. Thirteenth review round (merge): global `http.send` hooks
  must ship via the signed immutable artifact path in production (mutable
  ConfigMap/`--watch` = dev or network-free globals only); platform config
  flags documented + regression-tested as fail-closed parses (exact `"true"`
  enables, anything else disables). Fourteenth review round: the nonexistent
  `max_response_bytes` field removed from the ADR (OPA verifiably rejects it;
  response size must be bounded by the endpoint or an egress proxy), and the
  `http.send` contract tightened to **read-only lookup** — literal `GET`/`HEAD`
  only, no `body`/`raw_body`, `max_retry_attempts` 0/absent, no `Host` header
  (all validator-enforced, mutation-tested). Fifteenth review round: HTTP
  4xx/5xx responses identified as a **fail-open gap** (they are successful
  `http.send` executions — `strict-builtin-errors` never fires), so network
  hooks must deny outside a declared success-status set;
  `examples/opa-hooks-http/` ships the reference hook + 10 contract tests
  (404/429/500/503, malformed/missing bodies, aggregator veto), wired into
  `pre-release.sh`; signed global-hook topology pinned (combined
  `authz/hooks/v1` bundle XOR separate `authz/hooks/v1/global` bundle). Sixteenth review round (ADR frozen): the HTTP status/schema contract is
  explicitly a **governance** requirement for platform-trusted network hooks
  (review + contract tests; not statically checkable), with the
  platform-HTTP-helper model documented as deferred v2 hardening;
  `platform_policy_compatibility` enforcement named (publish pipeline +
  activation monitor).
- **Hook-filtered enumeration + verified actor roles (ADR 0011 follow-up).**
  `HOOK_FILTERED_ENUMERATION=true` (Helm: `opa.hookFilteredEnumeration`)
  evaluates the applicable decision hooks per enumeration candidate and drops
  denied ids — listings then match per-object checks, replacing the blanket
  refusal. Guardrails: `HOOK_FILTER_MAX_CANDIDATES` (1000) refuses over-cap
  queries outright (`enumeration_refused_too_many_candidates`, typed 403);
  refused while the environment guard is active; paginated results switch to
  a raw-keyset protocol (`{hook_filtered, ids, has_more, cursor}`) so pages
  that filter below the limit never end pagination early (short/empty pages
  with a next_token are normal). And the hook ABI now carries the verified
  caller as `actor{id, roles}` on decisions AND writes (roles =
  `JWT_ROLES_CLAIM` aggregation, e.g. Keycloak realm + client roles) —
  role-based exemptions (`not "auditor" in input.actor.roles`) are
  expressible and stay veto-only. `examples/opa-hooks-filtering/` ships the
  reference hook + 14 contract tests, wired into `pre-release.sh`. Review
  hardening: strict cap parsing (digits-only, 1..100000; malformed ⇒ refusal,
  never a silent default), **sealed filtered-page cursors** (AES-GCM via
  `CURSOR_SEAL_KEY` — the raw-keyset cursor may name a hook-hidden id; failed
  unseal = 400), the per-page consistency claim qualified, `http.send` request
  fields moved to an explicit allowlist (cross-query cache controls
  forbidden), and the flat role namespace documented (use globally unambiguous
  exemption role names). Precedence pinned: with BOTH mode flags set, filtering
  wins, and a configured-but-inoperable filtering state (env guard, malformed
  cap) refuses — never degrades to the superset. `CURSOR_SEAL_KEY` is a
  comma-separated keyring (first mints, all accept) so key rotation keeps
  in-flight paginations alive. Sealed cursors are additionally **bound to
  their query context** (AEAD AAD over operation/store/subject/action/
  resource — cross-context replay rejected); the per-process fallback is
  declared dev-only (startup warning without a shared key on OPA-fronted
  instances); the cap tri-state pinned (missing → 1000, valid → value,
  malformed → refusal); cache-field prohibition promoted into the normative
  ADR `http.send` contract; `actor{id,roles}` additivity clarified (actor was
  always an object). Cursor binding completed: the AAD includes `actor.id` and a
  canonical caller-context hash (actor A's cursor is rejected for actor B);
  the Helm chart refuses to render `opa.hookFilteredEnumeration` without
  `authzen.opa.cursorSealKey`; the cap documented as per-request scope. Crypto
  invariants (freeze round): fresh random nonces per cursor, strict
  `CURSOR_SEAL_KEY` parsing (empty segments = startup error), an explicit
  envelope format version (unknown = fail closed), and 32-byte plaintext
  padding (token length reveals only a coarse bucket). Role provenance,
  two mechanisms: the hook `actor` carries **verbatim claim copies** under
  `actor.claims.<name>` (`HOOK_ACTOR_CLAIMS`, default
  `realm_access,resource_access` — client_ids stay map keys, so URI-shaped
  SAML entity IDs need no separator convention; the recommended way to write
  client-scoped hook logic; the actor top level stays reserved for derived
  identity), and
  `JWT_ROLES_SOURCE_PREFIX=true` (opt-in) emits provenance-prefixed FLAT
  roles — `realm::<role>` / `<client_id>::<role>` — for consumers of the flat
  set like the writer gate (update `WRITER_ROLE` to the prefixed form when
  enabling); flat aggregation remains the default. Custom selections
  (`HOOK_ACTOR_CLAIMS=...`, Helm: `opa.hookActorClaims`) replace the default —
  top-level claim names taken whole (URI-named OIDC claims work), missing
  claims absent. **Platform hook library** `authz.hooks.lib.v1`: shared,
  versioned helper functions — the single validator-allowlisted namespace
  hooks may import (platform-owned, functions-only, ships with the platform
  policy; a call to a nonexistent function fails validation). First module:
  `keycloak.has_realm_role` / `keycloak.has_client_role` +
  `realm_roles`/`client_roles` accessors, all fail-closed on absent claims;
  the `claims_guard` example uses it. Operators add their OWN shared helpers
  under the reserved `authz.hooks.lib.v1.ext.<name>` subtree
  (`validate-hooks.sh --lib`: functions-only, always pure — no `http.send`
  escape, since a shared lib would hand network access to network-free store
  hooks; Helm: `opa.extraLibsConfigMap`; validator: `HOOK_EXTRA_LIBS=<dir>`
  when validating hooks that call them; `examples/opa-hooks-lib/`). Onboarding pass: the dev compose stack now sets
  `DEPLOYMENT_ENVIRONMENT=dev` (mounting a first hook no longer trips the
  fail-closed environment guard; production still must set its own value —
  Helm: `authzen.opa.deploymentEnvironment`), `scripts/new-hook.sh` scaffolds
  a correctly-packaged hook skeleton, and the hooks README leads with a
  5-minute quickstart (surprising secure defaults called out up front)), plus
  `scripts/make-token.sh` (demo ES256 JWT minting, extracted from
  test-opa.sh) so the quickstart is runnable end-to-end — which also fixed
  the quickstart to target the OPA-fronted instance (8091, where hooks run)
  instead of the direct reader (8090, which never consults hooks). Dev flag: OPA
  console decision logging is now switchable — `OPA_DECISION_LOGS_CONSOLE=true`
  (compose) / `opa.decisionLogsConsole=true` (Helm), OFF by default (the log
  includes full inputs, i.e. forwarded bearer JWTs — dev only). Post-review hardening: **store
  names are restricted** to a Rego-safe identifier (`^[a-zA-Z_][a-zA-Z0-9_]*$`,
  ≤63 chars — migration 0008 + `create_store`), so a store is its hook package
  segment directly (no scope-key hashing); `evaluated_at` is **captured once
  by pgauthzd** and forwarded (every batch item/hook sees one timestamp); the
  write ABI names the authenticated **`actor`** distinct from the tuple's
  subject; and denial `code`/count are bounded.

- **HTTP availability hardening** (review #9). Go's zero timeouts are
  *unlimited*, so a black-holed dependency or a slow client could previously
  hang requests, probes, or startup:
  - `OPA_REQUEST_TIMEOUT` (default `10s`) bounds every OPA HTTP call; the
    startup health probe runs under its own deadline.
  - Every listener now sets `ReadHeaderTimeout` (`HTTP_READ_HEADER_TIMEOUT`,
    default `5s`, slowloris hardening) and `IdleTimeout` (`HTTP_IDLE_TIMEOUT`,
    default `60s`) — deliberately **no** `WriteTimeout`, so long-running
    search/explain/watch responses are never killed mid-write.
  - `HTTP_MAX_BODY_BYTES` (default 10 MiB, `0` disables) caps request bodies
    via `http.MaxBytesReader` on both the public and callback listeners.
  - `/readyz`'s backend ping is bounded server-side (5s), so a black-holed
    database fails the probe promptly instead of hanging it.
- **Strict deep-readiness mode** (review #9). `OPA_DEEP_READINESS_REQUIRED`
  (default `false`): when set, a policy set without the `callback_healthy`
  rule **fails** readiness instead of silently degrading to the shallow
  OPA-`/health`-only check. Either way the active mode is now observable as
  `pgauthzd_opa_readiness_mode{mode="deep|shallow"}`.

### Fixed

- **Whitespace-only audit actors rejected** (review #9). `performed_by` is
  trimmed before the non-empty check (`"   "` no longer passes) and capped at
  256 characters, so the immutable audit trail can't carry blank or junk
  attribution.

## [0.13.0] - 2026-07-07

### Security

- **`/readyz` no longer echoes backend errors** (review #8). The probe
  endpoints are unauthenticated, and a failing backend's error text can carry
  internal hostnames or DSN fragments; callers now get a generic
  `{"status":503,"message":"unhealthy"}` while the cause goes to the
  structured server log. Test pins that DSN/hostname strings never reach the
  body.
- **No empty audit attribution on the callback listener** (review #8,
  F16 follow-up). The service-token callback listener has no JWT subject to
  fall back to, so an omitted `performed_by` would have stored an *empty*
  actor in the immutable audit trail; it is now rejected (`400`). The
  sanctioned caller is unaffected — the OPA policy always asserts
  `authn.subject_id`.

### Added

- **OPA-mode readiness is end-to-end** (review #8). An OPA-fronted instance's
  `/readyz` previously proved only that OPA's own `/health` answered — not
  that a decision could succeed. The pgauthz client policy now exposes
  `data.authz.pgauthz.callback_healthy` (allowlisted in `system_authz.rego`,
  a bare boolean; reuses the callback mTLS options, 2s timeout, never
  cached), and `opabackend.Healthz` queries it after OPA `/health` — so
  "ready" means **OPA policy eval → native callback → PostgreSQL** is usable.
  A policy set without the rule (custom Rego) degrades to the shallow check.
  Validated against a real OPA (rule true with the callback up, false with it
  down) and asserted in `tests/test-opa.sh`.

### Changed

- **Store names are restricted to `^[a-zA-Z_][a-zA-Z0-9_]*$` (≤63 chars)**
  (migration 0008). Enforced by a table `CHECK` and `create_store`. Required so
  a store name can be the Rego package segment for store-scoped OPA policy
  hooks (ADR 0011); every existing store name already complies.

- **GitHub Actions bumped off the deprecated Node 20 runtime**: `checkout@v7`,
  `setup-go@v6`, `cache@v6`, `docker/setup-buildx-action@v4`,
  `docker/build-push-action@v7`.

## [0.12.0] - 2026-07-07

### Security

- **Audit actor spoofing closed on the public listener** (audit finding F16,
  found by external review #7). The native write bodies' `performed_by` field
  previously overrode the authenticated JWT subject on **both** listeners, so
  any authorized writer could stamp another user into the immutable audit
  trail. Now the trust contexts are split: on the **public** listener the JWT
  subject is authoritative — a differing body value is rejected (`403`) unless
  `ALLOW_SUBJECT_OVERRIDE` is enabled (the existing trusted-PEP switch, now
  governing both the decision-path subject and audit attribution); the
  internal callback listener is unchanged (the body value is the trusted OPA
  upstream's assertion of the subject it authenticated — the field's purpose).

### Added

- **`/livez` and `/readyz` probes** (review #7). `/livez` is process liveness
  with **no dependency checks**; `/readyz` pings the backend (the old
  `/healthz` behavior, which remains as a deprecated alias). The Helm chart
  now points `livenessProbe` at `/livez` and `readinessProbe` at `/readyz`,
  so a PostgreSQL outage takes instances out of rotation instead of making
  Kubernetes restart healthy pgauthzd processes in a loop.

### Changed

- **OpenAPI wording: the served document is *topology-accurate*, not
  capability-pruned.** It lists exactly the routes the instance registers — a
  `decision-only` instance keeps the write operations (they respond with a
  documented `403`; pruning them would claim a route doesn't exist while it
  demonstrably answers). The `serviceToken` security scheme now states
  explicitly that it is rejected (`401`) on the public listener.

## [0.11.0] - 2026-07-07

### Changed

- **`wrong_epoch` recovery guidance is now reconcile-first** (review #6). The
  structured freshness 409 (and ADR 0009 / README) previously advised
  "re-mint via a new write" — misleading after a **lossy** promotion, where the
  original write may be gone and an unrelated write's token proves nothing
  about it. The guidance is now: re-read and reconcile the intended
  authorization state on the current primary, reapply the change idempotently
  if missing, then use that write's token (matters most for
  revokes/offboarding, as the promotion integration test demonstrates).
- **Token ordering documented as timeline-local.** "A later token covers all
  earlier writes" holds only within one WAL timeline; a failover
  (`wrong_epoch`) voids the ordering contract until the client reconciles
  (PRODUCTION.md PEP guidance + ADR 0009).
- **The served OpenAPI document is instance-accurate.** An OPA-fronted
  instance (whose public listener does not register the native routes) now
  serves a copy with the native paths omitted; the source file keeps the full
  contract, and native operations carry a machine-readable
  `x-pgauthz-availability` extension (`listeners`, `public_listener:
  not-when-opa-fronted`, `profile: full` on writes). New `OPENAPI_ENABLED`
  (default `true`) disables the endpoints entirely.

### Fixed

- **Mint-status tri-state edge:** freshness keys configured but a write
  backend that cannot mint now reports `X-PGAuthz-Revision-Status:
  unavailable` (enabled-but-broken, counted + logged) instead of `disabled`
  (feature off). Defensive-only — a `full` instance's direct pgx backend
  always mints.

## [0.10.0] - 2026-07-07

### Added

- **Verdict-specific freshness errors** ([ADR 0009](docs/adr/0009-freshness-tokens.md)).
  An unsatisfiable `at_least_as_fresh` read now returns a structured `409` —
  `{error: "freshness_constraint_unsatisfied", verdict, primary_consulted,
  message}` (plus the existing `X-PGAuthz-Stale` header) — with per-verdict
  guidance: `stale`/`unknown` → retry the primary; `wrong_epoch` → **not
  retryable** (a failover happened; re-mint via a new write or drop the
  constraint). `primary_consulted: true` says the transparent fallback already
  re-checked the primary, so "retry the primary" is no longer offered as advice.
- **Mint failures are surfaced, not silent.** A write that commits but cannot
  mint its freshness token now reports `X-PGAuthz-Revision-Status: unavailable`
  (vs `issued` / `disabled`), increments
  `pgauthzd_freshness_mint_failures_total`, and logs the error;
  `pgauthzd_freshness_tokens_minted_total` counts successes.
- **Duplicate derived key ids are a startup error.** Two `FRESHNESS_TOKEN_KEYS`
  secrets deriving the same kid (a ~2⁻³¹-per-pair sha256-prefix accident) would
  silently shadow one key at verification; `config.Load` now rejects the keyring
  deterministically at startup.
- **Real promotion integration tests** (`tests/test-scaling.sh`). The scaling
  suite now ends with an actual `pg_promote` of the streaming standby, proving
  the ADR 0009 timeline guard against a live failover: a **lossy** promotion
  (the standby is network-disconnected before a write, then promoted and its
  new timeline advanced past the token's LSN — the exact scenario where a naive
  LSN-only check false-allows, F12) and a **clean** promotion (caught-up token)
  both yield `wrong_epoch`, asserted before any `CHECKPOINT` so a lagging
  control-file timeline source would fail the test; a token re-minted on the
  promoted node carries the new epoch and is immediately `fresh`. Also asserts
  the primary-side F12 behavior directly (cross-timeline token → `wrong_epoch`
  on a primary).

### Removed

- **`gateway/` (the nginx "OPA edge proxy" template).** It existed for the
  legacy topology that exposed OPA's decision API directly to clients — a
  topology gone since the pgauthzd consolidation ([ADR 0008](docs/adr/0008-opa-is-opt-in.md)):
  OPA is now internal-only (pgauthzd is its sole caller), edge TLS belongs on
  any ordinary proxy/ingress in front of pgauthzd, the internal callback hop
  has built-in mTLS (`INTERNAL_TLS_*`), and OPA's management surface is gated
  by `system_authz.rego` + network isolation. Keeping the template suggested
  OPA was meant to be externally exposed — exactly the mistake the current
  architecture removes. PRODUCTION.md's "Edge TLS / mTLS" section now
  documents the per-hop guidance; the template remains in git history.

### Added

- **OpenAPI description for pgauthzd, contract-tested against the code.** The
  full HTTP surface — native `/pgauthz/v1` and AuthZEN `/access/v1` (incl. the
  store-scoped variants), every `X-PGAuthz-*` request/response header, the
  error envelopes (standard + the structured freshness `409`), and both
  security schemes (public-listener JWT vs the internal callback's service
  token) — lives in `pgauthzd/internal/api/openapi.yaml`, is embedded into the
  binary, and is served unauthenticated at `GET /pgauthz/v1/openapi.json`
  (and `.yaml`) with `info.version` stamped to the build version. AuthZEN
  shapes cross-checked against the official openid/authzen JSON schemas
  (`properties` bags accepted; the detail `context` documented as a vendor
  extension). Drift is impossible to ship: `openapi_test.go` enforces
  bidirectional route coverage (documented ⊆ registered ⊆ documented) and
  validates real handler responses against the schemas — wired into `go test`,
  CI, and `scripts/pre-release.sh` (which now also runs the pgauthzd unit
  tests).

### Added (docs / examples)

- **README "A complete example first"** — the full lifecycle in one
  copy-pasteable psql session at the top of the API section (store → model →
  `describe_model` → `write_tuple` → `check_access` → `explain_access` →
  `list_objects`/`list_subjects` → revoke), with real outputs; validated live.
  The same example ships as loadable files under
  **`examples/models/helloworld/`** (`model.sql`, `seed.sql`, `demo.sql`) —
  the smallest useful model, now the first row of the Example Models table.

### Changed

- **Bad-token 400s are opaque by design.** The freshness guard returns one fixed
  message for every bad-token cause (malformed / unknown-or-retired kid /
  signature mismatch) so a probe can't distinguish "key rotated away" from
  "forged"; the specific reason is now logged server-side instead.
- Documented the **cooperative-consistency contract** (ADR 0009 + PRODUCTION.md):
  freshness tokens upgrade only the reads that present them — deployment-level
  revocation visibility remains `remote_apply`'s job, and a PEP fronting end
  users must own consistency selection (retain the newest token, never let
  clients weaken the mode, cache-bypass after revokes).

## [0.9.0] - 2026-07-06

### Added

- **Freshness-token key rotation** ([ADR 0009](docs/adr/0009-freshness-tokens.md)).
  The signing config is now an ordered keyring, `FRESHNESS_TOKEN_KEYS`
  (comma-separated): the **first** key mints, **every** key verifies, enabling a
  zero-downtime three-phase rotation (`"old,new"` → `"new,old"` → `"new"`;
  runbook in [PRODUCTION.md](docs/PRODUCTION.md)). Tokens embed a key id derived
  from the secret (`base64url(sha256(secret)[:4])`, MAC-covered), so verification
  picks the right key during the overlap; an unknown/retired kid fails with the
  same opaque error as a forgery (fail closed). New per-kid drain metric
  `pgauthzd_freshness_key_verifications_total{kid}` shows when the old key is
  safe to drop. `FRESHNESS_TOKEN_KEY` remains as a single-key alias (setting
  both is a startup error). **Breaking:** the token wire format now carries the
  kid — tokens minted by v0.8.0 fail with `400` after the upgrade (clients
  re-mint on their next write); closes audit finding F13.

### Fixed

- **Freshness tokens: a promoted primary no longer accepts stale tokens**
  ([ADR 0009](docs/adr/0009-freshness-tokens.md)). `assert_fresh` previously
  returned `fresh` unconditionally on any primary, so after a **lossy failover** a
  promoted primary (new timeline) would confirm a token minted on the old
  timeline whose write it never received — a stale-allow. It now derives its own
  timeline + WAL position (`pg_walfile_name(pg_current_wal_insert_lsn())`) and
  applies the same `wrong_epoch`/`stale` checks as a standby, so a cross-timeline
  token is rejected everywhere. **Breaking:** a primary can now return
  `wrong_epoch`/`stale` for a token instead of always `fresh`.
- **Transparent primary fallback re-validates on the primary.** It previously
  marked the request for primary routing without re-checking; it now re-runs
  `assert_fresh` against the primary pool and only serves from it on a `fresh`
  verdict (else `409`), closing the same lossy-failover hole on the fallback path.
- **`at_least_as_fresh` without a token is now `400`** (was a silent downgrade to
  a low-latency read — a fail-open on client misconfiguration).

## [0.8.0] - 2026-07-06

### Added

- **Prometheus metrics** ([ADR 0010](docs/adr/0010-metrics-observability.md), Slice 1)
  on an opt-in, non-public listener (`METRICS_LISTEN_ADDR`): HTTP RED
  (`pgauthzd_http_requests_total` / `_duration_seconds` by templated route),
  freshness verdict/fallback counters (`pgauthzd_freshness_verdicts_total{verdict}`,
  `pgauthzd_freshness_fallback_total` — lagging-replica + failover signals),
  `pgauthzd_build_info`, and pgx pool stats (`pgauthzd_db_pool_connections{pool,state}`),
  plus the default Go/process collectors. Demo wiring: `./start.sh --metrics`
  brings up a Prometheus + Grafana that scrape it (compose-metrics.yml, UIs on
  :9095/:9096); Helm exposes it via `metrics.enabled` + a `ServiceMonitor`
  (`metrics.serviceMonitor.enabled`). **Slice 2** adds per-store decisions
  (`pgauthzd_check_decisions_total{store,decision,api}`), search
  (`pgauthzd_search_requests_total` / `_result_size`), auth signals
  (`pgauthzd_jwt_validation_failures_total`, `pgauthzd_authz_denied_total`), and
  backend latency (`pgauthzd_db_query_duration_seconds{op,pool}`,
  `pgauthzd_opa_request_duration_seconds`). **Slice 3** adds periodically-sampled
  engine/tenant gauges — `pgauthzd_store_tuples{store}` (top-N, capped by
  `METRICS_MAX_STORES`) + `pgauthzd_stores_total` (`METRICS_SAMPLE_INTERVAL_SECONDS`).
- **Freshness tokens for read-your-writes across replicas** ([ADR 0009](docs/adr/0009-freshness-tokens.md)).
  An opt-in, HMAC-signed LSN-watermark token (`{epoch=timeline, lsn}`): a write
  mints one (`X-PGAuthz-Revision` header + `"revision"` body), and a read can
  present it with `X-PGAuthz-Consistency: at_least_as_fresh` to demand
  read-your-writes. A replica that hasn't caught up answers `409` +
  `X-PGAuthz-Stale` so the caller retries against the primary; the epoch guards
  against a lossy-failover false-allow (the timeline is read from the WAL
  position, never the lagging control file). Engine primitives
  `authz.freshness_token()` / `authz.assert_fresh()`; enabled by
  `FRESHNESS_TOKEN_KEY` (same value on writer + readers; empty = off, fail
  closed). No PostgreSQL 19 dependency. Paginated searches bind the freshness
  floor into the `next_token` cursor, so a scan can't mix pre/post-revoke states
  across pages. Optional **transparent primary fallback** (`FRESHNESS_PRIMARY_URL`
  on a decision-only reader): a not-fresh-enough read is re-run on the primary
  (marked `X-PGAuthz-Served-By: primary`) instead of returning 409.
- **Proprietary HTTP headers are namespaced `X-PGAuthz-*`** (was the generic,
  collision-prone `X-Authz-*`): `X-PGAuthz-Role` / `-Detail` / `-Consistency` /
  `-Revision` / `-Stale` / `-Store` (the last also fixes a casing slip).

### The pgauthzd front door — PostgREST removed, OPA now opt-in

A large architectural consolidation: **pgauthzd** (one Go daemon) is now the
external front door for reads *and* writes, PostgREST is gone entirely, and OPA
is demoted to an **opt-in** internal policy sidecar — the default stack is
OPA-free, answering directly from PostgreSQL.

### Changed

- **pgauthzd is the external front door.** Clients speak AuthZEN 1.0
  (`/access/v1/*`) or the native `/pgauthz/v1/*` API to pgauthzd, which validates
  the JWT (multi-issuer via `JWT_ISSUERS`; the `iss` claim selects the validator).
  OPA is an internal sidecar — the *only* caller of OPA is pgauthzd, which
  forwards the verified token; OPA's Rego calls **back** into pgauthzd's native
  `/pgauthz/v1` callback for graph data (service-token authenticated, optional
  mTLS). The old "OPA is the single front door" topology is gone.
- **pgauthzd fronts and authorizes writes.** The `full`/writer instance exposes
  `POST /pgauthz/v1/{write,delete,delete-user,write-checked}` and gates them on a
  `WRITER_ROLE` claim (default `authz_writer`; `JWT_ROLES_CLAIM` defaults to
  `roles`) — it authorizes writes itself instead of relying on an OPA-fronted
  writer. Writes apply natively via pgx under a fixed writer DB role.
- **Profiles are DB capability only: `decision-only` | `full`.** The former
  `compat-opa` profile is replaced by an orthogonal **`OPA_URL`** flag: set it and
  pgauthzd consults OPA for the AuthZEN surface; the native surface stays direct
  pgx and is exposed on the public listener only when *not* fronting OPA (so the
  raw API can't sidestep OPA policy). A DB-less instance with `OPA_URL` set is a
  pure OPA-AuthZEN gateway.
- **One daemon, one image.** The separate `authzen-direct` / `authzen-opa`
  services are collapsed into pgauthzd profiles; reader/writer separation is a
  deployment topology (a `decision-only` reader instance + a `full` writer
  instance), not a per-process split.
- **OPA is opt-in; the default stack is OPA-free**
  ([ADR 0008](docs/adr/0008-opa-is-opt-in.md)). pgauthzd answers
  `/access/v1` and `/pgauthz/v1` directly from PostgreSQL (with conditions for
  ABAC); OPA + the OPA-fronted pgauthzd gateway are an opt-in overlay:
  `./start.sh --opa` (or `PGAUTHZ_OPA=1`) for compose, `authzen.opa.enabled`
  (default `false`) for Helm. The `--keycloak` / `--playground` overlays imply it.
  Fronting OPA stays the orthogonal `OPA_URL` flag; this only flips the DEFAULT
  from on to off. One fewer moving part, one JWT validation, lower latency by
  default; policy-as-code Rego remains a first-class opt-in.
- Helm: the ingress front door routes to pgauthzd (not OPA); OPA's NetworkPolicy
  is tightened to gateway-only. The `examples/keycloak` demo now routes through
  pgauthzd (AuthZEN) via the gateway instead of hitting OPA's data API directly.
- Docs: the inline ADRs in `docs/ARCHITECTURE.md` §9 are consolidated into the
  `docs/adr/` log (ADRs 0002–0008); §9 is now an index into that log.

### Removed

- **PostgREST — removed from the project entirely.** Every read and write path,
  and every deployment (compose, scaling, Helm), uses the native pgauthzd
  callback. There is no PostgREST fallback.
- **PostgREST role/hook residue:** the `authz_authenticator` LOGIN role, the
  `api_anon` role (folded into `authz_reader` — there is no anonymous tier; every
  request is JWT-validated), and the `authz._pre_request` / `_pre_request_reader`
  db-pre-request hooks. pgauthzd now validates the per-app DB role (member of
  `authz_reader`/`authz_writer`, not admin) and applies `SET LOCAL ROLE` +
  the consistency mode itself in Go.

### Added

- **Native `/pgauthz/v1` API:** `check`, `check-batch`, `list-objects`,
  `list-subjects`, `list-actions`, `explain`, `watch`, and the write endpoints —
  plus their `/stores/{store}/…` tenant variants.
- **OPA callback listener** (service-token auth, optional mTLS `RequireAndVerify`
  client cert) — the native surface an OPA sidecar calls back into, kept off the
  public listener.
- **Multi-issuer JWT validation** (`JWT_ISSUERS` JSON array) with per-issuer
  store and DB-role bindings.
- `authz_watcher` — a dedicated read-only login role (granted `authz_auditor`)
  for the `examples/watch` changefeed consumer, replacing the bootstrap superuser.

### Fixed

- **Per-write consistency now fails closed.** An unknown/misspelled consistency
  mode is rejected (400) instead of being silently ignored (which downgraded the
  durability guarantee) — restoring the behavior the removed SQL hook enforced.
- `pgauthzd-opa` now carries `restart: unless-stopped`, so on a fresh database it
  crash-loops until roles are ready (like the reader/writer) instead of exiting
  and breaking `up --wait`.

## [0.7.3] - 2026-07-05

### Fixed

- **`check_access_detailed` `conditional` is now compositional** (review #4
  P0). Previously `state` aggregated missing condition-context keys across the
  whole trace, so an intersection/exclusion with a structural deny the context
  could not repair (e.g. `A AND B` with A conditional-on-missing and B a hard
  deny) was mis-reported as `conditional`. It now confirms `conditional` with
  a second **optimistic** evaluation (conditions failing solely for missing
  context treated as passing): a decision is `conditional` only when supplying
  the missing context could actually flip DENY→ALLOW, else `deny`. `allow`
  still fires only on the real boolean, so no authorization was ever wrong.
  8 truth-table tests across OR/AND/EXCLUSION.

## [0.7.2] - 2026-07-05

### Fixed

- **Live expiry now judged per statement, not per transaction** (migration
  0007; review 2026-07-05). The expiry RLS policy compared `expires_at`
  against `now()`, which in PostgreSQL is transaction-start time — so a
  long-lived direct-SQL transaction could keep seeing a tuple after its
  wall-clock expiry (the request-per-transaction front door was unaffected).
  It now uses `statement_timestamp()`, so every check/search re-evaluates
  expiry at its own start, matching the documented "stops granting the moment
  expiry passes". Regression-tested.

### Documentation

- **Re-granting a tuple without `expires_at` clears its expiry** (makes it
  permanent) — documented as a footgun for generic sync/upsert code, which
  should pass `expires_at` explicitly or read-modify-write.

## [0.7.1] - 2026-07-05

### Security

- **Fixed a fail-open in tuple expiry (SECURITY-AUDIT F11), migration 0006.**
  The v0.7 expiry enforcement hid expired tuples with a row-level-security
  policy whose write-side escape was a **caller-settable GUC**
  (`authz.tuples_include_expired`). Because expiry is read inside the
  `SECURITY DEFINER` functions app roles invoke, a **direct `authz_reader`
  SQL connection could set that GUC and make expired grants grant again**
  (not reachable through the OPA/PostgREST front door, which exposes RPC
  only — a direct-SQL trust-tier hole). The escape is now a dedicated
  `BYPASSRLS` role (`authz_rls_bypass`) that owns the `SECURITY DEFINER`
  helper functions performing the two operations that must see expired rows
  (reactivating upsert, cleanup); the SELECT policy has no GUC escape and is
  unbypassable by any caller value. `EXECUTE` on the helpers is granted only
  to `authz_owner` and no LOGIN role can reach the bypass role. Found and
  fixed in the v0.7 security-audit delta; verified closed (the reproduction
  now denies).

### Added

- **Signed release tags (SSH).** `release.sh` now creates signed tags
  (`git tag -s`) and refuses to tag unsigned, printing the one-time SSH
  signing setup if missing; `RELEASING.md` documents the flow, the GitHub
  "Signing Key" upload for the Verified badge, and local `git tag -v`
  verification via an allowed-signers file. `.github/CODEOWNERS` marks the
  security-sensitive paths (engine roles/migrations, OPA policies + Helm
  copy, AuthZEN token/issuer code, CI/release machinery) as review-gated —
  the supply-chain hardening "first slice".

## [0.7.0] - 2026-07-05

### Fixed

- **`list_objects` scanned every tuple partition of every store** — a
  partition-count scaling defect present since the beginning, uncovered by
  the expiry benchmark A/B. The reachability expansion's subject-rooted
  scans left the partition key (`object_type`) unconstrained, so each
  recursion iteration touched all tuple partitions in the database (168
  from just 3 stores in the dev DB; linear in tenant count for
  store-per-tenant deployments). The scans now carry a tautological
  `object_type IN (this store's types)` predicate that the executor turns
  into startup-time partition pruning: sparse `list_objects` 133.9 → 4.6
  ms/op (raw expansion 94.6 → 0.8 ms) on the 168-partition database.
  Check paths are object-rooted and were never affected.

### Added

- **Native relationship expiration: `tuples.expires_at`** (migration `0005`; review #3 priority 4). Grants can carry a server-time expiry:
  the moment it passes, the tuple stops granting on **every** check and
  search path. Enforcement is structural — row-level security on
  `authz.tuples` (FORCEd onto the engine's definer functions) hides expired
  rows from every read, so a missed filter in any of the ~37 tuple-scan
  sites is unrepresentable; caller-supplied context has no influence.
  Write paths: `write_tuple(p_expires_at)` and `"expires_at"` in the jsonb
  batch/`write_tuples_checked` tuples (flows through the OPA write API);
  re-granting an expired tuple reactivates it; a batch re-grant makes it
  permanent; granting an already-expired tuple is rejected up front.
  `cleanup_expired_tuples(store, grace)` garbage-collects (audited);
  offboarding removes expired grants too. Time-travel judges expiry **as of
  the asked time** — a grant that expired at T still shows allowed for
  p_at < T, even after cleanup deleted the row. Conditions remain the tool
  for complex time windows; this is the simple case without CEL/SQL.
  Measured overhead of the RLS enforcement: ~+10% on checks, up to ~+50% on
  large `list_*` scans (see BENCHMARKS.md addendum). 16 SQL tests.

- **Rich decision results (opt-in): which KIND of "no"** (review #3
  priority 3). New engine function `authz.check_access_detailed` classifies
  a decision — `state: allow | deny | conditional` — plus the missing
  condition-context keys (namespaced `request.*`/`stored.*`), the conditions
  that lacked input, the explain reason, and the registry model version for
  managed stores. `conditional` distinguishes "denied because required
  context was not supplied" (recoverable: supply it / step up and re-check)
  from a genuine deny; the boolean APIs keep collapsing it to deny (fail
  closed, unchanged). Exposed as the OPA rule `authz/allow_detailed`
  (allowlisted in system_authz; uncached by design) and on both AuthZEN
  services via the `X-PGAuthz-Detail` request header, which populates the
  AuthZEN response `context` field. Runs the explain machinery — a
  per-decision opt-in, not a hot-path default. 10 SQL tests + e2e on OPA and
  both AuthZEN services; demo walkthrough section 9g.

- **`pgauthzctl` — model-as-code toolchain** (new top-level Go CLI; review #3's
  top item). Author models as **verbatim OpenFGA DSL** (`.fga`) in git,
  parsed with the official `openfga/language` transformer — no new DSL —
  and piped into the existing `import_openfga_model`. Verbs:
  `model import | publish | plan | diff | apply | export | status |
  versions | rollout | test`. `publish` turns a git file into the next
  immutable registry version; `plan` exits non-zero on blockers
  (CI-gateable); `apply --plan-first` refuses blocked rollouts;
  `model test` runs YAML fixtures (a **superset of OpenFGA's store-test
  format** — existing OpenFGA tests port directly) against a hermetic
  ephemeral store, with pgauthz extensions (condition `context`,
  `contextual_tuples`, golden `explain` reason paths) and `--junit` output.
  DSL `condition` blocks are parsed but not imported (OpenFGA CEL and
  pgauthz CEL vocabularies differ) — pgauthzctl prints a
  `create_condition_cel` scaffold per condition instead. Own Go module
  (keeps the ANTLR dependency tree out of the services); integration suite
  `tests/test-pgauthzctl.sh` wired into `test-all.sh`, CI, and
  `pre-release.sh`.

- **`plan_model_apply`: dry-run for model rollouts** (review #2 priority 2).
  Read-only report of what `apply_model` would do to a store: per-section
  changes (types add/update, relations add/remove, rules, type restrictions,
  conditions add/update/remove), the exact blockers that would make the apply
  raise (`extra_type`, `relation_referenced_by_tuples` with the tuple count,
  `cel_evaluator_missing`), `no_op`/`can_apply` verdicts, the store's current
  managed state, and **rollback feasibility** — whether the currently
  recorded version could be re-applied afterwards (a version that adds types
  cannot be rolled back, since types are never removed automatically). Diffs
  the same canonical name-based exports the checksums hash, so the plan
  agrees with `model_status` by construction; reader-callable so pipelines
  can gate rollouts without admin credentials. 7 new SQL tests; usage +
  example in MODEL_DESIGN §16.

- **Per-request decision-cache bypass.** Read requests may set
  `"no_cache": true` on the OPA input to force a 0-second cache TTL for that
  decision — the escape hatch for revocation-sensitive checks that must see a
  just-committed change inside the normal TTL window. AuthZEN callers request
  the same with the standard **`Cache-Control: no-cache`** header, which
  `authzen-opa` maps to `input.no_cache` (headers cannot reach OPA policy
  input, so the body field is the mechanism at the OPA hop; `authzen-direct`
  has no decision cache and is fresh by construction). Applies to every
  cached read call (check, batch, list, explain); e2e-tested on both hops (a
  revoke is visible through the bypass immediately after a cached allow).
  Not a DoS vector: unauthenticated callers never reach PostgreSQL, and
  cache-busting by varying the object id was already free. PRODUCTION.md now
  states the end-to-end staleness bound explicitly: replication staleness
  (zero on the synchronous set with `remote_apply`) + the decision-cache TTL.

### Documentation

- **Model rollout guidance** (MODEL_DESIGN §16 + `apply_model` fleet-variant
  comment): the fleet apply is one atomic transaction — right for small
  fleets, wrong for hundreds of stores (use an external orchestrator with
  bounded batches, a pinned version, and `model_rollout_status` as the
  progress/retry view); and "rolling back is a forward operation" — immutable
  versions re-apply under the same guard rails, so plan model evolution as
  expand → migrate → contract.

## [0.6.0] - 2026-07-05

### Added

- **Per-app namespace isolation on READS over OPA (slice B).** The OPA read
  path now gets the same database-enforced per-application isolation the
  write path has had: OPA forwards the caller's per-app DB role as
  `X-PGAuthz-Role` on every PostgREST read call, and the reader's new
  `PGRST_DB_PRE_REQUEST` hook (`authz._pre_request_reader`) validates it —
  member of `authz_reader`, **not** admin-capable, fail closed — and
  `SET LOCAL ROLE`s to it, so the engine's read-side namespace checks key on
  the calling application instead of the fixed `api_anon`. Role source
  mirrors subject trust: verified token claim (`authn.db_role`) in token
  mode, `input.db_role` only in trusted-PEP mode
  (`REQUIRE_TOKEN_FOR_READS=false`). `authzen-opa` derives the role like
  `authzen-direct` (claim → issuer map → global map, validated against the
  issuer's `db_roles` binding) and forwards it as `input.db_role` — both
  AuthZEN services now provide equivalent read-side isolation. The role
  header is part of OPA's `http.send` cache key, so cached read decisions
  are partitioned per role. No role configured → reads stay `api_anon`
  (unchanged). E2E-tested in test-opa.sh (namespaced type: denied without
  role / allowed with grant / admin rejected) + 7 SQL hook tests.

- **Model registry: named, versioned models shared across stores** (migration
  `0004` + `db/engine/model_registry.sql`). Multi-tenant pattern: one store
  per tenant (tuples isolated by construction), one common model rolled out
  per store. `authz.export_model` renders a store's live model as a
  canonical, name-based JSONB definition (types incl. namespace/labels,
  relations, rules, type restrictions, conditions — not tuples, not
  namespace role grants); `authz.publish_model` snapshots it into the
  registry as the next immutable version of a named model (republishing an
  unchanged model is a no-op); `authz.apply_model` makes a target store's
  live model match a registry version — exact diff via the existing model
  API (validation + `models_audit` time-travel stay engaged), self-verified
  by checksum after apply, with strict guards: types are never removed
  automatically, and a stale relation still referenced by tuples aborts the
  apply instead of silently orphaning them. A fleet variant applies one
  resolved version to a list of stores. Drift detection: `authz.model_status`
  (per store) and `authz.model_rollout_status` (per model) compare the live
  model's checksum against the applied registry version — hash-partition
  layout (`hash_modulus`) is excluded from checksums, so per-tenant partition
  sizing does not read as drift. `authz.list_model_versions` lists the
  registry.

- **AuthZEN: issuer binding enforcement flags.** `REQUIRE_STORE_BINDING=true`
  refuses startup unless every trusted issuer carries a `stores` binding;
  `REQUIRE_DB_ROLE_BINDING=true` does the same for `db_roles`/`client_db_roles`
  when per-app role derivation is configured — an unbound issuer means
  unrestricted store/role access, so multi-tenant deployments should set both.
  With the flags off (default, legacy-compatible), the services now log a
  startup **warning** per unbound issuer whenever several issuers are trusted.

### Changed

- **`WRITER_DB_ROLE_CLAIM` renamed to `DB_ROLE_CLAIM`** (OPA service env,
  Helm value `opa.dbRoleClaim`): the same claim now drives the role switch
  on both the write and the read path.
- **AuthZEN (direct): per-app DB role validation results are now cached with a
  TTL** (`DB_ROLE_CACHE_TTL_SECONDS`, default 60; `0` = re-validate every
  request) instead of indefinitely — dropping a role or revoking its
  `authz_reader` membership takes effect within the window, not at the next
  service restart.
- `scripts/pre-release.sh` now fails if the Helm chart's OPA policy copy
  (`deploy/helm/pgauthz/files/opa/policies`) drifts from `opa/policies`
  (it had drifted silently); the copy is re-synced in this change.

### Documentation

- **Security self-audit refreshed** (`docs/SECURITY-AUDIT.md`) for the v0.6
  surface: AuthZEN multi-issuer routing + store/role bindings, the two new
  role-switch hooks (writer + reader), token forwarding and the trusted-PEP
  `input.db_role` path, per-role OPA cache partitioning, and the model registry
  as a cross-store propagation path; playground reviewed as a dev-only tool.
  No High/Critical code findings; four new Info/Low findings (F7–F10) accepted
  with operational controls, plus expanded operational-risk and hardening
  checklists.
- **AuthZEN isolation parity documented** (authzen/README.md + PRODUCTION.md
  checklist): the interim callout that `authzen-opa` lacked database-enforced
  per-application namespace isolation was superseded *within this release* by
  slice B (see Added) — the docs now describe the symmetric setup: both
  services enforce read-side isolation, with `DB_ROLE_CLAIM` configured on the
  OPA service for the token-mode role source.

## [0.5.0] - 2026-07-04

### Added

- **AuthZEN: store selection via URL path.** Every `access/v1` endpoint (and
  the discovery document) is also served store-scoped under
  `/stores/{store}/…` (OpenFGA-style), so each pgauthz store presents as its
  own AuthZEN PDP. Resolution order: path → `X-PGAuthz-Store` header →
  `DEFAULT_STORE`.
- **AuthZEN: per-app namespace enforcement (authzen-direct).** The direct
  backend can derive a per-app DB role from the verified token —
  `DB_ROLE_CLAIM` (dot-path, mirrors the writer's `WRITER_DB_ROLE_CLAIM`) or
  the `CLIENT_DB_ROLES` map keyed by client id (`azp`) — and assume it per
  request (`SET LOCAL ROLE` in a transaction, validated: member of
  `authz_reader`, not admin-capable, fail closed). pgauthz namespace
  restrictions then apply per calling application on the read path.
  authzen-opa (OPA→PostgREST reads) is documented follow-up work.
  **Per-issuer role binding:** `JWT_ISSUERS` entries gain `db_roles`
  (anchored regex patterns) restricting which roles that issuer's tokens may
  yield — without it, any trusted issuer could claim another tenant's role;
  violations are rejected (403), never downgraded. Plus issuer-scoped
  `client_db_roles` maps (azp is only unique within an issuer, so the global
  `CLIENT_DB_ROLES` map is unsafe across tenants).
- **AuthZEN: per-issuer store binding.** `JWT_ISSUERS` entries gain a `stores`
  list of **anchored regex patterns** (plain names match exactly,
  `tenant-a-.*` covers families): tokens from that issuer may only access
  matching stores (403 otherwise) — multi-tenant isolation where each
  tenant's IdP is bound to its stores. Issuers without a list stay
  unrestricted.

- **Multi-AZ reference configuration.** PRODUCTION.md gains a concrete
  single-region/3-AZ Helm setup (all-serving synchronous standbys — the
  serving ⊆ sync-set invariant holds by construction, lagging replicas
  block visibly instead of serving stale allows — zone anti-affinity,
  per-write modes, failure drill); the chart gains a `database.affinity`
  passthrough (CNPG `.spec.affinity`) for zone spreading. Plus a
  **two-node datacenter variant** with an operator-driven promotion
  runbook (fence-first, clear the sync requirement, rejoin via
  pg_rewind/basebackup) and the monitoring signals that map to it.
- **Strict revocation: the write path commits with `remote_apply`.** The
  OPA-fronted writer's connection now sets `synchronous_commit = remote_apply`
  (compose + Helm `postgrestWriter.synchronousCommit`): with synchronous
  standbys configured, a grant/revoke is only acknowledged once every
  synchronous replica has **applied** it — after the ack no replica in the
  set can serve a stale allow (the "new-enemy" window). A no-op without
  synchronous standbys, so all existing deployments are unaffected. The
  serving(-ro) ⊆ synchronous-set invariant, blocking semantics, and the
  client-cancel caveat are documented in PRODUCTION.md → Strict revocation;
  regression-tested in the scaling suite (revoke ack → immediate replica
  check must deny, 10× cycles). **Per-write consistency modes:** the write
  API accepts `consistency: applied | durable | eventual` (forwarded as
  `X-PGAuthz-Consistency`; the writer's `_pre_request()` maps it to a
  transaction-local `synchronous_commit`, failing closed on unknown values) —
  the connection default is the policy, individual writes opt up or down;
  direct-SQL callers use `SET LOCAL synchronous_commit` in their own
  transaction.

### Changed

- **PostgREST v14.13 → v14.14.** Maintenance release (admin server now logs
  the cause of failures); no breaking changes. Verified against the full OPA
  (52) and AuthZEN (42) integration suites.
- **OPA 1.17.1 → 1.18.2.** The only 1.18 breaking change (outbound
  `User-Agent` header format, RFC 9110) doesn't affect this stack; no changes
  to `http.send` caching, the data API, or Rego evaluation we rely on.
  Policies parse clean under 1.18.2 (`opa check`); verified against the full
  OPA (52) and AuthZEN (42) integration suites.

## [0.4.0] - 2026-07-02

### Added

- **`explain_access` now reports the exact granting tuple.** Each granting-tuple
  step gains a `matched_tuple` field — the stored tuple that satisfied it, as
  `subject → relation → object` with `*` wildcards resolved (so an object-wildcard
  grant shows `user:* → can_read_user → user:*`, not the queried ids). Redacted in
  safety mode. The playground's resolution tree renders it. No API break (additive).
- **`todo` example model (AuthZEN interop).** A pgauthz port of the OpenFGA
  [authzen-interop todo model](https://github.com/openfga/authzen-interop/tree/main/todo):
  list/item roles, ownership, TTU, wildcards (incl. a pgauthz **object wildcard**
  making every profile world-readable in one tuple), and an **intersection** —
  deleting/updating an item needs management rights on the parent list *and*
  ownership (so a viewer who owns an item still can't delete it), while
  `admin`/`evil_genius` on the parent bypass ownership. The interop's test-only
  "evil_genius" user is modeled with a **contextual tuple**, as the suite does.
  Ships with `model.sql`, `seed.sql`, `demo.sql`, and a `tests.sql` derived from the interop
  `.fga.yaml` assertions (wired into `tests/test.sh`).
- **AuthZEN console in the playground.** A second perspective — global
  `Access Explorer` | `AuthZEN` tabs — that drives the real `authzen-opa` service
  through the BFF (the session token is injected server-side; the SPA never sees
  it). An endpoint picker (evaluation, evaluations, subject/resource/action search,
  discovery), a **templated request** built from the shared subject/action/resource
  fields, and a response pane. The JSON editors gained a **Format** button, a
  read-only highlighted mode (used for responses), and now fill their pane.
- **Multi-issuer AuthZEN service.** `authzen-opa` can trust several JWT issuers at
  once via `JWT_ISSUERS` (a JSON list of `{issuer, audience, jwks_url|jwks_file}`);
  the token's `iss` selects that issuer's JWKS validator. The legacy single-issuer
  env vars still work (as one issuer). Lets one instance serve demo-issuer tokens
  (tests) and Keycloak tokens (playground) side by side.
- **Role-gated reverse search.** The AuthZEN search endpoints
  (`search/subject|resource|action`) enumerate the access graph, so they can now
  require a role: `SEARCH_REQUIRED_ROLE` (+ `JWT_ROLES_CLAIM` for the claim paths,
  aggregated like OPA's). A new Keycloak `authzen_auditor` realm role (granted to
  alice) gates them in the playground, which disables the search tabs for users
  without it (`/api/me` → `search_enabled`). Off by default (search stays open).
- **Folder support in the demo model.** A nestable `folder` type: `parent` for
  nesting, `viewer`/`editor`/`owner` grants, `can_share` (owner *or* editor), and
  recursive `can_view`/`can_edit`/`can_manage_access from parent`; documents gain an
  additive `parent_folder`, so a grant on a folder inherits **down** through
  subfolders to the documents inside. A new [`docs/MODEL_DESIGN.md` §14 — Recursive
  Hierarchies](docs/MODEL_DESIGN.md) covers the pattern in depth: stable IDs, which
  folders to store (mirror the tree vs. contextual tuples vs. app-resolved
  ancestors), single-check recursion, and cheap subtree moves via
  `write_tuples_checked`.
- **AuthZEN token-forwarding to OPA.** `authzen-opa` can forward the verified bearer
  token to OPA (`FORWARD_TOKEN_TO_OPA`) so OPA re-validates it via `input.token`
  instead of trusting a forwarded subject — letting OPA run in the secure
  `REQUIRE_TOKEN_FOR_READS=true` mode (no tokenless subject-trust), enabled for the
  playground. Off by default; trusted-PEP deployments that check arbitrary subjects
  on behalf of others keep subject-forwarding.
- **Playground: Model Explorer perspective + model-driven type graph.** The UI now
  groups into three perspectives — **Model Explorer** (model DSL + type graph),
  **Access Explorer** (query + resolution path), and **AuthZEN**. The type graph can
  render the model's **declared type restrictions** (all direct relations, matching
  the DSL) or the **tuple-observed** edges, via a model/data toggle, with a legend
  distinguishing direct (`[type]`) from userset (`[type#relation]`, dashed) edges.
  Zoom gained Ctrl/⌘-scroll and trackpad-pinch (about the cursor); hidden nodes are
  now excluded from the layout.

### Changed

- **The demo model declares explicit type restrictions.** Every direct relation now
  lists its assignable subject types (e.g. `define payroll_clerk: [internal_user,
  team#member]`) instead of accepting any type (`[any]`), matching how OpenFGA models
  must declare them. Write-enforced, so `describe_model` and the playground type
  graph now show the real schema. (Example-model change only; no engine change.)

### Fixed

- **Subject search over the OPA path returned no results in trusted-PEP mode.**
  `data.authz.accessible_subjects` reused the `_subject_valid` guard, which in
  no-token mode requires an `input.subject` that subject search doesn't carry — its
  subject is the *result*, not the caller. A dedicated `_subject_search_valid` guard
  authorizes the caller instead (valid token, or trusted PEP), so `authzen-opa`
  subject search now works. Token-mode callers were unaffected.

## [0.3.0] - 2026-07-01

### Added

- **Playground web UI ([`playground/`](playground/README.md)).** An
  OpenFGA-playground-style app to browse a store's model, tuples, and conditions
  and run access queries, then **visualize the `explain_access` resolution path**
  as a tree and an access graph — through the real OIDC → OPA → PostgREST → engine
  path, so the UI shows exactly what the engine decides. A Go backend-for-frontend
  (OIDC authorization-code + PKCE against Keycloak; tokens held server-side, single
  `ISSUER` discovery) plus a no-build Lit SPA, packaged as one self-contained
  container image served under `/playground`. Brought up with the
  `compose-playground.yml` overlay (or `start.sh --playground`). A trusted
  **admin/dev tool** — keep it access-restricted.
- **Advisory type labels.** Migration `0003_type_labels.sql` adds a
  `labels text[]` column (free-form `key:value`, GIN-indexed) to `authz.types` — a
  many-to-many logical grouping orthogonal to `namespace`, for tooling to cluster,
  filter, or hide types by domain. `model_register_type` gains an optional
  `p_labels`; new `model_{set,add,remove}_type_labels` manage them; the playground
  renders them as type-graph clusters.
- **Keycloak demo OIDC issuer ([`keycloak/`](keycloak/)).** Opt-in, realistic
  OIDC/OPA demo (Terraform-provisioned realm and clients, nginx TLS proxy) used by
  the playground and the OPA front-door examples.
- **OPA `explain` endpoint + `token_debug` diagnostics.** OPA now exposes the
  engine's `explain_access`, plus optional token diagnostics (keep off in
  production).
- **Time-boxed conditional grant in the demo seed.** A `non_expired_grant` SQL
  condition + a grant gated by it — a runnable ABAC example that fails closed
  without a request context.
- **Synchronous-replication / zero-RPO failover knob in the Helm chart.**
  CloudNativePG already does automatic write failover when
  `database.instances >= 2` (promotes a standby, repoints the `-rw` Service); the
  new `database.replication.synchronous` block lets a commit wait for a standby
  ack so an acknowledged grant/revoke is never lost on failover (RPO 0). Off by
  default (asynchronous); enable via the new
  [`values-ha.yaml`](deploy/helm/pgauthz/values-ha.yaml) overlay. A render-time
  guard fails the install if `maxSyncReplicas >= instances`. Documented in
  [`docs/PRODUCTION.md` → High availability & failover](docs/PRODUCTION.md) and
  the chart README, with a copy-paste **failover game-day runbook** (planned
  `cnpg promote` switchover + unplanned pod-kill + the single-node-k3d
  stuck-`Terminating` gotcha). `start.sh` gained an `HA=1` toggle (and
  multi-file `VALUES` layering) to deploy the synchronous overlay. The drill was
  validated live on k3d: auto-promotion, `-rw` repoint, and RPO 0 (a
  pre-failover acked write survived) all confirmed.
- **`deploy/helm/pgauthz/failover-test.sh`** — one-command game-day helper:
  `MODE=switchover` (default, graceful `cnpg promote`) or `MODE=failover`
  (pod-kill, auto-force-deletes a stuck-`Terminating` primary). Discovers the
  cluster/primary/standby, checks sync status, lays down a probe write, triggers
  the handover, and asserts RPO 0 (the probe survived) + write-path recovery on
  the new primary, then cleans up.

### Changed

- **Read-replica memo now fails fast at its cap instead of silently degrading.**
  `authz.memo_max_entries` defaults to **5000** (was unlimited), and when a check
  on the GUC (read-only/replica) backend would exceed it, `check_access` raises
  `memo_limit_exceeded` (SQLSTATE `53400`) rather than continuing un-memoized —
  silent degradation past the cap would reintroduce the ~quadratic re-work the
  memo prevents (raised in the external project review). Callers should catch it
  and **retry on the primary** (whose temp-table backend is uncapped). Set
  `authz.memo_max_entries = 0` to restore the old unlimited/no-abort behavior.
  The primary/temp-table path is unaffected. Test:
  `tests/sql/tests_readonly.sql` (`ro_08`/`ro_09`).

### Fixed

- Helm `Chart.yaml` `home:` pointed at the wrong repo (`…/authz-dev`); now
  `https://github.com/thomasdarimont/pgauthz`.
- **Fresh-install / CI init.** `db/security/roles.sql` still referenced the old
  five-argument `model_register_type`; realigned to the new six-argument signature
  (with `p_labels`) and granted the new label functions, so `init.sh` (and every CI
  job that runs it) no longer fails with `function … does not exist`.
- **Playground.** Backend HTTP errors now propagate to the UI instead of rendering
  empty/stale state; conditional **userset** grants receive the correct condition
  annotation (the lookup now includes `user_relation`); the decision and the
  resolution graph are derived from a **single `explain_access` result**, so they
  can no longer disagree (and it halves the work); access-graph nodes that differ by
  rule / condition / wildcard stay distinct instead of collapsing into one.
- **CI.** Fixed a flaky `test-scaling` streaming-replication test.

### Security

- **Playground hardening.** Explore mode (engine-direct, arbitrary-subject checks)
  is now gated behind `PLAYGROUND_EXPLORE_ENABLED` (off by default) plus an optional
  `PLAYGROUND_EXPLORE_ROLE` (a Keycloak realm/client role); the BFF's engine
  connection uses a dedicated least-privilege `authz_metadata` role (read-only
  metadata `SELECT` + `check`/`explain`/`describe_model`) instead of the engine
  superuser; the `write` OPA rule was removed from the BFF's allow-list (read-only);
  and the HTTP server now sets read/write/idle timeouts.

## [0.2.2] - 2026-06-29

### Added

- **`STORE_RETIRED` watch/changefeed event.** `retire_store` now records one
  store-lifecycle event (`action = 'STORE_RETIRED'`) in the audit log and fires
  the `authz_changes` doorbell, so watch consumers learn a store was retired and
  can invalidate everything for it. The event is store-wide: it bypasses the
  per-tuple object-type / namespace / relation filters, and `watch_changes` /
  `watch_cursor` now resolve retired stores (so a consumer can drain the
  changefeed's final events). Time-travel ignores it (the snapshot builders
  filter `action = 'INSERT'`).

### Changed

- **`retire_store` is now O(1), not O(tuples), in audit terms.** It previously
  ran `DELETE FROM authz.tuples` before dropping the live partitions purely to
  make the audit trigger record the removal — writing **one `tuples_audit` row
  per tuple**, a huge-transaction / WAL / replication-lag / partition-lock hazard
  for stores with millions of tuples (raised in the external project review).
  The redundant `DELETE` is gone: dropping the partitions (DDL) already removes
  the data, and a single `STORE_RETIRED` lifecycle event (+ the `deleted_at`
  marker) records the retirement once, regardless of tuple count. The time-travel
  evaluator (`_build_audit_snapshot`) treats a retired store as denying
  everything as of `>= deleted_at`, while the kept INSERT history still answers
  "could X do Y at time T `<` retirement?". Tradeoff: the audit log no longer
  holds a per-tuple deletion record at retirement — the lifecycle event replaces
  it; `audit_list_user`/`audit_list_object` still show the full INSERT history.

## [0.2.1] - 2026-06-29

### Added

- **`retire_store(store)` — soft-delete for audit retention.** Drops only a
  store's live tuples (reclaiming their partitions) and marks it retired
  (`stores.deleted_at`, migration `0002_store_retire.sql`), while keeping the
  dictionary (`types`/`relations`/`models`/`conditions`) and full audit log.
  The `audit_*` time-travel API still resolves a retired store **by name**, so
  preserved history stays queryable — closing the gap where `delete_store`
  removed the name dictionary and orphaned its own preserved audit rows (raised
  in the external project review). Live APIs reject a retired store and its name
  stays reserved; `delete_store` remains the explicit physical-removal/erasure
  path and can later purge a retired store.

### Changed

- `authz._s(name)` now resolves **live (non-retired) stores only**, so every
  live API rejects a retired store with a clear error; the `audit_*` functions
  opt into resolving retired stores. `delete_store` resolves retired stores too,
  so a retired store can be purged.

### Fixed

- **Memoization broke `check_access` on read replicas.** The per-check memo
  builds a session temp table, which cannot be created in a read-only
  transaction (a hot standby), so checks on a replica failed with `cannot
  execute CREATE TABLE in a read-only transaction`. On a read-only transaction
  the memo now switches to a session-GUC `jsonb` backend (the only mutable
  scratch a standby allows) instead of the temp table — so checks on replicas
  are both **correct and still protected** against converging/diamond graphs
  (the GUC backend is slower than the temp table but still polynomial). The
  fast temp-table backend is unchanged on the primary. The GUC payload (visited
  object ids + decisions) is cleared before the check returns (success or error)
  so it never lingers in the session, and `authz.memo_max_entries` (default
  `0` = unlimited) can hard-cap the map size; a check with thousands of distinct
  subproblems is slow on a replica regardless and should be routed to the
  primary (`statement_timeout` is the backstop). Time-travel
  (`audit_check_access`) is unaffected: it materializes its as-of state into
  temp tables, so it already requires a writable transaction and is primary-only.
  Regression test: `tests/sql/tests_readonly.sql`.
- Logical-replication demo (`db/replication/init-replication.sh`) hardcoded
  applying only `0001_baseline.sql`, so the new `0002_store_retire.sql` column
  (`stores.deleted_at`) was missing and every `authz._s()` call failed with
  `column "deleted_at" does not exist`. It now replays **all**
  `db/migrations/*.sql` in order, staying correct as future structural deltas
  land.

### Performance

- **Memoized the `check_access` evaluator** (and the time-travel
  `audit_check_access` twin): converging / diamond relationship graphs that
  re-evaluated a node once per path (`O(2^depth)`) are now collapsed to ~linear
  with a per-check memo that caches only path-independent (cycle-free)
  sub-results — identical decisions on every input, proven differentially in
  `tests/sql/tests_memoization.sql`. A depth-12 diamond DENY dropped from
  ~732 ms to ~1.9 ms (live) / ~1.6 s to ~6 ms (time-travel). Toggle with
  `SET authz.memoize = 'off'`.

## [0.2.0] - 2026-06-29

### ⚠️ Breaking

- **Widened all identifier columns from `smallint` to `integer`** — stores,
  types, relations, models, conditions, and every FK referencing them, including
  the `tuples` partition key `object_type` and the `_tuple_key` / `access_check`
  composite types. This lifts the previous **32,767** cumulative-ID ceiling
  (IDENTITY never reuses values) to ~**2.1 billion**, removing the practical limit
  for dynamic / multi-tenant deployments that create and delete many
  stores/types/relations over time (raised in the external project review).
- **No in-place upgrade from 0.1.x.** Because `tuples` is partitioned by
  `object_type`, a partition-key column type cannot be altered in place, so 0.2.0
  **re-baselines** the schema (`0001_baseline.sql`). Upgrading from a 0.1.x
  install is a **reinstall**, not a migration. (There are no production 0.1.x
  deployments; the `upgrade-test` CI job skips the pre-0.2.0 boundary and resumes
  for 0.2.x onward.) **Performance is unchanged** — verified A/B on one machine:
  integer ≡ smallint within run-to-run noise.

## [0.1.4] - 2026-06-29

Release-process tooling and docs (no engine changes).

### Added
- `docs/RELEASING.md` — a release runbook + pre-release checklist (the bump →
  notes → push → CI-green → tag flow, with the gotchas we've hit); linked from
  `CONTRIBUTING.md`.
- `scripts/release.sh` automation:
  - `--auto` — wait for the GitHub CI run on HEAD to pass, then tag and push
    (= `--wait-ci` + `--push` + `--strict-changelog`).
  - `--wait-ci` — block until CI is green before tagging, so a red commit is
    never tagged (needs the `gh` CLI).
  - `--strict-changelog` — fail instead of warn when the release notes are empty.
- `scripts/release.sh` now warns when the `## [X.Y.Z]` CHANGELOG section has no
  notes (empty-release-notes guard).

## [0.1.3] - 2026-06-29

### Added
- CI `scaling-test` job + `tests/test-scaling.sh` covering the streaming-
  replication (read-replica) demo: the standby streams the schema + data,
  resolves `check_access` on the read-only replica, and serves the
  OPA → PostgREST → replica read path.
- `-version` flag on the AuthZEN Go apps (`authzen-direct` / `authzen-opa`),
  stamped at build time via ldflags (tracks the image tag; `dev` for local
  builds). No HTTP endpoint.

### Fixed
- Streaming-replication scaling demo (`compose-scaling.yml`) was broken in four
  places:
  - `db/scaling/start-replica.sh`: the standby FATAL'd because
    `max_connections` (100) was below the primary's 250 — pin it to 250.
  - `env.sh` ignored the documented `COMPOSE_FILE=compose-scaling.yml ./init.sh`
    override and aborted under `set -e` on `ps -q authz-db` — honor
    `COMPOSE_FILE` and resolve `authz-db` or `authz-primary`.
  - `compose-scaling.yml`: OPA was missing the `REQUIRE_TOKEN_FOR_READS`
    mapping the base stack has, so it denied the documented tokenless demo read.

## [0.1.2] - 2026-06-29

### Added
- CI `replication-test` job + `tests/test-replication.sh` covering the logical-
  replication demo end to end: subscribers reach `ready`, the full replica
  resolves `check_access` on replicated data, the derived replica receives the
  flat `materialized_permissions` table, and a live write on the primary
  propagates.

### Fixed
- Logical-replication demo (`db/replication/`) was silently broken
  (`init-replication.sh` lacked `ON_ERROR_STOP`, so SQL errors left a broken
  setup but the script still exited 0). Four fixes:
  - `init-replication.sh` resolved `PG_DIR` to `db/db/...` after the script
    moved under `db/replication/` — point it at the repo root.
  - `setup-publication.sql`: `ALTER DEFAULT PRIVILEGES … GRANT SELECT` was
    missing `ON TABLES` (syntax error).
  - `setup-subscription.sql`: the metadata subscription copied data into tables
    the subscriber already populates by loading the model, causing duplicate-key
    crash-loops — use `copy_data = false` (stream changes only).
  - `materialized_permissions.sql` `_queue_permissions_refresh()`: an `INSERT`
    had three target columns but two expressions — add the missing `store_id`.

## [0.1.1] - 2026-06-29

### Added
- **Non-destructive in-place upgrade** — `upgrade.sh` (`SKIP_RESET=1 ./init.sh`)
  applies pending migrations and reloads the idempotent engine code without
  `DROP SCHEMA`, preserving stores/tuples/audit. The local analog of the
  CloudNativePG `deploy/migrations/run-migrations.sh` path.
- CI `upgrade-test` job: install the previous release tag, seed fixtures,
  upgrade in place to HEAD, and assert the data survived and access still
  resolves (ADR 0001 step 6).
- `scripts/bump-version.sh` — bump every pinned version reference and roll the
  CHANGELOG; pairs with `scripts/release.sh`.

### Fixed
- sqlx migration-ledger shadowing on re-runs / in-place upgrades: connecting as
  role `authz` let the baseline-created `authz` schema shadow the real
  `public._sqlx_migrations` via `search_path`, so sqlx treated the baseline as
  unapplied and tried to re-run it. Pin `search_path=public` on every sqlx
  connection (`env.sh`, `deploy/migrations/run-migrations.sh`,
  `scripts/gen-schema.sh`). Fresh installs and the CloudNativePG path (which
  connects as `postgres`) were unaffected.

## [0.1.0] - 2026-06-29

Initial tagged release: a PostgreSQL-native authorization engine implementing
Google Zanzibar / OpenFGA relationship-based access control (ReBAC) in pure
PL/pgSQL.

### Engine
- Recursive relationship resolution with union (OR), intersection (AND), and
  exclusion (BUT NOT) rule semantics; type restrictions and wildcards.
- Multi-store architecture — every operation scoped to a `store_id`.
- `check_access`, `list_objects` / `list_subjects` (search) with keyset
  pagination, and `explain_access` (decision trace + human-readable summary).
- Conditions / ABAC with a `lang` discriminator: `sql` built-in plus optional
  `cel` via the `pg_cel` extension; conditions evaluate in the zero-privilege
  `authz_eval` sandbox. Management API (`create_condition*` / `delete_condition`).
- Atomic, conditional writes with optimistic-concurrency preconditions
  (`write_tuples_checked`).
- Immutable, monthly-partitioned audit trail with time-travel queries and a
  cursored changefeed (`watch_changes` + `NOTIFY`).
- `describe_model` renders a stored model as OpenFGA-DSL text; OpenFGA JSON
  model/tuple import.

### Deployment
- Three-tier reference stack: PostgreSQL engine, PostgREST REST bridge, OPA as
  the single front door for reads and writes (JWT authn, policy-as-code).
- Go AuthZEN 1.0 API services: `authzen-direct` (Go→PostgreSQL) and
  `authzen-opa` (Go→OPA→PostgREST→PostgreSQL).
- Deployment profiles (substrate / read / write / audit) via a manifest;
  read-only install (`init-readonly.sh`) for an embedded engine fed by logical
  replication.
- Helm chart on CloudNativePG, with `extraRoles` for declarative app roles.
- Logical-replication and streaming-replication (read-replica) topologies.

### Schema management
- Forward-only structural migrations in `db/migrations/` applied by `sqlx-cli`
  and tracked in `public._sqlx_migrations`; idempotent engine code loaded after.
  Install and upgrade are the same non-destructive operation — no `DROP SCHEMA`
  (see [ADR 0001](docs/adr/0001-schema-migrations.md)).

### Requirements
- PostgreSQL 18.x (developed/tested on 18.4). PostgREST, OPA, the AuthZEN
  services, and `pg_cel` are optional components of the reference deployment.

[Unreleased]: https://github.com/thomasdarimont/pgauthz/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.7.3...v0.8.0
[0.7.3]: https://github.com/thomasdarimont/pgauthz/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/thomasdarimont/pgauthz/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/thomasdarimont/pgauthz/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/thomasdarimont/pgauthz/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/thomasdarimont/pgauthz/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/thomasdarimont/pgauthz/releases/tag/v0.1.0
