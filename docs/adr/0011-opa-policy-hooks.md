# ADR 0011 — OPA policy hooks (user veto rules in the standard pipeline)

- **Status:** Accepted (FROZEN) — amended across twenty-three 2026-07-07
  review and implementation rounds (see [Amendment history](#amendment-history))
- **Date:** 2026-07-07
- **Deciders:** maintainers
- **Relates to:** [0008](0008-opa-is-opt-in.md) (OPA is the opt-in policy
  sidecar these hooks live in), `opa/README.md` → Product-team policies (the
  neighboring extension models)

## Context

A benefit of running OPA as the policy sidecar is that users can put their own
policy **between** pgauthzd and the graph answer. Before this ADR the extension
story had two ends and a gap:

- **Beside** the pipeline: team packages (`app.dms`, …) that call the
  `authz.pgauthz` client library and expose their *own* decision endpoints —
  each needs its own `system_authz` allowlist entry, its own callers, its own
  pgauthzd wiring.
- **Replace** the pipeline: mount your own package and point `OPA_PACKAGE` at
  it — full control, full responsibility.
- **Missing:** extending the *standard* pipeline in place — "additionally
  require X for decisions/writes matching Y" — with zero pgauthzd config
  changes, zero allowlist edits, and composability across independent teams.

## Decision

A reserved, **versioned, two-tier** Rego namespace whose packages the platform
policy aggregates (`opa/policies/hooks.rego`):

- `authz.hooks.v1.global.<name>` — apply to **every** store (operator tier).
- `authz.hooks.v1.stores.<store>.<name>` — apply **only** when
  `input.store == <store>`. Keyed by a map lookup on the request's (validated,
  issuer-bound) store, so evaluation cost is **O(global hooks + target-store
  hooks)** per request — the aggregator only *invokes* the target store's hooks.
  The "every hook self-checks `input.store`" alternative can't give that (it
  evaluates all tenants' hooks every request). **True isolation is enforced by
  the validator, not by namespace selection alone:** a store hook could
  otherwise *reference* another store's package
  (`data.authz.hooks.v1.stores.other…`), a platform rule, or a dynamic
  `data[…]` lookup. `validate-hooks.sh` rejects any hook that references `data`
  outside its own package (and dynamic `data[var]`), so a store hook touches
  only `input` + its own rules + pure builtins + the **platform hook library**
  (`authz.hooks.lib.v1`, the single allowlisted shared namespace — see below)
  — it cannot read across tenants
  or into platform state, and the per-store pinning stops it authoring under
  another store (a cross-tenant DoS, since hooks only deny). Hook authors remain
  trusted code; the validator makes the isolation an *enforced* contract, not a
  convention.

**Store names are restricted to a Rego-safe identifier** —
`^[a-zA-Z_][a-zA-Z0-9_]*$`, ≤63 chars (migration 0008), **minus the Rego
reserved words** `as contains default else every false if import in not null
package some true with` and the root documents `input`/`data` (migration 0009,
case-sensitive like Rego) — identifier *syntax* alone isn't Rego-safe: keyword
segments parse inconsistently across Rego tooling (e.g.
`import data.…stores.if` is a syntax error even where the package declaration
parses). Both enforced by table CHECKs and `create_store`. So `<store>` is the
package segment **directly** — no hashing/encoding layer — and the namespace
stays readable. (This is why we restrict the name rather than derive a
canonical scope key.)

The hook **`<name>` segment follows the same rules as store names** —
identifier syntax, no Rego reserved words, ≤63 chars — enforced by
`validate-hooks.sh` (the namespace regex pins the syntax; the validator
rejects reserved names and over-length names explicitly).

Users add hooks by **mounting `.rego` files** — compose: volume onto
`/policies/hooks/global` or `/policies/hooks/stores/<store>`; Helm:
`opa.extraPoliciesConfigMap` (global) + `opa.storePoliciesConfigMaps.<store>`
(each per-tenant ConfigMap owned + validated separately).

### The hook contract (v1)

| Rule | Vetoes | Consulted by |
|---|---|---|
| `deny contains d` | a decision | `allow`, `allow_detailed`, `evaluations`, per-action filtering of `permitted_actions`, and — with `HOOK_FILTERED_ENUMERATION` — per-candidate filtering of `accessible_objects`/`accessible_subjects` |
| `deny_write contains d` | a write | `write` (every operation shape) |

- **Normalized input ABI, classified by trust source.** Hooks are evaluated
  `with input as` a versioned document (`api_version: pgauthz.hooks/v1`).
  Fields carry an implicit trust class a hook MUST respect for security gates:
  - **server-derived:** `api_version`, `operation`, `evaluated_at`,
    `deployment.environment`. `evaluated_at` (ns) is captured ONCE by pgauthzd
    and forwarded, so every batch item and every hook in a request sees the
    **same** timestamp — stable across pgauthzd's *internal* retries of one
    request (a fresh client retry gets a fresh timestamp). `deployment.
    environment` is the server-configured `DEPLOYMENT_ENVIRONMENT` — a short
    identifier (`^[a-zA-Z][a-zA-Z0-9_-]{0,31}$`), **validated at startup** (an
    invalid value fails `config.Load`, so a mistyped gate can't silently pass).
    **An unset environment is NOT fail-safe for veto gates** — a rule like
    `deny if input.deployment.environment == "production"` simply never fires
    on an empty value, i.e. it fails *open*. pgauthzd forwards the explicit
    sentinel **`"unknown"`** when unset (never `""`), which makes the
    unconfigured state *visible* — but visibility alone still relies on every
    author writing allowlist-style gates. So the guarantee is **enforced by a
    platform-level guard** in the aggregator: with any applicable hook loaded
    and `environment == "unknown"`, the platform itself injects the denial
    `{tier: "platform", hook: "environment_guard", code:
    "deployment_environment_unknown"}` into decisions AND writes — an unset
    `DEPLOYMENT_ENVIRONMENT` can never fail open, regardless of hook style.
    Explicit opt-out: `ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT=true`, ONLY for
    deployments whose hooks are genuinely environment-independent (see
    *Platform configuration flags* below for how flags reach Rego).
    (pgauthzd cannot require the variable "when hooks are enabled": hooks are
    mounted into OPA, invisible to pgauthzd config at startup — so the guard
    lives where the hooks are.) Environment-sensitive hooks should still be
    written allowlist-style. Time- and environment-gated hooks read these,
    **never** caller `context.*`.
  - **platform-derived:** `store`, `subject`, and **`actor`** — the
    authenticated caller, now on BOTH ABIs as `{id, roles}`. `actor.roles` is
    the platform-verified role set (`authn.roles`, aggregated from the
    configured `JWT_ROLES_CLAIM` paths — for Keycloak typically
    `realm_access.roles` plus an app client's `resource_access.<client>.roles`),
    empty without a valid token (trusted-PEP mode). By default all configured role claim
    paths share ONE flat namespace — a role aggregated from
    `realm_access.roles` is indistinguishable from the same string under
    another client's `resource_access.<client>.roles` — so either use
    globally unambiguous exemption role names and aggregate only the claim
    paths you need, or — the RECOMMENDED
    mechanism for client-scoped hook logic — read the **verbatim claim
    copies** under `actor.claims.<name>`: by default the Keycloak role
    structures `realm_access` and `resource_access`, same names and shapes as
    in the token (`ra := object.get(input.actor.claims, "resource_access",
    {}); some r in object.get(ra, "document-api", {}).roles; r == "admin"`).
    Client_ids stay map keys, so URI-shaped SAML entity IDs need no separator
    convention, and Keycloak's own token documentation applies unchanged;
    `claims` is `{}` without a token or when the selected claims are absent. The selection is **`HOOK_ACTOR_CLAIMS`** (default:
    `realm_access,resource_access`; setting it REPLACES the default) — the
    actor top level stays reserved for platform-DERIVED identity (`id`,
    `roles`), while `.claims` holds verbatim copies, so operator picks can
    never collide with reserved fields. Entries are top-level claim NAMES
    taken whole — never path-split, so namespaced OIDC claim names containing
    dots work; missing claims are absent, and hooks must treat absence as
    most-restrictive. Copied claims are platform-derived (the verified token)
    but visible to every applicable hook — select deliberately, avoid PII you
    don't need. For the WRITER GATE (which consumes the flat set),
    enable **`JWT_ROLES_SOURCE_PREFIX=true`**:
    roles are then emitted with their provenance — `realm::<role>` for realm
    roles, `<client_id>::<role>` for client roles — making
    `"document-api::admin"` and `"billing-api::admin"` distinct. The
    separator is `::` (not `.`) because client_ids may be URIs (SAML entity
    IDs), where a dot is ambiguous; `::` does not occur in URI
    scheme/host/path components. Opt-in because the flat aggregation is
    released behavior — enabling it changes every consumer of the role set
    (`WRITER_ROLE`, e.g. `authz-api::authz_writer`, and hook exemptions must
    switch to prefixed names in the same change). This enables
    **role-based exemptions** that stay veto-only: `not "auditor" in input.actor.roles`
    narrows a hook's own denial and can never grant what the graph denies —
    and it composes with filtered enumeration (an exempt caller's listings
    keep the ids the hook would otherwise hide). `actor` is deliberately
    distinct from `subject`: under `ALLOW_SUBJECT_OVERRIDE`, batch items, or
    candidate filtering, `subject` is who is being *checked*; `actor` stays
    who is *asking*. On writes it is distinct from the tuple subjects who
    *receive* the grant. **Compatibility:** the write-side `actor` has been an
    OBJECT (`{id}`) since its introduction (amendment 3) — adding `roles` to
    it, and adding `actor` to the decision ABI, are both additive within
    `pgauthz.hooks/v1`. (v1 has also never been externally released; it ships
    for the first time with this feature branch.)
  - **caller-supplied:** `action`, `resource`, `context` (decisions) /
    `tuple`/`tuples`/`writes`/`user` (writes).
  Bearer & service tokens and transport fields are structurally invisible.
  (A fuller `principal{issuer, client_id, roles}` split is a v2 ABI option; v1
  exposes `subject`/`actor` and `evaluated_at`, which cover the motivating
  cases.)
- **Structured, bounded denials.** A denial is a string (→ `code: "denied"`)
  or `{code, message}`; aggregation attaches a source descriptor
  `{tier, store?, hook}` that the value cannot override. `code` and `message`
  are capped (64 / 256 chars). Two truncation layers, both reported honestly:
  - **Per-hook cap (16):** each hook contributes at most 16 denials **to the
    diagnostic result**. This bounds the *output*, not the hook's internal
    evaluation work — a set rule may still generate all its denials before the
    aggregator slices; runtime is bounded by `OPA_REQUEST_TIMEOUT` and the
    pure-builtin capability set, not by this cap. `hook_output_truncated: true`
    flags that some hook hit its cap (so its raw output is *not* fully
    represented — the pre-cap total is deliberately not reported).
  - **Total cap (64):** the aggregate — sorted deterministically by
    `(tier, store, hook, code, message)` — is sliced to 64.
    `denials_truncated: true` + `denials_dropped: <n>` report the slice.
  So **`denial_count` is defined as the total number of denials *after* per-hook
  caps** (what the aggregator kept), never a claimed raw sum. Evaluation is
  bounded by `OPA_REQUEST_TIMEOUT` (review #9). The *fact* of a veto is what
  gates; the list + counts are diagnostic — availability bounds on trusted
  code, not a sandbox. Malformed denials are normalized defensively; making one
  a hard evaluation failure is a possible future tightening.
- **Denial disclosure is authorization-gated.** A veto's structured `denials`
  (hook identities + reasons — internal policy structure) are returned ONLY when
  the caller is authorized for detail (`X-PGAuthz-Detail`), for both the batch
  403 and the write veto: without it the response is just
  `{error: "denied_by_policy_hook"}`; with it, `{…, denials, denial_count}`.
  Same rule as `allow_detailed`.
- **Veto-only:** `allow` = graph answer AND no hook denial. A hook can narrow,
  never widen. (A widening hook, if ever wanted, must be a separate,
  explicitly-enabled mechanism.)
- **Per-item batch evaluation.** `/evaluations` evaluates decision hooks
  against **each graph-allowed item's** normalized single-decision ABI —
  evaluating only the top-level input would let a batch item slip past a
  per-item `deny`. Any denial rejects the **whole** batch → pgauthzd **403**
  `denied_by_policy_hook` (`PolicyHookDeniedError`); the per-item denials
  (each with `evaluation_index`) are included only under `X-PGAuthz-Detail`
  (see disclosure above). An all-false result would conflate graph denials,
  hook denials, and never-evaluated items. (Per-item *partial results* —
  allowing the un-vetoed items — remain deferred; per-item *evaluation* is
  required, as deferring it would be a batch bypass.)
- **`permitted_actions` is hook-filtered per action** (clients read it as
  "what can the user actually do" — advertising an action a hook will veto is
  misleading).
- **Enumeration with hooks: refuse by default, FILTER on opt-in (v1).**
  `accessible_objects`/`accessible_subjects` are **graph-derived supersets**
  that decision hooks do not filter: a hook-vetoed object would still be
  *listed*, leaking existence/confidentiality. So when any **applicable** hook
  is loaded — a **global** hook or a hook for the **requested store** (the
  refusal keys on `hooks_loaded`, which is store-scoped: tenant B's hooks never
  disable tenant A's enumeration) —
  those queries return `{"error": "enumeration_refused_with_hooks"}` → pgauthzd
  **403** with an actionable message — never a silently unfiltered list. The
  operator opts into superset semantics explicitly with
  `ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true` when hooks are
  advisory/time-gating rather than confidentiality rules (see *Platform
  configuration flags*). With no hooks loaded, enumeration is unchanged.

  **Per-candidate FILTERING is implemented** (`HOOK_FILTERED_ENUMERATION=true`,
  precedence over both refusal and the superset opt-out — and once filtering
  is *configured*, an inoperable state (env guard, malformed cap) **refuses
  even if the superset opt-out is also set**: a config error must not
  downgrade "listings match checks" to "listings leak hidden objects"): every candidate id
  is evaluated through the applicable decision hooks with the same ABI a
  per-object check would see (subject search substitutes the CANDIDATE
  subject, like a batch item), and denied candidates are dropped. Precisely:
  **every returned candidate passed the applicable hooks using the normalized
  input for that enumeration-page request** — same action, actor, context,
  `evaluated_at`, and policy revision. A later direct check with different
  context or time may legitimately differ, and **no snapshot consistency
  across pages is implied**. Guardrails: cost is O(candidates × applicable
  hooks), so a raw candidate set beyond `HOOK_FILTER_MAX_CANDIDATES`
  is **refused outright** (`enumeration_refused_too_many_candidates`;
  cap semantics: *missing* → 1000, *valid integer 1..100000* → that value,
  *malformed/out-of-range* → invalid configuration, filtering off ⇒ refusal —
  a real default for the common case, fail-closed for operator mistakes) — never partially filtered, since a truncated-but-filtered
  list would read as complete; filtering stays refused while the platform
  environment guard is active (the config-error state); and **pagination
  keeps raw keyset space**: pgauthzd peeks limit+1 on the raw page, so
  filtered pages return an explicit `{hook_filtered, ids, has_more, cursor}`
  protocol object where `has_more`/`cursor` come from the RAW page — a page
  that filters below the client limit does not end pagination, and short
  (even empty) pages with a next token are normal. The raw cursor is the last
  **consumed** candidate (never the limit+1 peek item) and may be an id the
  hooks deliberately hid — so pgauthzd **seals filtered cursors with AES-GCM**
  (`CURSOR_SEAL_KEY` — a comma-separated keyring like the freshness keys:
  first key mints, all accept, so rotation is prepend-roll-drop with no
  broken in-flight paginations): opaque, integrity-protected — **no direct
  disclosure of hook-hidden identifiers through pagination metadata** (the
  plaintext is padded to a 32-byte multiple, so the token length reveals only
  a coarse length bucket, not the id length). Cryptographic invariants:
  every cursor uses a fresh 96-bit nonce from the CSPRNG, generated
  independently of the raw key and query context (never derived, never
  repeated under a key); keys are KDF'd to exactly 32 bytes (AES-256 by
  construction) and keyring parsing rejects malformed values at startup
  (empty segments are an error, never silently skipped); the envelope carries
  `{format version, nonce, ciphertext, auth tag}` with the same version also
  bound into the AAD. The seal is **bound to the query
  context AND the caller** via AEAD additional-authenticated-data — payload:
  `{last_consumed_raw_key}`; AAD: `{cursor-format version, operation, store,
  actor.id, subject/resource query dimensions, action, canonical
  caller-context hash}`. The version component is the **cursor-format
  contract version** (`pgauthz-cursor-v1`) — NOT the pgauthzd release or the
  authorization-model version: bumping it deliberately invalidates all
  outstanding cursors when the binding layout changes, while deploys and
  model publishes leave in-flight paginations untouched (model drift between
  pages is the documented no-cross-page-snapshot case) — a cursor minted for one store/query/caller is
  rejected for any other (filtered results are actor-dependent through role
  exemptions, so actor A's cursor must not position actor B's pagination).
  The actor's ROLE SET is deliberately not bound: role changes between pages
  fall under the no-cross-page-snapshot semantics. The per-process key
  fallback (unset `CURSOR_SEAL_KEY`) is **development-only**: in production
  with filtered enumeration, a shared key is required — otherwise load
  balancing, restart, or failover turns valid cursors into 400s (an
  availability issue, not an authorization one). Enforcement boundary, stated
  honestly: pgauthzd cannot infer whether a deployment is production or
  multi-replica, so **the Helm chart refuses to render**
  `opa.hookFilteredEnumeration` without `authzen.opa.cursorSealKey`, while
  pgauthzd itself only warns at startup and falls back to the per-process
  development key. A cursor that fails to
  unseal (replica without the shared key, tampering) is a 400 — never
  interpreted as an id.
- **Attribution:** `allow_detailed` carries `hooks_loaded` — **the global and
  target-store hook packages *applicable to this request*** (not every module
  loaded into the OPA instance; other stores' hooks are structurally absent),
  named `<name>` for globals and `stores/<store>/<name>` for store hooks —
  plus `hook_denials`; the write veto carries `denials` + `hooks_loaded`. All of it rides pgauthzd's detail channel: **discarded** on
  the plain boolean path, **returned** under `X-PGAuthz-Detail` — hook
  identities do not leak through unauthorized channels.
- **Absent = inert:** with nothing mounted, behavior is **semantically
  identical** to pre-hook releases — no hook fields appear (the `hooks_loaded`
  attribution is added only when hooks are loaded), and every decision/result
  is the graph answer.

### Two trust tiers

Rego places modules by their **declared package**, not their mount path: a
mounted file could declare `package authz` and add an `allow` body (widening),
or claim another store's namespace. So the hook contract is enforced by
**tooling**, not a runtime sandbox — and the trust tier differs by hook tier:

- **Global hooks** (`authz.hooks.v1.global.*`) are authored at the
  **platform-policy trust tier**: an operator with the same reach as the
  platform Rego. Their mount is a platform-controlled artifact.
- **Store hooks** (`authz.hooks.v1.stores.<store>.*`) are the **delegated
  tenant-policy tier**: a tenant may own them, so they are constrained to the
  **normalized input ABI, their own package's rules, and the approved pure
  builtin set** (the hooks-v1 capability allowlist). The validator's isolation
  + capability checks make that boundary an *enforced* contract for a
  less-trusted author — not merely a convention among equally-trusted ones.

**`scripts/validate-hooks.sh` is the authoritative gate** (wired into
`pre-release.sh` and `test-opa.sh`; run it in CI / the bundle build):
`--global` pins a directory to `authz.hooks.v1.global.<name>`, `--store <s>`
to `authz.hooks.v1.stores.<s>.<name>`; both reject duplicate names,
platform-package definitions, any `data`/`input` **import** or `data` reference
outside the hook's own package or a dynamic `data[var]` (the isolation gate —
imports are checked too, since `import data.other as x` would otherwise surface
as `x.*` in the body and evade a body-only check), and **non-pure builtins** —
enforced by compiling against `opa/hooks-v1-capabilities.json`
(`opa check --capabilities`), a pinned allowlist of pure builtins
(http.send / io.* / opa.* / rego.* / net.lookup* / time.now_ns removed). That
makes the execution ABI **reproducible across OPA upgrades**: a future builtin
is disallowed until explicitly added. **All checks operate on the parsed Rego
AST** (`opa parse --format json` for imports/refs, `opa check` for
types/capabilities), never source text — so aliases and indirect references
can't slip past.

**`http.send` is a GLOBAL-hook option only.** `--allow-http` opts a
platform-governed *global* hook into `http.send`; it is **rejected for store
hooks** — delegated tenant hooks may never use network-capable builtins in v1
(no exfiltration, no external availability dependency, no calling another
tenant's service). A global hook that does use it is governed by **three
independent controls** (capabilities are a *build/check-time* validation —
`opa run` takes no capabilities file, so `allow_net` is NOT a runtime knob):

1. **Build-time — capabilities + AST validation.** `--allow-http` validates
   with `opa check` (and the bundle build with `opa build`) against
   `opa/hooks-v1-http-capabilities.json` — the pure set + `http.send` only,
   whose `allow_net` is a deny-all template (`[]`) the platform copies and
   fills with its approved hosts (`HOOK_HTTP_CAPABILITIES` points the
   validator at the copy). The validator **additionally rejects non-static
   destinations**: every `http.send` request must be a literal object with a
   literal string `url` — a computed or input-derived URL would make the
   checked allowlist meaningless (and is an exfiltration vector). Because the
   URLs are forced static, the validator **enforces the allowlist itself**:
   each destination host must be a member of the profile's `allow_net`
   (`opa check` alone does not inspect hosts — `allow_net` is otherwise
   evaluation-time, `opa eval/test --capabilities`). The request object is validated
   against an explicit **field allowlist** — only `url`, `method`, `headers`,
   `timeout`, `raise_error`, `enable_redirect`, `tls_insecure_skip_verify`,
   and `max_retry_attempts` are admitted; **every other field is rejected**,
   in particular ALL cross-query cache controls (`cache`, `force_cache`,
   `force_cache_duration_seconds`, `caching_mode`, `cache_ignored_headers`):
   network hooks execute **fresh on every decision** — a cached response
   would decide a later, different request. Unlisted future OPA options
   cannot enter the profile implicitly. The full **static request
   contract** (each admitted field absent or a safe literal; computed values
   rejected):
   `enable_redirect` must stay `false` (OPA's default — verified — so an
   approved literal URL can't bounce to an unapproved destination);
   `raise_error` must stay `true` (setting it `false` converts a failed call
   into a `status_code: 0` *response*, silently bypassing the
   `strict-builtin-errors` fail-closed guarantee); `tls_insecure_skip_verify`
   must stay `false`; and `timeout` must be a static non-zero bound (`0` =
   unbounded in the decision path).
2. **Supply chain — the validated policy ships as a signed immutable
   artifact** (see the bundle section), so what runs is what was checked.
3. **Runtime — network egress is enforced independently** of OPA:
   Kubernetes NetworkPolicy, an egress proxy, or equivalent firewall
   controls restrict the OPA pod to the platform callback hosts + the
   approved hook destinations. A blocked or failed `http.send` fails the
   request **closed** through `strict-builtin-errors=true`.

**A global hook using `http.send` MUST be deployed through the signed
immutable bundle/artifact path in production** — control (2) is part of its
guarantee, not an option. Mutable ConfigMap/`--watch` deployment is permitted
only for development, or for global hooks that use no network-capable
builtins.

**HTTP error responses are NOT builtin errors — declare a success-status
set and deny outside it.** `raise_error` + `strict-builtin-errors` cover
*transport and evaluation* failures; receiving a `404`/`429`/`500`/`503` is a
**successful** execution of `http.send` that returns an ordinary response
object. The common pattern `status_code == 200; body.restricted` is simply
*undefined* on a 503 and contributes no denial — it **fails open**. So: HTTP
responses outside an explicitly declared success-status set are policy
failures and MUST produce a denial (e.g. `external_policy_unavailable` on
`status_code != 200`, `external_policy_malformed` on a 200 without the
expected fields). Because tenant isolation forbids cross-package references,
this pattern cannot be a shared helper — it is **inlined per hook**;
`examples/opa-hooks-http/` ships the reference implementation with contract
tests for 404/429/500/503, malformed and missing response bodies, and the
aggregator veto path (transport failure and timeout raise builtin errors and
are already failed closed by `strict-builtin-errors`).

**Honest enforcement boundary: this contract is GOVERNANCE, not statics.**
Correct handling of HTTP status codes and response schemas is a semantic
code-review and contract-test requirement for platform-trusted global hooks —
it is **not statically guaranteed by `validate-hooks.sh`** (which enforces the
request shape only; it cannot prove a hook denies on a 503). That is
defensible because network hooks already sit at the platform-policy trust
tier, are rare, and must ship through the reviewed, signed bundle path with
their own contract tests (`examples/opa-hooks-http/` is the template). The
mechanically-enforced alternative — a platform-owned HTTP helper package that
alone may call `http.send`, with the validator allowing exactly that one
cross-package reference — was considered and deferred: the helper can
guarantee *status* fail-closed but not *schema* fail-closed (expected
response fields are hook-specific, so authors must still emit the malformed
denials), and it would buy that partial guarantee at the cost of an isolation
exception, a helper ABI, and per-hook schema configuration. If network hooks
proliferate, it is the natural v2 hardening.

**The v1 contract is read-only network lookup, not arbitrary HTTP** —
enforced by the same static validator: `method` must be the literal `GET` or
`HEAD`, `body`/`raw_body` must be absent, `max_retry_attempts` must be
`0`/absent (OPA gives `http.send` no exactly-once semantics — a retried
non-idempotent call could repeat a side effect), and a `Host` header is
rejected (it would divert the request from the allowlisted URL host at the
HTTP layer).

Per call: a **strict `timeout`** well under `OPA_REQUEST_TIMEOUT`
(`http.send` participates in the decision path — its latency is decision
latency). **Response size cannot be bounded from the request object** — stock
OPA `http.send` has no per-request response-size limit (no
`max_response_bytes` field exists) and returns the complete body, so an
oversized response inflates memory and decision logs; the approved endpoint
itself, or an enforcing egress proxy, must impose the bound. A future
store-hook network profile would additionally require egress allowlisting
and sandboxing.

**Enforcement in the deployment path matches these tiers:**

- **ConfigMap mount + `--watch`** (dev, or platform-trust *global* hooks): the
  Helm chart runs two `opa check` **initContainers** when any hook ConfigMap is
  set — one compiles each hook dir against the **capability allowlist**
  (`--capabilities`, so a non-pure builtin fails the pod, not just a syntax
  error), one type-checks the assembled `/policies` tree. This is a deploy-time
  backstop for syntax/type/**purity**; namespace/isolation/dup checks stay in
  the build-time `validate-hooks.sh`. Kubernetes resource identifiers are
  sanitized **independently** of the Rego namespace, and lossily-sanitized
  names alone would collide (`Foo` and `foo` → `foo`) or overflow the 63-char
  k8s limit (`store-hooks-` + a 63-char store name). The deterministic mapping
  is
  `store-hooks-<first 40 chars of lower/underscore-sanitized name>-<8-char sha256 of the raw name>`
  (12+40+1+8 = 61 ≤ 63; the hash disambiguates case/truncation collisions),
  while the **mount path keeps the exact store name**
  (`/policies/hooks/stores/<store>`) — the sanitized form never leaks into the
  package namespace or the ABI.
- **Delegated *store* hooks** (the isolation-critical case) **must** be
  delivered as a **signed, pre-validated immutable bundle**. The **v1 topology
  is a single platform-controlled bundle**:

  ```text
  every tenant's store-hook source
    → platform pipeline validates each dir (validate-hooks.sh --store <s>)
    → assembles ALL validated hooks into ONE bundle
    → signs it with a PLATFORM-owned key
    → OPA verifies that signature at load (--verification-key), atomically
  ```

  The **platform pipeline owns the signing key** — a tenant must never be able
  to sign an artifact that production OPA accepts (that would reintroduce the
  bypass the validator exists to prevent). **The pipeline signs the exact
  validated bundle *contents*: an OPA bundle signature covers the complete
  file set and each file's hash — not the literal compressed tarball bytes, so
  repacking identical contents remains valid. No policy-content transformation
  may occur after validation.** The bundle `.manifest` must declare an
  explicit **root scoped to exactly what the bundle owns** — a root defines
  the namespace the bundle owns and *overwrites on activation*. The store-hook
  bundle contains only delegated store hooks, so its root is the **stores
  subtree**, NOT `authz/hooks/v1`: the wider root also claims
  `authz/hooks/v1/global`, and activation would erase global hooks loaded
  separately from platform ConfigMaps. (Without any root OPA defaults to
  `[""]` — the *entire* namespace, conflicting with the platform policy.)

  ```json
  {
    "roots": ["authz/hooks/v1/stores"],
    "rego_version": 1,
    "revision": "<git-sha>",
    "metadata": {
      "hook_abi": "pgauthz.hooks/v1",
      "platform_policy_compatibility": "<version>"
    }
  }
  ```

  A production **global hook using `http.send`** must itself live in a
  signed artifact (its three-control guarantee includes one), so such a
  deployment uses either (a) the **combined** signed bundle rooted at
  `authz/hooks/v1` carrying both tiers, with *no* separately mounted hooks at
  all, or (b) a **separate signed global-hook bundle** rooted at
  `authz/hooks/v1/global` alongside the non-overlapping store bundle above.
  Pick one model per deployment, never a bundle root overlapping a mounted
  tree. Production OPA must reject
  **unsigned bundles**, **signatures from unknown keys**, and any **fallback
  to an unverified local hook directory** — verification failing must mean
  the hooks don't load, not that an unsigned path is used instead. `revision`
  ties decisions to the exact hook state. The `metadata` compatibility check
  has named owners: the **bundle publish pipeline** refuses to publish when
  `platform_policy_compatibility` does not match the target deployment's
  platform-policy version (pre-activation gate), and the **activation
  monitor** — the same status-watching that already tracks
  revision/last-known-good — alerts when the *active* bundle's metadata
  disagrees with the running platform (post-activation detection; stock OPA
  does not evaluate custom manifest metadata itself). Per-store bundle *roots* (a separate
  signed bundle per tenant) are a deferred refinement; v1 is the single
  assembled bundle. A **mutable ConfigMap under `--watch` is explicitly NOT an
  isolation boundary** for delegated tenants — a post-startup edit would bypass
  the build-time validation. Pin it: the signed bundle above, or
  `immutable: true` ConfigMaps + pod rollout, or admission validation on
  ConfigMap updates.

Review-gate the mount source (CODEOWNERS / the per-tenant ConfigMap or bundle
repo) like any policy change.

**Store rename implications.** The store name is now part of both the hook
package namespace (`authz.hooks.v1.stores.<store>`) and the ABI `store` field.
Renaming a store therefore orphans its store-scoped hooks (they must be
re-packaged under the new name) and changes the `store` value hooks see — treat
a store rename as a policy migration, not a cosmetic change.

### The platform hook library (`authz.hooks.lib.v1`)

Shared helper functions hooks may call — the ONE namespace besides its own
package a hook may reference (imports and refs allowlisted by the validator;
everything else stays rejected). Why this is not an isolation hole: the
library is **platform-owned** and ships/signs **with the platform policy**
(never tenant-mounted); it lives **outside the aggregated namespace**
(`authz.hooks.lib.v1`, not `authz.hooks.v1` — the aggregator never iterates
it, and the tier regex prevents a hook claiming it); and it contains **pure
functions over their arguments only** — no rules over request or tenant
state. Versioned like the input ABI: additive within v1, breaking changes
become `lib.v2`. The validator loads the library into its compile checks, so
a call to a nonexistent library function is a validation error, not a
runtime surprise. First module: `keycloak` —
`keycloak.has_realm_role(input.actor, role)`,
`keycloak.has_client_role(input.actor, client, role)`, plus the raw
`realm_roles`/`client_roles` accessors, all undefined-safe (absent claims
fail closed).

**Operator extension libraries** live under the reserved
`authz.hooks.lib.v1.ext.<name>` subtree — deployments add their own shared
helpers there (compose: mount into `/policies`; Helm:
`opa.extraLibsConfigMap`), validated by **`validate-hooks.sh --lib`**:
namespace pinned to `ext.*`, **functions only** (a plain rule would be
shared ambient state), pure builtins with **no `--allow-http` escape** — a
shared library with `http.send` would hand network access to every caller,
including network-free store hooks. Ext libs may compose the platform
modules (e.g. call `keycloak.*`); hooks reference them through the same
`authz.hooks.lib.v1` allowlist with zero validator changes. Since shared
code executes inside every consumer's evaluation, ext libraries are
**operator-trust tier** by construction — a tenant cannot mount one (store
ConfigMaps are pinned to the store namespace). `HOOK_EXTRA_LIBS=<dir>`
points the validator at ext libs when validating hooks that call them (a
call into an absent library fails compile). `examples/opa-hooks-lib/` is
the reference.

### Platform configuration flags

Rego has no ambient access to process environment variables; the two hook
flags (`ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT`,
`ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS`) are **set on the OPA deployment
environment and surfaced to policy exclusively through the platform
configuration module** (`authz.pgauthz.config`, via `opa.runtime().env` — the
established mechanism for this stack's OPA config, e.g. `DEFAULT_STORE`).
Two properties make this trusted configuration data rather than ambient
state: `opa.runtime` is **excluded from the hook capability set**, so hooks
cannot read the environment (or these flags) directly — they see only the
platform's decision; and the config module is platform policy, shipped and
signed with it. A deployment without process env (WASM, data-only bundles)
injects the same values as trusted data under the config package instead —
the aggregator reads `config.allow_*`, not the environment. The same
contract covers the enumeration-filtering flags: `HOOK_FILTERED_ENUMERATION`
(exact `"true"` enables, like the others) and `HOOK_FILTER_MAX_CANDIDATES`
(exact tri-state: **missing → 1000**; **valid integer 1..100000 → that
value**; **malformed/out-of-range → invalid configuration**, filtering OFF,
enumeration refuses — a real default for the common case, fail-closed for
operator mistakes, never a silently applied unexpected bound. OPA reads env
at query time, so "fail startup" isn't expressible; fail-closed-at-use is the
enforceable equivalent, regression-tested. Scope: the cap limits the raw
candidates evaluated by hooks in ONE enumeration request — the page, for
paginated queries — NOT the total result set across pages). Boolean parsing is **fail-closed by
construction**: the flag rules match exactly the string `"true"` — missing,
malformed, or any other value leaves the rule undefined, and every consumer
gates on `not config.allow_*` / requires the rule defined, so anything but an
exact `"true"` means the protection stays active (regression-tested).

### Failure semantics (stated honestly)

- **Startup load error** (bad syntax): OPA refuses to start → container fails
  → readiness fails.
- **Hot-reload (`--watch`) / bundle-activation error:** OPA keeps the
  **last-known-good** policy set and logs the error — the new revision is NOT
  active.

  The four signals do **not** overlap — don't conflate them:
  - **Deployment-time** compilation + `validate-hooks.sh` validate **all**
    hooks (every store package), before they can serve.
  - **Bundle activation status / revision** tells you the *intended* policy
    revision actually loaded.
  - **Deep readiness** (`callback_healthy`, review #8) proves only the
    OPA → native callback → PostgreSQL **connectivity** path — a single
    synthetic query **cannot** exercise every store-specific hook package, and
    is not claimed to.
  - **Runtime metrics** (`pgauthzd_opa_rego_eval_duration_seconds`,
    `opa_requests_total{result}`) surface *actual* hook failures/latency in
    production. A rising `error` rate is the live "a hook is failing" signal.
- **Runtime evaluation error — FAILS CLOSED on EVERY path.** `strict-builtin-
  errors=true` is applied at pgauthzd's single OPA-query chokepoint, so it
  covers **all** standard-pipeline rules — `allow`, `allow_detailed`,
  `evaluations` (batch), `write`, `permitted_actions`, and the deep-readiness
  query. The standard pipeline queries
  OPA with **`strict-builtin-errors=true`**, so a builtin error in a hook or
  platform rule (a type error, a bad `time.clock`, …) makes the *query* fail
  rather than silently making the affected expression undefined — a vanished
  `deny` must not fail open. **Any** OPA error, an unparseable/malformed OPA
  response, or a transport failure becomes `policy_evaluation_failed` (5xx) at
  pgauthzd — **no authorization result, no write, and it is never converted
  into `allow: false` or a normal graph denial**. This is safe because the
  client library's own `http.send` calls use `raise_error: false`, so expected
  downstream non-2xx responses stay handled and don't trip strict mode.
  Operators may not disable this for the standard pipeline.
  - Distinguish this from a genuinely **undefined** decision: `allow` being
    undefined resolves to `false` — that is the intended *default-deny*, a
    decision, not an error. An error never masquerades as that default-deny.
  Hooks should still be written defensively (`object.get`, type checks) so a
  bug is a caught operational error, not a request failure.

### Enforcement boundary

Hooks guard the **OPA-fronted pipeline only**. They do not constrain
direct-mode pgauthzd (no `OPA_URL`), the native API, or direct SQL. Hooks are
for request-time policy and ingress governance — invariants that must hold for
*every* mutation belong in checked writes, engine validation, or database
constraints.

### Caching

The decision cache sits on the client library's graph calls
(`http.send` `force_cache`), *below* hook evaluation — hooks run fresh on
every decision, so time-dependent hooks are correct without cache-key changes.
Keep it that way: never cache the hook-composed result without keying on the
policy revision.

## Consequences

- The `system_authz` allowlist remains the chokepoint for genuinely **new**
  API surface; hooks never require editing it.
- Testable against the real pipeline: `opa test opa/policies <hook-dir>`;
  `examples/opa-hooks/` ships two reference hooks + the contract suite
  (ABI/token-invisibility, structured attribution, no-widening,
  batch-rejection, per-action filtering, write shapes), wired into
  `test-opa.sh` together with the validator.
- The check-routing table in `opa/README.md` still applies: relationships →
  tuples; per-grant attributes → engine conditions; request-time business
  rules → hooks; coarse route gating → gateway.

## Deferred follow-ups (tracked, not blocking v1)

- ~~Enumeration confidentiality~~ — **SHIPPED in v1** (secure-by-default
  refusal, `ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS` opt-out; see Decision).
  ~~Full per-result filtering~~ — **also shipped** (amendment 17:
  `HOOK_FILTERED_ENUMERATION`, per-candidate evaluation with fail-closed cap
  + raw-keyset paginated protocol). Still open from the original item:
  surfacing `{result_semantics: "graph_derived_superset"}` on
  explicitly-opted-out unfiltered responses.
- **Hook observability.** Per-hook/-code veto counters, hook evaluation
  latency, and runtime-error counters; **policy/bundle revision as an
  observable field** in decision logs and readiness/activation metrics (so a
  decision can be tied to the exact hook revision that produced it). (The OPA
  request deadline already exists — `OPA_REQUEST_TIMEOUT`, review #9.) A
  maximum-hook-count budget enforced by the validator.
- **Malformed denial = hard failure.** Today a malformed denial value is
  normalized defensively; making it a `policy_evaluation_failed` instead
  (paired with a validator lint on `deny`/`deny_write` shapes) is a tightening.
- **Fuller principal ABI** (`principal{issuer, client_id, …}`) as a v2 ABI —
  partially delivered: verified `actor{id, roles}` is in the v1 ABI (additive);
  issuer/client_id remain v2.
- **Remote signed bundles** for fleet distribution (per-store bundle `roots`
  give a third isolation layer under the validator + veto-only).

## Alternatives considered

- **Editable platform files** — merge conflicts on upgrade, no composition.
- **Widening hooks** (`custom_allow`) — "mounted a file" must never mean
  "granted access the graph refused"; revisit only behind an explicit flag.
- **Raw `input` as the hook ABI** — couples hooks to transport details and
  leaks tokens; rejected in the amendment in favor of the versioned document.
- **All-false batch results on veto** — safe but misleading; replaced by the
  structured 403 rejection.
- **Bundle server / OPA management APIs** — the fleet-scale distribution
  path (signing, activation status, hot rollout); deliberate follow-up, works
  with the same namespace + validator.
- **Per-item *partial* batch results** — deferred. Hooks ARE evaluated per
  item (deferring that would be a batch bypass); what is deferred is returning
  the un-vetoed items — in v1 any per-item veto rejects the whole batch.
  `permitted_actions` got per-action filtering because action lists are small
  and clients treat the answer as authoritative.
- **Hashed store-scope keys** (`s_<sha256(store)>`) — considered so store names
  needn't be Rego-safe, but rejected in favor of **restricting store names** to
  an identifier charset (migration 0008): the store name is then the package
  segment directly, keeping the namespace readable and dropping an encoding
  layer. Both `store` and the raw name stay caller-legible.

## Amendment history

Twenty-three rounds on 2026-07-07 (external reviews + the implementation deliveries of the deferred enumeration filtering and its hardening), each amending this ADR (and the
implementation) in place:

(1) versioned namespace, normalized ABI, structured denials, batch rejection,
  `permitted_actions` filtering, validator, honest failure semantics;
  (2) two-tier store scoping, **per-item** batch hook evaluation, **fail-closed**
  runtime errors via `strict-builtin-errors`, server-derived `evaluated_at`
  with trust-source classification, mandatory validator;
  (3) store names restricted to a Rego-safe identifier (migration 0008 — the
  store IS the package segment, no scope-key hashing), `evaluated_at`
  **forwarded once by pgauthzd**, explicit write **`actor`** vs tuple subject,
  bounded denial code/count, enumeration-confidentiality guidance;
  (4) **validator-enforced tenant isolation** (no cross-package/dynamic `data`
  refs — the isolation claim is now true, not just structural), server-derived
  **`deployment.environment`**, hook-detail disclosure gated on
  `X-PGAuthz-Detail`, denial ordering + `denials_truncated`/`denial_count`,
  deploy-time `opa check` gate + sanitized Helm identifiers;
  (5) **two trust tiers** (global = platform, store = delegated tenant),
  capability-allowlist purity (`opa/hooks-v1-capabilities.json`, reproducible
  ABI) enforced in the validator + Helm initContainer, signed-bundle path
  required for delegated store hooks, per-hook denial cap, `DEPLOYMENT_ENVIRONMENT`
  format validation, strict-error coverage on every query path;
  (6) **`http.send` forbidden for store hooks** (global-only under governance),
  `data`/`input` **import** ban closing the alias hole (AST-based, not textual),
  single-platform-signed-bundle topology with platform-owned key, honest
  `denial_count` (post-per-hook-cap) + `denials_dropped`/`hook_output_truncated`,
  `DEPLOYMENT_ENVIRONMENT` syntax/failure defined, non-overlapping readiness
  signals;
  (7) **enumeration refusal shipped in v1, secure by default**
  (`accessible_objects/subjects` are 403-refused with any hook loaded unless
  `ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true`), unset environment forwards
  the sentinel **`"unknown"`** — never `""`, which fails *open* on equality
  gates (allowlist-style env gates required), per-hook cap defined as an
  output bound not a compute bound, bundle-signing + rejection requirements,
  http.send governance requirements, sanitized-Helm-identifier mapping defined;
  (8) enumeration refusal wording pinned to **applicable** hooks (already
  store-scoped in code, now tested), Rego **reserved words blacklisted** as
  store names (migration 0009), hash-suffixed k8s volume names (collision +
  63-char safe), bundle signature semantics corrected (file set + per-file
  hashes, not tarball bytes) + explicit `.manifest` **roots**, and the
  `"unknown"` environment made **enforced-fail-closed** via a platform guard
  denial with `ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT` opt-out;
  (9) **bundle root narrowed to `authz/hooks/v1/stores`** (the wider root
  would claim `…/global` and erase separately mounted global hooks on
  activation) with a full `.manifest` example (`rego_version`, `revision`,
  `metadata.hook_abi`); the http.send destination allowlist made
  **capability-enforced** (`opa/hooks-v1-http-capabilities.json`: pure set +
  `http.send` + deny-all `allow_net` template); hook `<name>` segments follow
  the store-name rules (reserved words + length, validator-enforced);
  amendment history moved to this appendix;
  (10) **runtime-capabilities claim corrected** — `opa run` takes no
  capabilities file, so `allow_net` is a *build/check-time* validation, not a
  runtime control; the model is three independent controls (build-time
  capabilities + AST validation with **static-destination enforcement** in the
  validator, signed immutable artifact, and independent runtime egress
  enforcement via NetworkPolicy/egress proxy — a blocked `http.send` fails
  closed via `strict-builtin-errors`);
  (11) **configuration-injection mechanism made explicit** (flags reach Rego
  only through the platform config module — `opa.runtime().env`, a builtin
  hooks cannot call; data-injected under the config package where process env
  doesn't exist), the validator **statically enforces the `allow_net`
  allowlist** on the (forced-literal) `http.send` destinations and **rejects
  `enable_redirect: true`** (redirects stay off, verified default);
  (12) `http.send` static contract completed: **`raise_error` must stay
  `true`** (`false` returns a `status_code: 0` response instead of raising —
  `strict-builtin-errors` would never fire, silently defeating fail-closed),
  `tls_insecure_skip_verify` must stay `false`, `timeout` must be a static
  non-zero bound; computed values for any of these are rejected;
  (13) global `http.send` hooks **must ship via the signed immutable artifact
  path in production** (mutable ConfigMap/`--watch` only for dev or
  network-free global hooks), and the platform config flags documented +
  regression-tested as fail-closed parses (exact `"true"` enables; missing/
  malformed/other = disabled);
  (14) **`max_response_bytes` claim corrected** — no such `http.send` request
  field exists (verified: OPA rejects it as an invalid parameter); the
  response-size bound must come from the endpoint or an egress proxy. And the
  contract tightened to **read-only network lookup**: literal `GET`/`HEAD`
  only, no `body`/`raw_body`, `max_retry_attempts` 0/absent, no `Host` header
  override — all validator-enforced;
  (15) **HTTP error statuses identified as a fail-open gap** — a 4xx/5xx is a
  *successful* `http.send` (no builtin error, `strict-builtin-errors`
  inapplicable), so network hooks MUST deny outside a declared success-status
  set; reference implementation + contract tests shipped
  (`examples/opa-hooks-http/`, 404/429/500/503 + malformed/missing bodies +
  aggregator veto). Signed global-hook topology pinned: combined bundle
  rooted `authz/hooks/v1` XOR separate global bundle rooted
  `authz/hooks/v1/global` beside the store bundle;
  (16) the HTTP status/schema contract's enforcement boundary stated
  honestly — a **governance requirement** (review + per-hook contract tests)
  for platform-trusted network hooks, not a `validate-hooks.sh` static
  guarantee; the platform-HTTP-helper alternative documented as the v2
  hardening (deferred: schema fail-closed stays author-side regardless);
  `platform_policy_compatibility` given named enforcement owners (publish
  pipeline pre-activation, activation monitor post-activation);
  (17 — implementation phase) **per-candidate hook-FILTERED enumeration
  shipped** (`HOOK_FILTERED_ENUMERATION`, candidate cap with fail-closed
  refusal, raw-keyset paginated protocol `{hook_filtered, ids, has_more,
  cursor}`, refused while the env guard is active), and the v1 ABI gained the
  verified **`actor{id, roles}`** on both operations (Keycloak client-role
  exemptions expressible, veto-only preserved; `examples/opa-hooks-filtering/`
  covers both with a 14-test suite);
  (18) filtering review hardening — the new flags joined the trusted
  configuration contract (strict digits-only 1..100000 cap parsing;
  malformed/out-of-range ⇒ filtering off ⇒ refusal), **filtered-page cursors
  sealed with AES-GCM** (`CURSOR_SEAL_KEY`; the raw-keyset cursor may name a
  hook-hidden id — opaque + integrity-protected, failed unseal = 400), the
  consistency claim qualified (per-page normalized input, no cross-page
  snapshot), `http.send` request fields moved to an explicit **allowlist**
  (cross-query cache controls forbidden — hooks execute fresh per decision),
  and the flat role namespace made explicit (exemptions need globally
  unambiguous role names);
  (19) both-flags precedence pinned (filtering wins; CONFIGURED-but-inoperable
  filtering refuses even with the superset opt-out set) and `CURSOR_SEAL_KEY`
  became a rotation keyring (first mints, all accept);
  (20) consistency fixes — the write-side `actor` was always an object, so
  `roles` is additive within v1 (stated; v1 also never externally released);
  sealed cursors **bound to the query context** via AEAD AAD with the
  per-process key fallback declared development-only (startup warning on
  OPA-fronted instances without `CURSOR_SEAL_KEY`); the cap tri-state pinned
  (missing → 1000, valid → value, malformed → refusal); and the cache-field
  prohibition promoted from the amendment history into the normative
  `http.send` contract;
  (21) cursor binding completed — the AAD now includes **`actor.id`** and a
  **canonical caller-context hash** (actor A's cursor is rejected for actor
  B; the role set deliberately unbound per no-cross-page-snapshot), the Helm
  chart **refuses to render** filtered enumeration without
  `authzen.opa.cursorSealKey` (the stated production requirement is now
  enforced where production is knowable), the cap's per-request scope stated,
  and the amendment numbering/status line repaired;
  (22 — freeze) cryptographic invariants stated and enforced — fresh random
  96-bit nonces per cursor, strict keyring parsing (empty segments = startup
  error, closing the silent `CURSOR_SEAL_KEY=","` fallback), an explicit
  envelope format version (unknown versions fail closed), plaintext padding
  to 32-byte buckets (length side-channel reduced to a coarse bucket), and
  the disclosure claim reworded honestly. Out of iterative architectural
  review; validation continues via mutation, multi-replica pagination,
  key-rotation, and end-to-end tests;
  (23 — implementation phase) the verified **actor** landed in its final
  shape `{id, roles, claims}` (verbatim claim copies under `actor.claims`,
  `HOOK_ACTOR_CLAIMS` defaulting to Keycloak's `realm_access` +
  `resource_access`; opt-in `JWT_ROLES_SOURCE_PREFIX` for flat-set
  consumers), and the **platform hook library** `authz.hooks.lib.v1` was
  introduced — the single validator-allowlisted shared namespace
  (platform-owned, functions-only, ships with the platform policy), first
  module `keycloak` (`has_realm_role` / `has_client_role`), with the
  reserved `ext.*` subtree for **operator extension libraries**
  (`validate-hooks.sh --lib`: functions-only, always pure, never
  tenant-mountable).
