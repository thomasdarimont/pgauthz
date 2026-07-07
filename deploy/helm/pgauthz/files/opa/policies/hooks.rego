# ─────────────────────────────────────────────────────────────────────────────
# Policy hooks (ADR 0011): user-supplied VETO rules that ride along the
# standard decision pipeline without editing any platform policy file.
#
# TWO TIERS (both veto-only; a hook can only NARROW, never widen):
#   authz.hooks.v1.global.<name>          — apply to EVERY store (operator tier)
#   authz.hooks.v1.stores.<store>.<name>  — apply only when input.store == <store>
#
# The store tier is keyed by the request's store (a map lookup on the ABI), so
# in a multi-tenant deployment only the target store's hooks (plus globals) are
# consulted — tenant B's hooks are never evaluated on a tenant-A request. Since
# store selection is already validated (issuer bindings), a store hook runs only
# for authenticated requests bound to its store.
#
# CONTRACT v1 (versioned in the package path — a future v2 can coexist):
#   - Mount .rego files declaring the package above into the OPA container
#     (compose: /policies/hooks; Helm: opa.extraPoliciesConfigMap for globals,
#     opa.storePoliciesConfigMaps.<store> for a store's hooks).
#   - A hook may define (each denial is a STRING message or a
#     {"code": ..., "message": ...} object; both are normalized to a structured
#     {tier, store?, hook, code, message} — the hook identity comes from the
#     package, never spoofable by the denial value):
#       deny contains d        — veto a DECISION (allow / allow_detailed /
#                                evaluations / permitted_actions filtering)
#       deny_write contains d  — veto a WRITE (data.authz.write, all ops)
#   - Hooks do NOT see the raw platform input. They are evaluated against the
#     NORMALIZED, VERSIONED hook-input ABI below (api_version pgauthz.hooks/v1)
#     — bearer/service tokens and transport details are deliberately not part
#     of it, and platform-policy refactorings don't break hooks.
#   - Absent hooks contribute nothing: a deployment with no mounts behaves
#     identically to one without this feature.
#
# TRUST MODEL — TWO TIERS, a contract enforced by tooling, not a runtime
# sandbox. Rego places modules by their declared package, so a mounted file
# could declare `package authz` and add an `allow` body (widening), or a
# tenant's file could claim another store's namespace (a cross-tenant DoS,
# since hooks only deny). GLOBAL hook authors are platform-policy trust tier;
# STORE hook authors are the DELEGATED tenant tier — restricted to the ABI,
# their own package's rules, and the pure-builtin capability allowlist.
# scripts/validate-hooks.sh enforces it (CI / bundle build): namespace pinning
# (--global / --store <s>), duplicate names, platform packages, data/input
# imports + cross-package/dynamic data refs (isolation), and capability-based
# purity. http.send is GLOBAL-only via --allow-http; store hooks are
# network-free in v1. Delegated store hooks ship as a signed, platform-built
# immutable bundle (see ADR 0011).
#
# FAILURE SEMANTICS: pgauthzd queries with strict-builtin-errors=true on EVERY
# standard-pipeline query, so a runtime evaluation error inside any hook FAILS
# the query CLOSED (pgauthzd surfaces policy_evaluation_failed, never a
# phantom allow). Startup load error → OPA refuses to start → readiness fails.
# Hot-reload (--watch) / bundle-activation error → OPA KEEPS the
# last-known-good set and logs; monitor activation revision.
#
# ENUMERATION (v1, secure by default): accessible_objects/accessible_subjects
# are graph-derived SUPERSETS that decision hooks do not filter — with any
# hook loaded those queries are REFUSED unless the operator sets
# ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true (explicit superset opt-in).
# permitted_actions IS hook-filtered per action.
# ─────────────────────────────────────────────────────────────────────────────
package authz

import future.keywords.if
import future.keywords.in

import data.authz.pgauthz.config

# The hook names APPLICABLE to this request: every global hook, plus this
# store's hooks (namespaced so a store hook can't be confused with a global
# one). NOT every module loaded into OPA — other stores' hooks are structurally
# absent. pgauthzd returns this under X-PGAuthz-Detail or discards it.
hooks_loaded := sort(array.concat(
	[name | some name, _ in data.authz.hooks.v1.global],
	[sprintf("stores/%s/%s", [store, name]) | some name, _ in data.authz.hooks.v1.stores[store]],
))

# ── normalized hook-input ABI (pgauthz.hooks/v1) ─────────────────────────────

# Subject as the PLATFORM resolved it (JWT claims when a token is present) —
# hooks never re-derive identity, and never see the token itself.
_hook_subject := {"type": subject_type, "id": subject_id} if subject_id

_hook_subject := object.get(input, "subject", {}) if not subject_id

# evaluated_at is captured ONCE by pgauthzd and forwarded as input.evaluated_at
# (a single server timestamp, ns) so every batch item and every hook in one
# request sees the SAME value — no per-item clock skew, deterministic on retry.
# The time.now_ns() fallback is only for standalone `opa eval`/tests without
# pgauthzd; in production input.evaluated_at is always present.
_evaluated_at := object.get(input, "evaluated_at", time.now_ns())

# The authenticated caller for a write (write.rego's _performed_by = the
# verified subject). Defaulted so the write ABI is always well-formed even
# before authorization resolves the subject.
default _hook_actor_id := ""

_hook_actor_id := _performed_by

# Trust sources (a hook MUST NOT trust caller-supplied fields for security
# gates): api_version/operation/evaluated_at are SERVER-derived; store and
# subject are PLATFORM-derived from the verified token / validated request;
# action, resource, and context are CALLER-supplied. Time-/environment-gated
# hooks read `evaluated_at` — never context.time — so they can't be spoofed and
# stay deterministic/testable. Store names are Rego-safe identifiers (migration
# 0008), so `store` is the package segment for store-scoped hooks directly.
# Server-configured deployment info (DEPLOYMENT_ENVIRONMENT), forwarded by
# pgauthzd. Environment-gated hooks read deployment.environment — NOT the
# caller-supplied context — so the gate can't be spoofed. An UNSET environment
# arrives as the explicit sentinel "unknown", never "": an equality gate like
# `environment == "production"` would silently fail OPEN on "" — env-gated
# hooks must treat "unknown" as the most restrictive environment (deny unless
# the environment is in an explicit allowlist).
_deployment := object.get(input, "deployment", {"environment": "unknown"})

_decision_hook_input := {
	"api_version": "pgauthz.hooks/v1",
	"operation": "decision",
	"evaluated_at": _evaluated_at,
	"deployment": _deployment,
	"store": store,
	"subject": _hook_subject,
	"action": object.get(input, "action", ""),
	"resource": object.get(input, "resource", {}),
	"context": object.get(input, "context", {}),
}

# The write ABI names the AUTHENTICATED CALLER explicitly as `actor` — distinct
# from the subject(s) inside `tuple`/`tuples`/`writes` who RECEIVE the grant.
# A write-governance hook checks the actor for authorization-shaped rules and
# the tuple subjects for the relationships being written.
_write_hook_input := {
	"api_version": "pgauthz.hooks/v1",
	"operation": object.get(input, "operation", ""),
	"evaluated_at": _evaluated_at,
	"deployment": _deployment,
	"store": _store,
	"actor": {"id": _hook_actor_id},
	"tuple": object.get(input, "tuple", {}),
	"tuples": object.get(input, "tuples", []),
	"writes": object.get(input, "writes", []),
	"deletes": object.get(input, "deletes", []),
	"user": object.get(input, "user", {}),
}

# ── aggregation ──────────────────────────────────────────────────────────────

# A structured denial merges a SOURCE descriptor ({tier, store?, hook}) over
# the (normalized) denial. String denials become code "denied"; object denials
# may set code/message. code and message are bounded (64 / 256 chars), and the
# source always wins — so a denial value can't spoof its tier/store/hook
# identity, and a junk denial can't bloat the response.
_bounded(s, n) := substring(s, 0, n) if is_string(s)

_bounded(s, _) := "" if not is_string(s)

_structured(src, raw) := object.union(src, {"code": "denied", "message": _bounded(raw, 256)}) if is_string(raw)

_structured(src, raw) := object.union(
	{
		"code": _bounded(_denial_code(raw), 64),
		"message": _bounded(object.get(raw, "message", ""), 256),
	},
	src,
) if is_object(raw)

_denial_code(raw) := c if {
	c := object.get(raw, "code", "denied")
	is_string(c)
}

_denial_code(raw) := "denied" if not is_string(object.get(raw, "code", "denied"))

# Deterministic total order by (tier, store, hook, code, message).
_denial_key(d) := [d.tier, object.get(d, "store", ""), d.hook, d.code, d.message]

_ordered(ds) := [pair[1] | some pair in sort([[_denial_key(d), d] | some d in ds])]

# Total denials returned to a caller are capped (defense against a misbehaving
# hook flooding the response); the FACT of a veto is what gates, the list is
# diagnostic. `hook_denial_count` / `hook_denials_truncated` report the true
# size when the list is sliced.
_max_denials := 64

_cap(ds) := array.slice(_ordered(ds), 0, _max_denials)

# Per-hook denial cap: a single misbehaving hook can't contribute more than
# _max_per_hook denials to the aggregate (availability hardening — hooks are
# trusted, so this bounds a bug, not an adversary). Applied per (tier, package)
# before the global cap.
_max_per_hook := 16

_capped_global_deny(name) := array.slice(
	[_structured({"tier": "global", "hook": name}, raw) |
		some raw in data.authz.hooks.v1.global[name].deny with input as _decision_hook_input
	],
	0, _max_per_hook,
)

_capped_store_deny(s, name) := array.slice(
	[_structured({"tier": "store", "store": s, "hook": name}, raw) |
		some raw in data.authz.hooks.v1.stores[s][name].deny with input as _decision_hook_input
	],
	0, _max_per_hook,
)

# PLATFORM environment guard — the "unknown" sentinel is visible but not
# automatically fail-closed: an equality gate (`environment == "production"`)
# still silently never fires on it. This ENFORCES the guarantee: with hooks
# applicable and the environment unconfigured, the platform itself injects a
# denial, so an unset DEPLOYMENT_ENVIRONMENT can never fail open. Explicit
# opt-out (ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT=true) for deployments whose
# hooks are genuinely environment-independent.
default _env_guard_denials := []

_env_guard_denials := [{
	"tier": "platform",
	"hook": "environment_guard",
	"code": "deployment_environment_unknown",
	"message": "DEPLOYMENT_ENVIRONMENT is not configured; environment-gated hooks cannot be evaluated safely (set it, or opt out with ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT=true)",
}] if {
	count(hooks_loaded) > 0
	_deployment.environment == "unknown"
	not config.allow_unknown_environment
}

# Decision denials: platform guard + global tier + the request's store tier
# (each hook capped).
_all_decision_denials := array.concat(
	_env_guard_denials,
	array.concat(
		[d | some name, _ in data.authz.hooks.v1.global; some d in _capped_global_deny(name)],
		[d | some name, _ in data.authz.hooks.v1.stores[store]; some d in _capped_store_deny(store, name)],
	),
)

# denial_count is the total AFTER per-hook caps (what the aggregator kept) —
# NOT the raw pre-cap sum, which per-hook truncation makes unknowable. A hook
# that emitted more than its per-hook cap is flagged separately.
hook_denials := _cap(_all_decision_denials)

hook_denial_count := count(_all_decision_denials)

hook_denials_truncated if count(_all_decision_denials) > _max_denials

# How many the GLOBAL cap dropped from the returned list.
hook_denials_dropped := count(_all_decision_denials) - _max_denials if {
	count(_all_decision_denials) > _max_denials
}

# TRUE if any applicable hook emitted more than its per-hook cap (so
# denial_count already understates that hook's true output).
hook_output_truncated if {
	some name, _ in data.authz.hooks.v1.global
	count([1 | some _ in data.authz.hooks.v1.global[name].deny with input as _decision_hook_input]) > _max_per_hook
}

hook_output_truncated if {
	some name, _ in data.authz.hooks.v1.stores[store]
	count([1 | some _ in data.authz.hooks.v1.stores[store][name].deny with input as _decision_hook_input]) > _max_per_hook
}

# Write denials: same two tiers, against the write ABI and the write store
# (each hook capped at _max_per_hook).
_capped_global_deny_write(name) := array.slice(
	[_structured({"tier": "global", "hook": name}, raw) |
		some raw in data.authz.hooks.v1.global[name].deny_write with input as _write_hook_input
	],
	0, _max_per_hook,
)

_capped_store_deny_write(s, name) := array.slice(
	[_structured({"tier": "store", "store": s, "hook": name}, raw) |
		some raw in data.authz.hooks.v1.stores[s][name].deny_write with input as _write_hook_input
	],
	0, _max_per_hook,
)

# The platform environment guard applies to writes too — a write-governance
# hook's environment gate must not fail open either.
_all_write_denials := array.concat(
	_env_guard_denials,
	array.concat(
		[d | some name, _ in data.authz.hooks.v1.global; some d in _capped_global_deny_write(name)],
		[d | some name, _ in data.authz.hooks.v1.stores[_store]; some d in _capped_store_deny_write(_store, name)],
	),
)

hook_write_denials := _cap(_all_write_denials)

hook_write_denial_count := count(_all_write_denials)

# Per-action denial check for permitted_actions filtering — both tiers, with
# the candidate action substituted into the ABI document.
_action_hook_denied(action) if {
	hi := object.union(_decision_hook_input, {"action": action})
	some name, _ in data.authz.hooks.v1.global
	some _ in data.authz.hooks.v1.global[name].deny with input as hi
}

_action_hook_denied(action) if {
	hi := object.union(_decision_hook_input, {"action": action})
	some name, _ in data.authz.hooks.v1.stores[store]
	some _ in data.authz.hooks.v1.stores[store][name].deny with input as hi
}

# Convenience guards used by policy.rego / write.rego.
_hooks_pass if count(hook_denials) == 0

_write_hooks_pass if count(hook_write_denials) == 0
