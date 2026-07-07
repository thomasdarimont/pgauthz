# opa test suite for the hook contract (ADR 0011, amended): run with
#   opa test opa/policies examples/opa-hooks -v
# (platform policies + hooks together — exactly what the sidecar loads).
package authz.hooks_test

import future.keywords.if
import future.keywords.in

# Server-derived evaluated_at (ns). 10:00 UTC ≈ 12:00 Europe/Berlin (business
# hours); 22:00 UTC ≈ 00:00 (outside).
business_time := time.parse_rfc3339_ns("2026-07-07T10:00:00Z")

night_time := time.parse_rfc3339_ns("2026-07-07T22:00:00Z")

fin_input := {
	"store": "demo", # opa test has no DEFAULT_STORE env, so name it explicitly
	"deployment": {"environment": "test"}, # pgauthzd always forwards this
	"subject": {"type": "internal_user", "id": "alice"},
	"action": "can_read",
	"resource": {"type": "document", "id": "fin_q3_report"},
}

# ── normalized hook-input ABI ────────────────────────────────────────────────

# Hooks see the versioned ABI document, NOT the raw transport input: no token
# key, the platform-resolved subject, a server-derived evaluated_at, defaults.
test_hook_input_abi_hides_the_token_and_stamps_time if {
	hi := data.authz._decision_hook_input with input as object.union(
		fin_input,
		{"token": "SECRET-BEARER"},
	)
		with data.authz.subject_type as "internal_user"
		with data.authz.subject_id as "alice"
		with time.now_ns as night_time
	hi.api_version == "pgauthz.hooks/v1"
	object.get(hi, "token", "ABSENT") == "ABSENT"
	hi.subject == {"type": "internal_user", "id": "alice"}
	hi.evaluated_at == night_time # server-derived, not caller context
	hi.context == {}
}

# evaluated_at is forwarded by pgauthzd; the ABI uses it verbatim (same value
# for every batch item), falling back to the OPA clock only for standalone use.
test_evaluated_at_uses_forwarded_value if {
	hi := data.authz._decision_hook_input with input as object.union(fin_input, {"evaluated_at": 12345})
		with data.authz.subject_type as "user"
		with data.authz.subject_id as "alice"
	hi.evaluated_at == 12345
}

# The write ABI names the authenticated caller as `actor`, distinct from the
# tuple's subject (the grantee).
test_write_abi_has_actor_distinct_from_tuple if {
	hi := data.authz._write_hook_input with input as {
		"store": "demo",
	"deployment": {"environment": "test"},
		"deployment": {"environment": "test"},
		"operation": "write",
		"tuple": {"user_type": "user", "user_id": "alice", "relation": "viewer", "object_type": "document", "object_id": "d1"},
	}
		with data.authz._hook_actor_id as "service-account:provisioner"
	hi.actor.id == "service-account:provisioner"
	hi.tuple.user_id == "alice"
}

# ── two tiers: global applies everywhere, store hooks only to their store ────

# The demo store's decision hook fires for demo; a different store never sees it.
test_store_hook_scoped_to_its_store if {
	ext := {"store": "demo", "subject": {"type": "user", "id": "ext_carol"}, "action": "can_read", "resource": {"type": "document", "id": "d1"}}
	some d in data.authz.hook_denials with input as ext
		with time.now_ns as business_time
	d.tier == "store"
	d.store == "demo"
	d.hook == "tenant_guard"
}

test_store_hook_absent_for_other_store if {
	other := {"store": "tenant_b", "deployment": {"environment": "test"}, "subject": {"type": "user", "id": "ext_carol"}, "action": "can_read", "resource": {"type": "document", "id": "d1"}}
	count(data.authz.hook_denials) == 0 with input as other
		with time.now_ns as business_time
}

test_hooks_loaded_lists_global_and_this_store if {
	loaded := data.authz.hooks_loaded with input as fin_input
		with time.now_ns as business_time
	"business_hours" in loaded
	"tuple_rules" in loaded
	"stores/demo/tenant_guard" in loaded
}

# ── structured denials ───────────────────────────────────────────────────────

# A plain-string denial is normalized to {tier, hook, code: "denied", message}.
test_string_denial_is_structured if {
	some d in data.authz.hook_denials with input as fin_input
		with time.now_ns as night_time
	d.tier == "global"
	d.hook == "business_hours"
	d.code == "denied"
	contains(d.message, "fin_q3_report")
}

test_no_matching_hook_means_no_denials if {
	count(data.authz.hook_denials) == 0 with input as {
		"store": "demo",
	"deployment": {"environment": "test"},
		"deployment": {"environment": "test"},
		"subject": {"type": "internal_user", "id": "alice"},
		"action": "can_read",
		"resource": {"type": "document", "id": "doc_ordinary"},
	}
		with time.now_ns as night_time
}

# ── decision composition: hooks NARROW the graph answer ─────────────────────

test_graph_allow_plus_hook_deny_is_deny if {
	not data.authz.allow with input as fin_input
		with time.now_ns as night_time
		with data.authz._graph_allow as true
}

test_graph_allow_passes_inside_business_hours if {
	data.authz.allow with input as fin_input
		with time.now_ns as business_time
		with data.authz._graph_allow as true
}

# A hook can never turn a graph DENY into an allow (no widening).
test_hook_cannot_widen if {
	not data.authz.allow with input as fin_input
		with time.now_ns as business_time
		with data.authz._graph_allow as false
}

# allow_detailed reports WHICH hook vetoed, structured.
test_allow_detailed_attributes_the_hook if {
	d := data.authz.allow_detailed with input as fin_input
		with time.now_ns as night_time
		with data.authz._subject_valid as true
	d.decision == false
	d.reason == "policy_hook"
	d.hook_denials[0].hook == "business_hours"
	"business_hours" in d.hooks_loaded
}

# ── PER-ITEM batch evaluation (ADR 0011 amendment) ───────────────────────────

# A hook that denies item 1 (finance doc, at night) but not item 0 must reject
# the whole batch, tagging the offending index — evaluating only the top-level
# input would let item 1 slip through.
test_batch_per_item_hook_veto if {
	res := data.authz.evaluations with input as {
		"store": "demo",
	"deployment": {"environment": "test"},
		"deployment": {"environment": "test"},
		"subject": {"type": "internal_user", "id": "alice"},
		"evaluations": [
			{"action": "can_read", "resource": {"type": "document", "id": "doc_ok"}},
			{"action": "can_read", "resource": {"type": "document", "id": "fin_secret"}},
		],
	}
		with time.now_ns as night_time
		with data.authz._batch_subject_valid as true
		with data.authz._graph_evaluations as [{"decision": true}, {"decision": true}]
	res.error == "denied_by_policy_hook"
	res.denials[0].evaluation_index == 1
	res.denials[0].hook == "business_hours"
}

# A hook denial on an item the GRAPH already denied is moot — no batch veto.
test_batch_hook_ignores_graph_denied_item if {
	res := data.authz.evaluations with input as {
		"store": "demo",
	"deployment": {"environment": "test"},
		"deployment": {"environment": "test"},
		"subject": {"type": "internal_user", "id": "alice"},
		"evaluations": [{"action": "can_read", "resource": {"type": "document", "id": "fin_secret"}}],
	}
		with time.now_ns as night_time
		with data.authz._batch_subject_valid as true
		with data.authz._graph_evaluations as [{"decision": false}]
	res == [{"decision": false}]
}

# No hooks fire → the graph results pass through unchanged.
test_batch_passes_when_no_hook_denies if {
	res := data.authz.evaluations with input as {
		"store": "demo",
	"deployment": {"environment": "test"},
		"deployment": {"environment": "test"},
		"subject": {"type": "internal_user", "id": "alice"},
		"evaluations": [{"action": "can_read", "resource": {"type": "document", "id": "doc_ok"}}],
	}
		with time.now_ns as business_time
		with data.authz._batch_subject_valid as true
		with data.authz._graph_evaluations as [{"decision": true}]
	res == [{"decision": true}]
}

# ── permitted_actions is hook-filtered per action ────────────────────────────

test_permitted_actions_filtered_by_hooks if {
	acts := data.authz.permitted_actions with input as fin_input
		with time.now_ns as night_time
		with data.authz._subject_valid as true
		with data.authz._graph_permitted_actions as {"can_read", "can_approve"}
	count(acts) == 0
}

test_permitted_actions_untouched_inside_hours if {
	acts := data.authz.permitted_actions with input as fin_input
		with time.now_ns as business_time
		with data.authz._subject_valid as true
		with data.authz._graph_permitted_actions as {"can_read", "can_approve"}
	acts == {"can_read", "can_approve"}
}

# ── write governance (structured denials with codes; both tiers) ─────────────

wildcard_write := {
	"store": "demo",
	"deployment": {"environment": "test"},
	"operation": "write",
	"tuple": {"user_type": "user", "user_id": "*", "relation": "viewer", "object_type": "document", "object_id": "d1"},
}

test_global_write_hook_vetoes_wildcard if {
	res := data.authz.write with input as object.union(wildcard_write, {"detail": true})
		with data.authz._writes_enabled as true
		with data.authz._write_authorized as true
		with data.authz._valid_write_request as true
	res.allowed == false
	res.error == "denied_by_policy_hook"
	some d in res.denials
	d.hook == "tuple_rules"
	d.code == "wildcard_forbidden"
	d.tier == "global"
}

# WITHOUT authorized detail, the write veto returns only the error code — hook
# identities/reasons are not disclosed (ADR 0011 disclosure rule).
test_write_veto_hides_denials_without_detail if {
	res := data.authz.write with input as wildcard_write
		with data.authz._writes_enabled as true
		with data.authz._write_authorized as true
		with data.authz._valid_write_request as true
	res.error == "denied_by_policy_hook"
	not res.denials
}

# The demo store's OWN write hook (delete forbidden) fires for demo deletes.
test_store_write_hook_blocks_demo_delete if {
	res := data.authz.write with input as {
		"store": "demo",
	"deployment": {"environment": "test"},
		"deployment": {"environment": "test"},
		"detail": true,
		"operation": "delete",
		"tuple": {"user_type": "user", "user_id": "alice", "relation": "viewer", "object_type": "document", "object_id": "d1"},
	}
		with data.authz._writes_enabled as true
		with data.authz._write_authorized as true
		with data.authz._valid_write_request as true
	res.error == "denied_by_policy_hook"
	some d in res.denials
	d.hook == "tenant_guard"
	d.store == "demo"
}

# ...but not for another store.
test_store_write_hook_scoped_to_demo if {
	res := data.authz.write with input as {
		"store": "tenant_b",
		"deployment": {"environment": "test"},
		"operation": "delete",
		"tuple": {"user_type": "user", "user_id": "alice", "relation": "viewer", "object_type": "document", "object_id": "d1"},
	}
		with data.authz._writes_enabled as true
		with data.authz._write_authorized as true
		with data.authz._valid_write_request as true
		with data.authz._forward as {"status": 200, "body": {}}
	res.allowed == true
}

# ── denial truncation honesty (ADR 0011 amendment 6) ─────────────────────────

# A hook emitting more than the per-hook cap (16) sets hook_output_truncated,
# and denial_count reports the post-cap total (never a claimed raw sum).
flood := {"floody": {"deny": {sprintf("d%02d", [i]) | some i in numbers.range(1, 40)}}}

test_per_hook_cap_and_output_truncated if {
	dc := data.authz.hook_denial_count with input as {"store": "demo", "deployment": {"environment": "test"}, "subject": {"type": "u", "id": "a"}, "action": "r", "resource": {"type": "d", "id": "1"}}
		with data.authz.hooks.v1.global as flood
	dc == 16 # 40 emitted → capped to 16 per hook
	data.authz.hook_output_truncated with input as {"store": "demo", "deployment": {"environment": "test"}, "subject": {"type": "u", "id": "a"}, "action": "r", "resource": {"type": "d", "id": "1"}}
		with data.authz.hooks.v1.global as flood
}

# The GLOBAL 64-cap: many hooks past 64 total → denials_truncated + dropped.
many := {name: {"deny": {sprintf("x%s", [name])}} |
	some i in numbers.range(1, 80)
	name := sprintf("h%02d", [i])
}

test_global_cap_reports_dropped if {
	inp := {"store": "demo", "deployment": {"environment": "test"}, "subject": {"type": "u", "id": "a"}, "action": "r", "resource": {"type": "d", "id": "1"}}
	dc := data.authz.hook_denial_count with input as inp with data.authz.hooks.v1.global as many
	dc == 80
	data.authz.hook_denials_truncated with input as inp with data.authz.hooks.v1.global as many
	data.authz.hook_denials_dropped == 16 with input as inp with data.authz.hooks.v1.global as many # 80 - 64
	count(data.authz.hook_denials) == 64 with input as inp with data.authz.hooks.v1.global as many
}

# ── enumeration confidentiality (ADR 0011 amendment 7) ───────────────────────

_enum_input := {"store": "demo", "subject": {"type": "u", "id": "a"}, "action": "r", "resource": {"type": "d", "id": "1"}}

# With hooks loaded (this suite mounts several), enumeration is REFUSED by
# default — the graph-derived superset would ignore per-decision vetoes.
test_enumeration_refused_with_hooks_by_default if {
	data.authz.enumeration_refused with input as _enum_input
	data.authz.accessible_objects == {"error": "enumeration_refused_with_hooks"} with input as _enum_input
	data.authz.accessible_subjects == {"error": "enumeration_refused_with_hooks"} with input as _enum_input
}

# Explicit operator opt-in restores superset enumeration.
test_enumeration_allowed_with_explicit_optin if {
	not data.authz.enumeration_refused with input as _enum_input
		with data.authz.pgauthz.config.allow_unfiltered_enumeration as true
}

# With NO hooks loaded, enumeration is unaffected (default stack unchanged).
test_enumeration_not_refused_without_hooks if {
	not data.authz.enumeration_refused with input as _enum_input
		with data.authz.hooks.v1 as {}
}

# An UNSET deployment environment surfaces as the sentinel "unknown" (never ""
# — an equality gate would fail open on empty).
test_unset_environment_is_unknown_sentinel if {
	abi := data.authz._decision_hook_input with input as _enum_input
	abi.deployment.environment == "unknown"
}

# ── platform environment guard (ADR 0011 amendment 8) ────────────────────────

# With hooks applicable and DEPLOYMENT_ENVIRONMENT unconfigured ("unknown"),
# the PLATFORM injects a denial — an equality env gate would otherwise fail
# open. The sentinel is visible; the guard makes it enforced.
test_env_guard_denies_on_unknown_environment if {
	inp := object.remove(fin_input, ["deployment"]) # unset → ABI "unknown"
	some d in data.authz.hook_denials with input as inp
	d.tier == "platform"
	d.hook == "environment_guard"
	d.code == "deployment_environment_unknown"
	not data.authz.allow with input as inp
}

# The guard applies to writes too.
test_env_guard_denies_writes_on_unknown_environment if {
	inp := object.remove(wildcard_write, ["deployment"])
	some d in data.authz.hook_write_denials with input as inp
	d.code == "deployment_environment_unknown"
}

# Explicit platform opt-out for genuinely environment-independent hooks.
test_env_guard_optout if {
	inp := object.remove(fin_input, ["deployment"])
	count([d | some d in data.authz.hook_denials with input as inp; d.code == "deployment_environment_unknown"]) == 0 with data.authz.pgauthz.config.allow_unknown_environment as true
}

# With NO hooks loaded, the guard is inert (default stack unaffected).
test_env_guard_inert_without_hooks if {
	inp := object.remove(fin_input, ["deployment"])
	count(data.authz.hook_denials) == 0 with input as inp
		with data.authz.hooks.v1 as {}
}

# ── enumeration refusal is APPLICABLE-hook-scoped (ADR 0011 amendment 8) ─────

# A hook for tenant_b must NOT disable enumeration for demo: refusal keys on
# hooks_loaded = global + REQUESTED-store hooks only.
test_enumeration_scoped_to_applicable_hooks if {
	only_b := {"stores": {"tenant_b": {"guard": {"deny": {"no"}}}}}
	inp := {"store": "demo", "subject": {"type": "u", "id": "a"}, "action": "r", "resource": {"type": "d", "id": "1"}}
	not data.authz.enumeration_refused with input as inp
		with data.authz.hooks.v1 as only_b
	data.authz.enumeration_refused with input as object.union(inp, {"store": "tenant_b"})
		with data.authz.hooks.v1 as only_b
}

# ── platform config flags parse fail-closed (ADR 0011 amendment 13) ─────────

# Exactly "true" enables; missing, malformed, or any other value = disabled
# (the rules are partial: undefined = fail closed for both opt-outs).
test_config_flags_exact_true_only if {
	data.authz.pgauthz.config.allow_unknown_environment with opa.runtime as {"env": {"ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT": "true"}}
	not data.authz.pgauthz.config.allow_unknown_environment with opa.runtime as {"env": {"ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT": "True"}}
	not data.authz.pgauthz.config.allow_unknown_environment with opa.runtime as {"env": {"ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT": "1"}}
	not data.authz.pgauthz.config.allow_unknown_environment with opa.runtime as {"env": {}}
	data.authz.pgauthz.config.allow_unfiltered_enumeration with opa.runtime as {"env": {"ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS": "true"}}
	not data.authz.pgauthz.config.allow_unfiltered_enumeration with opa.runtime as {"env": {"ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS": "yes"}}
	not data.authz.pgauthz.config.allow_unfiltered_enumeration with opa.runtime as {"env": {}}
}

# ── claims_guard: actor.claims patterns (verbatim + custom claims) ──────────

_export_input := {
	"store": "demo",
	"deployment": {"environment": "test"},
	"token": "t",
	"subject": {"type": "internal_user", "id": "alice"},
	"action": "can_export",
	"resource": {"type": "document", "id": "report_1"},
}

_doc_api_exporter := {"resource_access": {"document-api": {"roles": ["exporter"]}}}

test_export_allowed_with_client_role if {
	count([d | some d in data.authz.hook_denials with input as _export_input
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "internal_user"
		with data.authn.subject_id as "alice"
		with data.authn.roles as set()
		with data.authn.actor_claims as _doc_api_exporter
		with time.now_ns as business_time
	; d.hook == "claims_guard"]) == 0
}

# The SAME role name on a DIFFERENT client does not qualify — that's the
# point of reading the verbatim structure instead of the flat set.
test_export_denied_with_other_clients_role if {
	some d in data.authz.hook_denials with input as _export_input
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "internal_user"
		with data.authn.subject_id as "alice"
		with data.authn.roles as set()
		with data.authn.actor_claims as {"resource_access": {"billing-api": {"roles": ["exporter"]}}}
		with time.now_ns as business_time
	d.code == "export_requires_client_role"
}

# Tokenless caller: actor.claims == {} → exemption can't match → denial.
test_export_denied_without_token if {
	inp := object.remove(_export_input, ["token"])
	some d in data.authz.hook_denials with input as inp
		with time.now_ns as business_time
	d.code == "export_requires_client_role"
}

# Custom claim (groups, via HOOK_ACTOR_CLAIMS): membership exempts; a missing
# claim is most-restrictive.
test_restricted_needs_compliance_group if {
	inp := object.union(_export_input, {"action": "can_read", "resource": {"type": "document", "id": "restricted_7"}})
	some d in data.authz.hook_denials with input as inp
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "internal_user"
		with data.authn.subject_id as "alice"
		with data.authn.roles as set()
		with data.authn.actor_claims as _doc_api_exporter # groups claim absent
		with time.now_ns as business_time
	d.code == "restricted_requires_compliance_group"

	count([d2 | some d2 in data.authz.hook_denials with input as inp
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "internal_user"
		with data.authn.subject_id as "alice"
		with data.authn.roles as set()
		with data.authn.actor_claims as {"groups": ["compliance"]}
		with time.now_ns as business_time
	; d2.hook == "claims_guard"]) == 0
}

# Realm-wide role gate: realm_access is the realm-scope counterpart to the
# client-scoped resource_access check.
test_delete_needs_realm_role if {
	inp := object.union(_export_input, {"action": "can_delete"})
	some d in data.authz.hook_denials with input as inp
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "internal_user"
		with data.authn.subject_id as "alice"
		with data.authn.roles as set()
		with data.authn.actor_claims as _doc_api_exporter # no realm role
		with time.now_ns as business_time
	d.code == "delete_requires_realm_role"

	count([d2 | some d2 in data.authz.hook_denials with input as inp
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "internal_user"
		with data.authn.subject_id as "alice"
		with data.authn.roles as set()
		with data.authn.actor_claims as {"realm_access": {"roles": ["records_officer"]}}
		with time.now_ns as business_time
	; d2.hook == "claims_guard"]) == 0
}
