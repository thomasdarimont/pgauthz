# Contract tests for hook-FILTERED enumeration (ADR 0011).
# Package deliberately OUTSIDE authz.hooks.v1.* (the aggregator iterates that
# namespace). The graph callback functions are mocked; the probe hook
# (classified.rego) provides real per-candidate vetoes.
package enumeration_filtering_test

import future.keywords.if
import future.keywords.in

_inp := {
	"store": "demo",
	"deployment": {"environment": "test"},
	"subject": {"type": "user", "id": "alice"},
	"action": "can_read",
	"resource": {"type": "document"},
}

mock_list(_, _, _, _, _) := ["classified_x", "doc_a", "doc_b"]

mock_list_page(_, _, _, _, _, _, _) := ["classified_x", "doc_a", "doc_b"]

mock_subjects(_, _, _, _, _) := ["alice", "bob", "contractor_eve"]

# ── mode selection ───────────────────────────────────────────────────────────

test_filtering_disables_refusal if {
	not data.authz.enumeration_refused with input as _inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
}

test_refused_without_any_optin if {
	data.authz.enumeration_refused with input as _inp
}

# Config-error state (env guard active) stays refused even with filtering on.
test_filtering_refused_while_env_guard_active if {
	inp := object.remove(_inp, ["deployment"])
	data.authz.enumeration_refused with input as inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
}

# ── unpaginated filtering ────────────────────────────────────────────────────

test_filtered_objects_drop_denied_candidates if {
	ids := data.authz.accessible_objects with input as _inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
		with data.authz.pgauthz.config.require_token_for_reads as false
		with data.authz.pgauthz.list_objects as mock_list
	ids == ["doc_a", "doc_b"] # classified_x vetoed per-candidate
}

test_filtered_subjects_drop_denied_candidates if {
	inp := {
		"store": "demo", "deployment": {"environment": "test"},
		"subject_type": "user", "action": "can_read",
		"resource": {"type": "document", "id": "doc_1"},
	}
	ids := data.authz.accessible_subjects with input as inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
		with data.authz.pgauthz.config.require_token_for_reads as false
		with data.authz.pgauthz.list_subjects as mock_subjects
	ids == ["alice", "bob"] # contractor_eve vetoed per-candidate
}

# ── fail-closed candidate cap ────────────────────────────────────────────────

test_cap_exceeded_refuses_not_partial if {
	res := data.authz.accessible_objects with input as _inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
		with data.authz.pgauthz.config.require_token_for_reads as false
		with data.authz.pgauthz.config.hook_filter_max_candidates as 2
		with data.authz.pgauthz.list_objects as mock_list
	res == {"error": "enumeration_refused_too_many_candidates"}
}

# ── paginated protocol (raw-space cursor survives filtering) ─────────────────

# Client limit 2 → pgauthzd sends page.limit 3 (peek). Raw page is full, so
# has_more; consumed = first 2 raw ids; classified_x filtered from ids; the
# cursor is the last RAW consumed id so no candidate is skipped.
test_filtered_page_protocol if {
	inp := object.union(_inp, {"page": {"limit": 3, "offset": 0}})
	res := data.authz.accessible_objects_page with input as inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
		with data.authz.pgauthz.config.require_token_for_reads as false
		with data.authz.pgauthz.list_objects_page as mock_list_page
	res.hook_filtered == true
	res.ids == ["doc_a"]
	res.has_more == true
	res.cursor == "doc_a"
}

# A short raw page (exhausted) → has_more false, cursor still present.
test_filtered_page_exhausted if {
	inp := object.union(_inp, {"page": {"limit": 5, "offset": 0}})
	res := data.authz.accessible_objects_page with input as inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
		with data.authz.pgauthz.config.require_token_for_reads as false
		with data.authz.pgauthz.list_objects_page as mock_list_page
	res.has_more == false
	count(res.ids) == 2
}

# Without the filtering flag, pages keep the raw array shape (refusal aside).
test_page_shape_unchanged_when_unfiltered if {
	inp := object.union(_inp, {"page": {"limit": 3, "offset": 0}})
	res := data.authz.accessible_objects_page with input as inp
		with data.authz.pgauthz.config.allow_unfiltered_enumeration as true
		with data.authz.pgauthz.config.require_token_for_reads as false
		with data.authz.pgauthz.list_objects_page as mock_list_page
	res == ["classified_x", "doc_a", "doc_b"]
}

# ── role-based exemption (verified actor.roles, e.g. Keycloak client roles) ──

# The ABI carries the PLATFORM-verified caller roles; without a token the
# actor is empty (trusted-PEP mode) and exemptions simply never match.
test_actor_roles_from_verified_token if {
	abi := data.authz._decision_hook_input with input as object.union(_inp, {"token": "t"})
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "user"
		with data.authn.subject_id as "alice"
		with data.authn.roles as {"auditor", "viewer"}
		with data.authn.actor_claims as {"realm_access": {"roles": ["ops"]}, "resource_access": {"document-api": {"roles": ["admin"]}}}
	abi.actor == {
		"id": "alice",
		"roles": ["auditor", "viewer"],
		"claims": {
			"realm_access": {"roles": ["ops"]},
			"resource_access": {"document-api": {"roles": ["admin"]}},
		},
	}
}

# The verbatim Keycloak claim structures make client-scoped exemptions
# expressible without any separator convention — URI client_ids are map keys.
test_actor_resource_access_uri_client if {
	abi := data.authz._decision_hook_input with input as object.union(_inp, {"token": "t"})
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "user"
		with data.authn.subject_id as "alice"
		with data.authn.roles as set()
		with data.authn.actor_claims as {"resource_access": {"https://sp.example.com/metadata": {"roles": ["admin"]}}}
	ra := object.get(abi.actor.claims, "resource_access", {})
	some r in object.get(ra, "https://sp.example.com/metadata", {}).roles
	r == "admin"
}

test_actor_empty_without_token if {
	abi := data.authz._decision_hook_input with input as _inp
	abi.actor == {"id": "", "roles": [], "claims": {}}
}

# An auditor's role EXEMPTS the classified veto — in checks and therefore in
# filtered listings too (same per-candidate evaluation).
test_auditor_role_unfilters_classified if {
	inp := object.union(_inp, {"token": "t"})
	ids := data.authz.accessible_objects with input as inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
		with data.authz.pgauthz.list_objects as mock_list
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "user"
		with data.authn.subject_id as "alice"
		with data.authn.roles as {"auditor"}
	ids == ["classified_x", "doc_a", "doc_b"] # nothing filtered for auditors
}

test_non_auditor_still_filtered if {
	inp := object.union(_inp, {"token": "t"})
	ids := data.authz.accessible_objects with input as inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
		with data.authz.pgauthz.list_objects as mock_list
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "user"
		with data.authn.subject_id as "bob"
		with data.authn.roles as {"viewer"}
	ids == ["doc_a", "doc_b"]
}

# The exemption cannot WIDEN: the graph answer still gates the actual check.
test_exemption_never_overrides_graph_deny if {
	inp := object.union(_inp, {"token": "t", "resource": {"type": "document", "id": "classified_x"}})
	not data.authz.allow with input as inp
		with data.authz.pgauthz.check_access as false
		with data.authn.token_is_valid as true
		with data.authn.subject_type as "user"
		with data.authn.subject_id as "alice"
		with data.authn.roles as {"auditor"}
}

# Malformed or out-of-range caps disable filtering entirely (→ refusal),
# never a silent fallback bound — tested through the REAL env parse path.
test_malformed_cap_refuses if {
	every bad in ["12x", "0", "200000", "-5", "1.5"] {
		data.authz.enumeration_refused with input as _inp
			with opa.runtime as {"env": {
				"HOOK_FILTERED_ENUMERATION": "true",
				"HOOK_FILTER_MAX_CANDIDATES": bad,
			}}
	}
}

test_valid_cap_enables_filtering if {
	not data.authz.enumeration_refused with input as _inp
		with opa.runtime as {"env": {
			"HOOK_FILTERED_ENUMERATION": "true",
			"HOOK_FILTER_MAX_CANDIDATES": "250",
		}}
}

# ── both flags set: filtering wins; broken filtering refuses, never superset ─

test_both_flags_filtering_wins if {
	ids := data.authz.accessible_objects with input as _inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
		with data.authz.pgauthz.config.allow_unfiltered_enumeration as true
		with data.authz.pgauthz.config.require_token_for_reads as false
		with data.authz.pgauthz.list_objects as mock_list
	ids == ["doc_a", "doc_b"] # filtered, NOT the raw superset
}

# Filtering configured but inoperable (env guard) → REFUSED even though the
# superset opt-out is also set: a config error must not downgrade "listings
# match checks" to "listings leak hidden objects".
test_both_flags_env_guard_refuses if {
	inp := object.remove(_inp, ["deployment"])
	data.authz.enumeration_refused with input as inp
		with data.authz.pgauthz.config.hook_filtered_enumeration as true
		with data.authz.pgauthz.config.allow_unfiltered_enumeration as true
}

test_both_flags_malformed_cap_refuses if {
	data.authz.enumeration_refused with input as _inp
		with opa.runtime as {"env": {
			"HOOK_FILTERED_ENUMERATION": "true",
			"ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS": "true",
			"HOOK_FILTER_MAX_CANDIDATES": "banana",
		}}
}
