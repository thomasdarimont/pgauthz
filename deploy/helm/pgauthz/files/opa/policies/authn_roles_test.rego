package authn_roles_test

import future.keywords.if
import future.keywords.in

_kc_claims := {
	"realm_access": {"roles": ["ops"]},
	"resource_access": {
		"document-api": {"roles": ["admin"]},
		"billing-api": {"roles": ["admin"]},
	},
}

_kc_paths := [["realm_access", "roles"], ["resource_access", "document-api", "roles"], ["resource_access", "billing-api", "roles"]]

# Default (flat, released behavior): identically named client roles COLLAPSE —
# the documented reason exemption roles must be globally unambiguous.
test_flat_aggregation_collapses_client_roles if {
	rs := data.authn.roles with data.authn.claims as _kc_claims
		with data.authn.token_is_valid as true
		with data.authn.config.roles_claim_paths as _kc_paths
	rs == {"ops", "admin"}
}

# JWT_ROLES_SOURCE_PREFIX=true: roles carry their provenance — realm roles
# as realm::<role>, client roles as <client_id>::<role>. "::" because
# client_ids may be URIs (SAML entity IDs), where "." is ambiguous.
test_source_prefix_disambiguates if {
	rs := data.authn.roles with data.authn.claims as _kc_claims
		with data.authn.token_is_valid as true
		with data.authn.config.roles_claim_paths as _kc_paths
		with data.authn.config.source_prefix_roles as true
	rs == {"realm::ops", "document-api::admin", "billing-api::admin"}
}

# URI client_ids (SAML entity IDs) stay unambiguous with the :: separator.
test_source_prefix_uri_client_id if {
	claims := {"resource_access": {"https://sp.example.com/metadata": {"roles": ["admin"]}}}
	rs := data.authn.roles with data.authn.claims as claims
		with data.authn.token_is_valid as true
		with data.authn.config.roles_claim_paths as [["resource_access", "https://sp.example.com/metadata", "roles"]]
		with data.authn.config.source_prefix_roles as true
	rs == {"https://sp.example.com/metadata::admin"}
}

# The prefix only applies to Keycloak-shaped paths — a plain custom "roles"
# claim is untouched even with the flag on.
test_plain_claim_unaffected_by_prefix_flag if {
	rs := data.authn.roles with data.authn.claims as {"roles": ["authz_writer"]}
		with data.authn.token_is_valid as true
		with data.authn.config.roles_claim_paths as [["roles"]]
		with data.authn.config.source_prefix_roles as true
	rs == {"authz_writer"}
}

# The DEFAULT actor-claims selection copies the Keycloak role structures
# verbatim (same names, same shapes) — the separator-free way to consume
# role provenance.
test_default_actor_claims_are_keycloak_structures if {
	out := data.authn.actor_claims with data.authn.claims as _kc_claims
		with data.authn.token_is_valid as true
	out == {
		"realm_access": {"roles": ["ops"]},
		"resource_access": {"document-api": {"roles": ["admin"]}, "billing-api": {"roles": ["admin"]}},
	}
}

# HOOK_ACTOR_CLAIMS: operator-selected claims copied verbatim — names taken
# whole (URI claim names with dots work), missing claims absent, unlisted
# claims never copied.
test_actor_claims_selection if {
	claims := {
		"groups": ["eng", "sec"],
		"https://example.com/entitlements": {"tier": "gold"},
		"email": "alice@example.com",
	}
	out := data.authn.actor_claims with data.authn.claims as claims
		with data.authn.token_is_valid as true
		with data.authn.config.actor_claims as ["groups", "https://example.com/entitlements", "department"]
	out == {
		"groups": ["eng", "sec"],
		"https://example.com/entitlements": {"tier": "gold"},
		# department missing from token -> absent; email unlisted -> not copied
	}
}
