# Global decision hook: gate sensitive actions on the caller's VERIFIED
# claims (ADR 0011) — the actor.claims patterns in one place, using the
# platform hook library (import data.authz.hooks.lib.v1.keycloak) for the
# Keycloak role checks and a raw-claims read for the custom "groups" claim.
#
# input.actor.claims carries verbatim copies of verified-token claims,
# selected by HOOK_ACTOR_CLAIMS (default: Keycloak's realm_access +
# resource_access; anything beyond that — like the "groups" claim below —
# must be listed explicitly, e.g.
# HOOK_ACTOR_CLAIMS=realm_access,resource_access,groups).
#
# Three rules, all fail-closed by construction: a missing claim, an absent
# client entry, or a tokenless caller (actor.claims == {}) never satisfies an
# exemption — the denial then applies.
package authz.hooks.v1.global.claims_guard

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.authz.hooks.lib.v1.keycloak

# Exports need the "exporter" CLIENT role of the document-api client — read
# from the verbatim resource_access structure, so an identically named role
# on another client does NOT qualify (client_ids are map keys; URI-shaped
# SAML entity IDs work the same way).
deny contains {
	"code": "export_requires_client_role",
	"message": "can_export requires the document-api client role 'exporter'",
} if {
	input.action == "can_export"
	not keycloak.has_client_role(input.actor, "document-api", "exporter")
}

# Restricted resources need membership in the "compliance" group — a CUSTOM
# claim, present only when HOOK_ACTOR_CLAIMS includes "groups". Absence of
# the claim (not configured, not in the token, no token at all) is treated
# as most-restrictive: the denial applies.
deny contains {
	"code": "restricted_requires_compliance_group",
	"message": "restricted resources require the compliance group",
} if {
	startswith(object.get(object.get(input, "resource", {}), "id", ""), "restricted_")
	not _in_group("compliance")
}

_in_group(g) if {
	some x in object.get(input.actor.claims, "groups", [])
	x == g
}

# Destructive actions require the REALM role "records_officer" — read from
# the verbatim realm_access structure. Realm roles are realm-wide (unlike
# the client-scoped roles above), so this is the right gate for privileges
# that span applications.
deny contains {
	"code": "delete_requires_realm_role",
	"message": "destructive actions require the realm role 'records_officer'",
} if {
	input.action in {"can_delete", "can_purge"}
	not keycloak.has_realm_role(input.actor, "records_officer")
}
