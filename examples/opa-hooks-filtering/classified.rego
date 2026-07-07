# Probe hook for hook-FILTERED enumeration (ADR 0011): with
# HOOK_FILTERED_ENUMERATION=true, accessible_objects/subjects evaluate the
# applicable decision hooks per candidate — this hook's vetoes then disappear
# from listings exactly as they deny per-object checks.
package authz.hooks.v1.global.classified

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Objects: anything id-prefixed classified_ is invisible/denied — UNLESS the
# authenticated caller carries the app's "auditor" role. input.actor.roles is
# the PLATFORM-verified role set (authn.roles, aggregated from the configured
# JWT_ROLES_CLAIM paths — for Keycloak typically realm_access.roles plus the
# app client's resource_access.<client>.roles). A role-based exemption stays
# veto-only: it narrows THIS hook's denial; it can never grant what the graph
# denies.
deny contains {"code": "classified_object", "message": "classified resource"} if {
	startswith(object.get(object.get(input, "resource", {}), "id", ""), "classified_")
	not _caller_is_auditor
}

_caller_is_auditor if {
	some r in object.get(object.get(input, "actor", {}), "roles", [])
	r == "auditor"
}

# Subjects: contractors never appear in who-has-access listings.
deny contains {"code": "contractor_excluded", "message": "contractor subjects are excluded"} if {
	startswith(object.get(object.get(input, "subject", {}), "id", ""), "contractor_")
}
