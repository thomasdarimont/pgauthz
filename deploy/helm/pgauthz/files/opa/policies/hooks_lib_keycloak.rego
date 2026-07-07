# Platform-provided hook LIBRARY (ADR 0011): shared, versioned helper
# functions hooks may call — the ONE namespace besides its own package a hook
# is allowed to reference (validate-hooks.sh allowlists authz.hooks.lib.v1).
#
# Why this doesn't break tenant isolation: the library is PLATFORM-owned,
# ships and is signed together with the platform policy (never tenant-
# mounted), lives OUTSIDE the aggregated hook namespace (authz.hooks.lib.v1,
# not authz.hooks.v1 — the aggregator never iterates it), and contains pure
# FUNCTIONS over their arguments only — no rules over request or tenant
# state. It is versioned like the input ABI: additive changes only within
# v1; a breaking change becomes authz.hooks.lib.v2.
#
# Usage in a hook:
#   import data.authz.hooks.lib.v1.keycloak
#   deny contains {...} if { not keycloak.has_realm_role(input.actor, "records_officer") }
package authz.hooks.lib.v1.keycloak

import future.keywords.if
import future.keywords.in

# All helpers read the VERBATIM Keycloak claim structures under actor.claims
# (HOOK_ACTOR_CLAIMS default) and are undefined-safe: absent claims, absent
# clients, or a tokenless actor never satisfy a check — `not keycloak.…`
# gates therefore fail closed.

# has_realm_role(input.actor, "records_officer") — realm-wide privileges.
has_realm_role(actor, role) if {
	some r in realm_roles(actor)
	r == role
}

# has_client_role(input.actor, "document-api", "exporter") — client-scoped:
# an identically named role on ANOTHER client does not qualify. The client
# key is used verbatim (URI-shaped SAML entity IDs work unchanged).
has_client_role(actor, client, role) if {
	some r in client_roles(actor, client)
	r == role
}

# The raw role lists, for set-style checks (e.g. intersections).
realm_roles(actor) := object.get(
	object.get(object.get(actor, "claims", {}), "realm_access", {}),
	"roles", [],
)

client_roles(actor, client) := object.get(
	object.get(object.get(object.get(actor, "claims", {}), "resource_access", {}), client, {}),
	"roles", [],
)
