package hooks_lib_test

import future.keywords.if

import data.authz.hooks.lib.v1.keycloak

_actor := {"id": "alice", "roles": [], "claims": {
	"realm_access": {"roles": ["ops"]},
	"resource_access": {
		"document-api": {"roles": ["exporter"]},
		"https://sp.example.com/metadata": {"roles": ["admin"]},
	},
}}

test_realm_role if {
	keycloak.has_realm_role(_actor, "ops")
	not keycloak.has_realm_role(_actor, "exporter") # client role is NOT a realm role
}

test_client_role_is_client_scoped if {
	keycloak.has_client_role(_actor, "document-api", "exporter")
	not keycloak.has_client_role(_actor, "billing-api", "exporter")
	keycloak.has_client_role(_actor, "https://sp.example.com/metadata", "admin")
}

# Tokenless / non-Keycloak actors fail closed on every helper.
test_empty_actor_fails_closed if {
	empty := {"id": "", "roles": [], "claims": {}}
	not keycloak.has_realm_role(empty, "ops")
	not keycloak.has_client_role(empty, "document-api", "exporter")
	keycloak.realm_roles(empty) == []
	keycloak.client_roles(empty, "document-api") == []
}
