package acme_lib_test

import future.keywords.if

import data.authz.hooks.lib.v1.ext.acme

_ops := {"id": "o", "roles": [], "claims": {"realm_access": {"roles": ["ops"]}}}

_portal := {"id": "p", "roles": [], "claims": {"resource_access": {"ops-portal": {"roles": ["admin"]}}}}

test_within_hours if {
	acme.within_utc_hours(1783430000000000000, 0, 24)
	not acme.within_utc_hours(1783430000000000000, 0, 0)
}

test_is_operator_composes_platform_lib if {
	acme.is_operator(_ops)
	acme.is_operator(_portal)
	not acme.is_operator({"id": "x", "roles": [], "claims": {}})
}
