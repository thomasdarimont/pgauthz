# Example OPERATOR extension library (ADR 0011): shared helpers your own
# hooks may import, under the reserved extension namespace
# authz.hooks.lib.v1.ext.<name>. Same contract as the platform library —
# functions only, pure builtins (never http.send: a shared lib with network
# access would hand it to every caller, including network-free store hooks) —
# enforced by:  scripts/validate-hooks.sh --lib <dir>
# Ext libs may build on the platform library (authz.hooks.lib.v1.keycloak).
package authz.hooks.lib.v1.ext.acme

import future.keywords.if
import future.keywords.in

import data.authz.hooks.lib.v1.keycloak

# within_utc_hours(input.evaluated_at, 6, 22) — time windows on the
# server-derived timestamp (never caller context).
within_utc_hours(evaluated_at_ns, from_h, to_h) if {
	hour := time.clock([evaluated_at_ns, "UTC"])[0]
	hour >= from_h
	hour < to_h
}

# is_operator(input.actor) — composes the platform keycloak module: an
# operator is a realm ops-role holder OR an ops-portal client admin.
is_operator(actor) if keycloak.has_realm_role(actor, "ops")

is_operator(actor) if keycloak.has_client_role(actor, "ops-portal", "admin")
