# Example STORE-SCOPED hook (ADR 0011): applies ONLY to the `demo` store —
# other tenants' requests never evaluate it. Store hooks live under
# authz.hooks.v1.stores.<store>.<name>; a tenant owns its own directory /
# ConfigMap, validated to its store with `validate-hooks.sh --store demo`.
#
# This one is a write-governance rule for the demo tenant: no deletes via the
# API (offboarding uses the dedicated tooling), and no cross-tenant subject ids.
package authz.hooks.v1.stores.demo.tenant_guard

import future.keywords.if
import future.keywords.in

# Deletes in the demo store must go through offboarding tooling, not the API.
deny_write contains {"code": "delete_forbidden", "message": "deletes in the demo store are not permitted via the API"} if {
	input.operation in {"delete", "delete_batch", "delete_user"}
}

# A decision hook, demo-only: block a demonstrably foreign subject id shape.
deny contains {"code": "foreign_subject", "message": "external subjects are not evaluated in the demo store"} if {
	startswith(input.subject.id, "ext_")
}

# A write hook using `actor` (the authenticated caller) — distinct from the
# tuple subject: only the provisioner service account may grant `editor`.
deny_write contains {"code": "editor_grant_restricted", "message": "only the provisioner may grant editor in demo"} if {
	some t in _all_tuples
	t.relation == "editor"
	input.actor.id != "service-account:provisioner"
}

_all_tuples contains t if t := input.tuple

_all_tuples contains t if some t in object.get(input, "tuples", [])

_all_tuples contains t if some t in object.get(input, "writes", [])
