# Example WRITE-GOVERNANCE hook (ADR 0011): rules every tuple write must pass,
# regardless of who is authorized to write. Applies to all write operations
# (write/delete/batch/checked) — _all_tuples gathers every shape.
package authz.hooks.v1.global.tuple_rules

import future.keywords.if
import future.keywords.in

# No public-access wildcards through this pipeline. A structured denial
# carries a stable machine-readable code alongside the message.
deny_write contains {"code": "wildcard_forbidden", "message": "wildcard subjects (user_id \"*\") are forbidden"} if {
	some t in _all_tuples
	t.user_id == "*"
}

# Ownership changes are an offboarding-tool concern, not an API write.
deny_write contains {"code": "reserved_relation", "message": sprintf("relation %q may not be written via the API", [t.relation])} if {
	some t in _all_tuples
	t.relation == "owner"
}

_all_tuples contains t if t := input.tuple

_all_tuples contains t if some t in object.get(input, "tuples", [])

_all_tuples contains t if some t in object.get(input, "writes", [])
