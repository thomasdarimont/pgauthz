# Example GLOBAL DECISION hook (ADR 0011): finance documents are only
# accessible during business hours — a request-time business rule composed WITH
# the ReBAC graph answer (the relationship check still has to pass; a hook only
# narrows). Global hooks apply to every store.
#
# Copy this file, rename the package (one package per concern under
# authz.hooks.v1.global.*), and mount it into the OPA container — see README.md.
#
# Hooks are evaluated against the NORMALIZED input ABI (pgauthz.hooks/v1):
# subject (as the platform resolved it), action, resource, context, store, and
# a SERVER-derived `evaluated_at` (nanoseconds). Time-gated hooks read
# `evaluated_at` — never caller-supplied context.time — so they can't be
# spoofed and stay deterministic/testable. A plain-string denial is normalized
# to {tier, hook, code: "denied", message}.
package authz.hooks.v1.global.business_hours

import future.keywords.if

deny contains msg if {
	input.resource.type == "document"
	startswith(input.resource.id, "fin_")
	not _business_hours
	msg := sprintf("finance document %q is only accessible 08:00-18:00 Europe/Berlin", [input.resource.id])
}

_business_hours if {
	clock := time.clock([input.evaluated_at, "Europe/Berlin"])
	clock[0] >= 8
	clock[0] < 18
}
