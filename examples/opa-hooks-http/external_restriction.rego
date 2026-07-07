# Reference GLOBAL http.send hook (ADR 0011): read-only lookup against an
# approved policy service, with the REQUIRED accepted-status contract.
#
# WHY THE EXPLICIT STATUS HANDLING: an HTTP 404/429/500/503 response is a
# SUCCESSFUL execution of http.send — it returns an ordinary response object,
# so `raise_error` + strict-builtin-errors do NOT fire. A hook written as
# `status_code == 200; body.restricted` is simply undefined on a 503 and
# contributes no denial: it FAILS OPEN. Responses outside the declared
# success-status set must therefore produce a denial themselves.
# (Transport failures and timeouts DO raise builtin errors and fail the whole
# query closed via strict-builtin-errors — that path needs no handling here.)
#
# Tenant isolation means hooks cannot import shared helpers (a hook may only
# reference its own package), so this pattern is INLINED per hook — copy it.
package authz.hooks.v1.global.external_restriction

import future.keywords.contains
import future.keywords.if

_resp := http.send({
	"method": "GET",
	"url": "https://policy.internal.example/v1/restrictions",
	"timeout": "500ms",
	"headers": {"Accept": "application/json"},
})

# Any status outside the declared success set = the external policy source is
# unavailable → DENY (fail closed), never "no opinion".
deny contains {
	"code": "external_policy_unavailable",
	"message": sprintf("restriction service returned status %d", [_resp.status_code]),
} if {
	_resp.status_code != 200
}

# A 200 whose body doesn't carry the expected boolean is malformed → DENY.
# (A non-object body makes object.get raise a type error, which
# strict-builtin-errors turns into a fail-closed query error — also safe.)
_restricted := object.get(object.get(_resp, "body", {}), "restricted", null)

deny contains {
	"code": "external_policy_malformed",
	"message": "restriction service returned 200 without a boolean 'restricted' field",
} if {
	_resp.status_code == 200
	not is_boolean(_restricted)
}

# The actual business rule — only reachable on a well-formed success response.
deny contains {
	"code": "external_restriction",
	"message": "restricted by external policy service",
} if {
	_resp.status_code == 200
	_restricted == true
}
