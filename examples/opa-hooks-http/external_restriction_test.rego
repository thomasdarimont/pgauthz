# Contract tests for the accepted-status pattern (ADR 0011): HTTP error
# statuses are ORDINARY http.send responses — a network hook must deny on
# them itself. Transport failure/timeout raise builtin errors and are failed
# closed by strict-builtin-errors at the platform layer (covered by the Go
# suite), so the mocks here cover the response-object cases.
# NOTE the package: test files must live OUTSIDE authz.hooks.v1.* — the
# aggregator iterates every package in that namespace, so an in-namespace
# test would be treated as a hook (and recursive when it queries the
# pipeline).
package external_restriction_contract_test

import future.keywords.if
import future.keywords.in

import data.authz.hooks.v1.global.external_restriction as hook

_abi := {
	"api_version": "pgauthz.hooks/v1", "operation": "decision",
	"evaluated_at": 1700000000000000000,
	"deployment": {"environment": "test"},
	"store": "demo",
	"subject": {"type": "user", "id": "alice"},
	"action": "can_read",
	"resource": {"type": "document", "id": "d1"},
	"context": {},
}

mock_ok_clean(_) := {"status_code": 200, "body": {"restricted": false}}

mock_ok_restricted(_) := {"status_code": 200, "body": {"restricted": true}}

mock_404(_) := {"status_code": 404, "body": {}}

mock_429(_) := {"status_code": 429, "body": {}}

mock_500(_) := {"status_code": 500, "body": {}}

mock_503(_) := {"status_code": 503, "body": {}}

mock_missing_field(_) := {"status_code": 200, "body": {"note": "no restricted key"}}

mock_wrong_type(_) := {"status_code": 200, "body": {"restricted": "yes"}}

mock_no_body(_) := {"status_code": 200}

test_clean_success_no_denial if {
	count(hook.deny) == 0 with input as _abi with http.send as mock_ok_clean
}

test_restricted_denies if {
	some d in hook.deny with input as _abi with http.send as mock_ok_restricted
	d.code == "external_restriction"
}

# THE FAIL-CLOSED CONTRACT: every non-200 must produce a denial.
test_404_denies_unavailable if {
	some d in hook.deny with input as _abi with http.send as mock_404
	d.code == "external_policy_unavailable"
}

test_429_denies_unavailable if {
	some d in hook.deny with input as _abi with http.send as mock_429
	d.code == "external_policy_unavailable"
}

test_500_denies_unavailable if {
	some d in hook.deny with input as _abi with http.send as mock_500
	d.code == "external_policy_unavailable"
}

test_503_denies_unavailable if {
	some d in hook.deny with input as _abi with http.send as mock_503
	d.code == "external_policy_unavailable"
}

# Malformed 200s: missing field, wrong type, missing body — all deny.
test_missing_field_denies_malformed if {
	some d in hook.deny with input as _abi with http.send as mock_missing_field
	d.code == "external_policy_malformed"
}

test_wrong_type_denies_malformed if {
	some d in hook.deny with input as _abi with http.send as mock_wrong_type
	d.code == "external_policy_malformed"
}

test_missing_body_denies_malformed if {
	some d in hook.deny with input as _abi with http.send as mock_no_body
	d.code == "external_policy_malformed"
}

# End-to-end through the AGGREGATOR: a 503 vetoes the decision.
test_unavailable_vetoes_via_aggregator if {
	not data.authz.allow with input as _abi with http.send as mock_503
		with data.authz.pgauthz.check_access as false
	some d in data.authz.hook_denials with input as _abi with http.send as mock_503
	d.code == "external_policy_unavailable"
	d.tier == "global"
}
