// Package conformance runs the OpenID conformance suite's AuthZEN PDP test plans against
// pgauthzd: the suite started with Testcontainers, an https front for the daemon (the suite
// refuses plain http), the PEP credential the suite authenticates with, and one test per plan
// that runs every module and asserts the result the suite reports. A module of its own
// (thomasdarimont.de/authz/conformance) so that the Docker client it needs stays out of pgauthzd.
//
// The suite plays the PEP (https://openid.net/certification/authzen_testing/): it sends the
// requests of the certification profile (openid/authzen issue #433) to the PDP's endpoints and
// checks the decisions, the search results and the error handling. pgauthzd answers from the
// authzen_cert store — the fixture in examples/models/authzen-cert — selected by the tenant
// path /stores/authzen_cert, so the instance's DEFAULT_STORE does not matter.
//
// The plan tests (plans_test.go) are skipped unless PGAUTHZ_CONFORMANCE_TESTS=true, as a plan
// takes minutes and needs Docker and a running pgauthzd (tests/test-conformance.sh prepares
// both the fixture and the run).
package conformance
