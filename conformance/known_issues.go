package conformance

import "strings"

// KnownSuiteIssue is a defect of the conformance suite itself that makes a module fail for a
// reason unrelated to the PDP. RunPlan skips a module whose failure matches one, so a suite
// bug does not mask a PDP regression and the plan still ends green; a module that PASSES
// despite its entry is reported, so the entry is removed once the suite is fixed.
type KnownSuiteIssue struct {
	// Module is the suite's test module name.
	Module string
	// Failure is a substring of the FAILURE the suite logs when the issue strikes.
	Failure string
	// Reason says what is wrong, for the skip message.
	Reason string
	// Issue is the suite's issue tracking the defect.
	Issue string
}

// KnownSuiteIssues as of release-v5.3.2.
var KnownSuiteIssues = []KnownSuiteIssue{
	{
		Module:  "authzen-pdp-evaluation-invalid-credentials-returns-401",
		Failure: "couldn't find required object in environment before evaluation: client",
		Reason: "CorruptAuthzenClientCredentials requires a `client` environment object (@PreEnvironment), " +
			"but the AuthZEN flow never creates one — no condition copies config.client into the environment, " +
			"for pdp_auth_type=api_key (which has no client section) or otherwise — so the module is INTERRUPTED " +
			"before it calls the PDP. The PDP's 401 for a bad token is covered by pgauthzd's own tests " +
			"(tests/test-authzen.sh) until the suite is fixed.",
		Issue: "https://gitlab.com/openid/conformance-suite/-/work_items/2040",
	},
	{
		// Every module of a discovery-variant plan; TestDiscoveryPlans is skipped as a whole
		// until the suite is fixed (CTS_DISCOVERY=true runs it anyway), this entry documents why.
		Module:  "*",
		Failure: "'PDP API Key' field is missing from the 'AuthZEN' section in the test configuration",
		Reason: "With pdp_server_metadata=discovery, GetPDPDynamicServerConfiguration stores the fetched metadata " +
			"as the `pdp` environment object, replacing the configured one that carried pdp.api_key; " +
			"AddApiKeyAuthenticationParametersToAuthzenApiRequest then finds no key and the module is " +
			"INTERRUPTED before it calls the PDP. The static variant keeps the configured object " +
			"(GetPDPStaticServerConfiguration) and works.",
		Issue: "https://gitlab.com/openid/conformance-suite/-/work_items/2041",
	},
}

// knownIssue returns the known suite issue a failed module matches, if any.
func knownIssue(result ModuleResult) (KnownSuiteIssue, bool) {
	for _, issue := range KnownSuiteIssues {
		if issue.Module != "*" && issue.Module != result.Module.Name {
			continue
		}
		for _, problem := range result.Problems() {
			if strings.Contains(problem, issue.Failure) {
				return issue, true
			}
		}
	}
	return KnownSuiteIssue{}, false
}
