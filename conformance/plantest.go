package conformance

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// ModuleTimeout is how long a module of a plan may take. A PDP module is a handful of HTTP
// calls; the idempotency and pagination loops are the longest.
const ModuleTimeout = 3 * time.Minute

// RunPlan runs a plan of the OpenID conformance suite against the PDP: creates the plan in the
// suite and runs every module of it as a subtest. A module passes when the suite finished it
// with PASSED, or with WARNING unless Settings.Strict (certification tolerates warnings — the
// SHOULDs — but a new one is worth a look, so they are logged). A module that fails the way a
// KnownSuiteIssue describes is skipped with the reason. Anything else fails with the failures
// and warnings the suite logged and the link to the suite's log page.
func RunPlan(t *testing.T, suite *Suite, plan PlanDefinition, pdp PDP) {
	t.Helper()
	ctx := context.Background()
	config, err := plan.Config(pdp)
	if err != nil {
		t.Fatal(err)
	}
	created, err := suite.Client().CreatePlan(ctx, plan.Name, plan.Variant(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Created plan %s %v with %d modules: %s", plan.Name, plan.Variant(), len(created.Modules), created.URL)
	for _, module := range created.Modules {
		t.Run(module.Name, func(t *testing.T) {
			moduleID, err := suite.Client().StartModule(ctx, created, module)
			if err != nil {
				t.Fatal(err)
			}
			result, err := suite.Client().AwaitResult(ctx, created, module, moduleID, ModuleTimeout)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case result.FinishedWith("PASSED"):
				t.Logf("PASSED %s", result.URL)
				for _, issue := range KnownSuiteIssues {
					if issue.Module == module.Name {
						t.Logf("NOTE: %s passed although a known suite issue is recorded for it — the suite may be fixed, remove the KnownSuiteIssues entry", module.Name)
					}
				}
			case result.FinishedWith("WARNING") && !suite.Settings().Strict:
				t.Logf("WARNING (accepted; CTS_STRICT=true fails it): %s", result.Summary())
			default:
				if issue, ok := knownIssue(result); ok {
					t.Skipf("known conformance suite issue, not a PDP failure (%s): %s", result.URL, issue.Reason)
				}
				logs, _ := json.MarshalIndent(result.Logs, "", "  ")
				t.Logf("Full log of the failed module %s:\n%s", module, logs)
				t.Fatal(result.Summary())
			}
		})
	}
}
