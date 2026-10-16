package conformance_test

// The AuthZEN PDP plans of the OpenID conformance suite against pgauthzd. Skipped unless
// PGAUTHZ_CONFORMANCE_TESTS=true: a plan takes minutes and needs Docker (for the suite) and a
// running pgauthzd with the authzen_cert fixture loaded — tests/test-conformance.sh prepares
// both. The suite is started once per process; the https front and the api_key are shared too.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"thomasdarimont.de/authz/conformance"
)

const conformanceTests = "PGAUTHZ_CONFORMANCE_TESTS"

func TestMain(m *testing.M) {
	code := m.Run()
	closeShared()
	conformance.CloseSharedSuite()
	os.Exit(code)
}

var (
	sharedMu    sync.Mutex
	sharedProxy *conformance.Proxy
	sharedPDP   conformance.PDP
)

func closeShared() {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if sharedProxy != nil {
		sharedProxy.Close()
		sharedProxy = nil
	}
}

// pdpUnderTest starts the suite (once per process), checks that pgauthzd answers, puts the
// https front in front of it and mints the api_key; it returns the suite and the PDP as the
// suite sees it.
func pdpUnderTest(t *testing.T) (*conformance.Suite, conformance.PDP) {
	t.Helper()
	if os.Getenv(conformanceTests) != "true" {
		t.Skipf("Set %s=true to run the conformance suite in Docker against a running pgauthzd (minutes per plan)", conformanceTests)
	}
	settings := conformance.SettingsFromEnvironment()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// pgauthzd first — a missing daemon is the cheap failure, say so before the suite starts.
	target, err := url.Parse(settings.PGAuthzdURL)
	if err != nil {
		t.Fatalf("CTS_PGAUTHZD_URL: %v", err)
	}
	if err := checkReady(target); err != nil {
		t.Fatalf("pgauthzd under test is not ready at %s (start the demo stack with ALLOW_SUBJECT_OVERRIDE=true and load examples/models/authzen-cert, or point CTS_PGAUTHZD_URL elsewhere): %v", settings.PGAuthzdURL, err)
	}

	suite, err := conformance.SharedSuite(context.Background(), settings, log)
	if err != nil {
		t.Fatal(err)
	}

	sharedMu.Lock()
	defer sharedMu.Unlock()
	if sharedProxy == nil {
		proxy, err := conformance.StartProxy(target, settings.PDPPort)
		if err != nil {
			t.Fatal(err)
		}
		apiKey, err := conformance.MintAPIKey(settings.SigningKey, settings.KeyID, settings.Issuer, settings.Audience, 12*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		sharedProxy = proxy
		sharedPDP = conformance.PDP{BaseURL: proxy.URL(suite.PDPHost()) + "/stores/" + settings.Store, APIKey: apiKey}
		t.Logf("PDP under test: %s (https front for %s)", sharedPDP.BaseURL, settings.PGAuthzdURL)
	}
	return suite, sharedPDP
}

func checkReady(base *url.URL) error {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(base.String() + "/readyz")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /readyz returned HTTP %d", response.StatusCode)
	}
	return nil
}

func TestEvaluationPlan(t *testing.T) {
	suite, pdp := pdpUnderTest(t)
	conformance.RunPlan(t, suite, conformance.Evaluation, pdp)
}

func TestEvaluationsPlan(t *testing.T) {
	suite, pdp := pdpUnderTest(t)
	conformance.RunPlan(t, suite, conformance.Evaluations, pdp)
}

func TestSubjectSearchPlan(t *testing.T) {
	suite, pdp := pdpUnderTest(t)
	conformance.RunPlan(t, suite, conformance.SubjectSearch, pdp)
}

func TestResourceSearchPlan(t *testing.T) {
	suite, pdp := pdpUnderTest(t)
	conformance.RunPlan(t, suite, conformance.ResourceSearch, pdp)
}

func TestActionSearchPlan(t *testing.T) {
	suite, pdp := pdpUnderTest(t)
	conformance.RunPlan(t, suite, conformance.ActionSearch, pdp)
}

// The comprehensive plan is not part of the certification program; it checks the optional
// short-circuit semantics, which pgauthzd implements (the response array ends with the
// decision that stopped processing).
func TestEvaluationsComprehensivePlan(t *testing.T) {
	suite, pdp := pdpUnderTest(t)
	conformance.RunPlan(t, suite, conformance.EvaluationsComprehensive, pdp)
}
