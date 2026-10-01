package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeJWKS(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(p, []byte(`{"keys":[{"kty":"RSA","kid":"k1","n":"AQAB","e":"AQAB"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// resetEnv clears every variable the daemon reads so a test starts clean.
func resetEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"DEPLOYMENT_ENVIRONMENT", "SEARCH_REQUIRED_ROLE", "EXPLAIN_REQUIRED_ROLE", "WATCH_REQUIRED_ROLE",
		"ALLOW_OPEN_DIAGNOSTICS", "INTERNAL_SERVICE_TOKEN", "INTERNAL_LISTEN_ADDR", "DATABASE_URL", "OPA_URL", "CURSOR_SEAL_KEY",
		"ALLOW_SUBJECT_OVERRIDE", "METRICS_LISTEN_ADDR", "DECISION_LOG", "JWKS_URL", "JWKS_FILE", "JWT_ISSUER", "JWT_AUDIENCE", "JWT_ISSUERS",
		"ALLOW_MISSING_AUDIENCE", "ALLOW_UNBOUND_MULTI_ISSUER", "REQUIRE_STORE_BINDING"} {
		t.Setenv(k, "")
	}
}

func byName(r *Report) map[string]Check {
	m := map[string]Check{}
	for _, c := range r.Checks {
		m[c.Name] = c
	}
	return m
}

func TestDoctorDemoDevConfigWarns(t *testing.T) {
	resetEnv(t)
	jwks := writeJWKS(t)
	t.Setenv("JWT_ISSUERS", `[{"issuer":"https://auth.example.com","audience":"authz-api","jwks_file":"`+jwks+`","stores":["demo"]}]`)
	t.Setenv("INTERNAL_LISTEN_ADDR", ":8081")
	t.Setenv("INTERNAL_SERVICE_TOKEN", "dev-native-service-token")
	t.Setenv("OPA_URL", "http://127.0.0.1:1") // unreachable
	t.Setenv("ALLOW_SUBJECT_OVERRIDE", "true")

	r := Run(context.Background(), Options{Version: "test", HTTP: &http.Client{}})
	c := byName(r)
	if c["config"].Status != StatusOK {
		t.Fatalf("config: %+v", c["config"])
	}
	if c["production profile"].Status != StatusWarn {
		t.Fatalf("production profile should warn when not production: %+v", c["production profile"])
	}
	if c["diagnostic surfaces"].Status != StatusWarn || !strings.Contains(c["diagnostic surfaces"].Detail, "search") {
		t.Fatalf("open surfaces should warn outside production: %+v", c["diagnostic surfaces"])
	}
	if c["demo secrets"].Status != StatusWarn || !strings.Contains(c["demo secrets"].Detail, "INTERNAL_SERVICE_TOKEN") || !strings.Contains(c["demo secrets"].Detail, "auth.example.com") {
		t.Fatalf("demo secrets: %+v", c["demo secrets"])
	}
	if c["jwks"].Status != StatusOK {
		t.Fatalf("jwks file should load: %+v", c["jwks"])
	}
	if c["subject override"].Status != StatusWarn {
		t.Fatalf("subject override: %+v", c["subject override"])
	}
	if c["opa"].Status != StatusFail {
		t.Fatalf("unreachable OPA should fail: %+v", c["opa"])
	}
	if c["database"].Status != StatusSkip {
		t.Fatalf("DB-less OPA gateway should skip the DB probe: %+v", c["database"])
	}
	if c["cursor seal key"].Status != StatusWarn {
		t.Fatalf("cursor seal key: %+v", c["cursor seal key"])
	}
	if r.ExitCode(false) != 1 || r.Failed != 1 {
		t.Fatalf("exit/failed = %d/%d, want 1/1 (opa)", r.ExitCode(false), r.Failed)
	}
}

func TestDoctorProductionProfileFailsOpenSurfaces(t *testing.T) {
	resetEnv(t)
	jwks := writeJWKS(t)
	t.Setenv("JWT_ISSUERS", `[{"issuer":"https://idp.example","audience":"api","jwks_file":"`+jwks+`","stores":["t1"]}]`)
	t.Setenv("DATABASE_URL", "postgres://svc:s3cret@db:5432/authz")
	// no diagnostic roles → the production profile refuses to load, exactly as the daemon would
	r := Run(context.Background(), Options{ForceProduction: true, HTTP: &http.Client{}})
	if r.Checks[0].Name != "config" || r.Checks[0].Status != StatusFail || !strings.Contains(r.Checks[0].Detail, "production") {
		t.Fatalf("production profile must fail at config load: %+v", r.Checks[0])
	}
	if r.ExitCode(false) != 1 {
		t.Fatal("exit code must be 1")
	}
}

func TestDoctorProductionCleanConfig(t *testing.T) {
	resetEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/certs":
			w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"k1","n":"AQAB","e":"AQAB"}]}`))
		case "/health":
			w.Write([]byte(`{}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	t.Setenv("JWT_ISSUERS", `[{"issuer":"https://idp.example","audience":"api","jwks_url":"`+srv.URL+`/certs","stores":["t1"]}]`)
	t.Setenv("SEARCH_REQUIRED_ROLE", "authz_auditor")
	t.Setenv("EXPLAIN_REQUIRED_ROLE", "authz_auditor")
	t.Setenv("OPA_URL", srv.URL)
	t.Setenv("CURSOR_SEAL_KEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("METRICS_LISTEN_ADDR", ":9090")
	t.Setenv("INTERNAL_LISTEN_ADDR", ":8081")
	t.Setenv("INTERNAL_SERVICE_TOKEN", "a-real-secret")

	r := Run(context.Background(), Options{ForceProduction: true, HTTP: srv.Client()})
	c := byName(r)
	for _, name := range []string{"config", "production profile", "diagnostic surfaces", "demo secrets", "issuers", "issuer store bindings", "jwks", "subject override", "cursor seal key", "opa", "metrics"} {
		if c[name].Status != StatusOK {
			t.Errorf("%s: %+v", name, c[name])
		}
	}
	if c["callback listener"].Status != StatusWarn { // no mTLS in production → warn
		t.Errorf("callback listener: %+v", c["callback listener"])
	}
	if r.Failed != 0 || r.ExitCode(false) != 0 {
		t.Fatalf("clean production config must pass: failed=%d checks=%+v", r.Failed, r.Checks)
	}
	if r.ExitCode(true) != 2 {
		t.Fatal("--strict must exit 2 on warnings")
	}
	var buf bytes.Buffer
	r.Print(&buf)
	if !strings.Contains(buf.String(), "OK") || !strings.Contains(buf.String(), "0 failed") {
		t.Fatalf("print: %s", buf.String())
	}
	if b, err := json.Marshal(r); err != nil || !strings.Contains(string(b), `"checks"`) {
		t.Fatalf("json: %v %s", err, b)
	}
}

func TestDBPassword(t *testing.T) {
	cases := map[string]string{
		"postgres://authz:authz@db:5432/authz":        "authz",
		"postgres://u:p%40ss@h/db":                    "p%40ss",
		"host=db user=u password=secret dbname=authz": "secret",
		"postgres://u@h/db":                           "",
	}
	for in, want := range cases {
		if got := dbPassword(in); got != want {
			t.Errorf("dbPassword(%q) = %q, want %q", in, got, want)
		}
	}
}

// `doctor --profile production` must report ALLOW_MISSING_AUDIENCE=true as a
// fatal config finding (the daemon would refuse to start with it), even when
// the issuer itself pins an audience.
func TestDoctorProductionProfileRejectsMissingAudienceOverride(t *testing.T) {
	resetEnv(t)
	jwks := writeJWKS(t)
	t.Setenv("JWT_ISSUERS", `[{"issuer":"https://auth.example.com","audience":"authz-api","jwks_file":"`+jwks+`","stores":["demo"]}]`)
	t.Setenv("SEARCH_REQUIRED_ROLE", "authz_auditor")
	t.Setenv("EXPLAIN_REQUIRED_ROLE", "authz_auditor")
	t.Setenv("ALLOW_MISSING_AUDIENCE", "true")

	r := Run(context.Background(), Options{Version: "test", HTTP: &http.Client{}, ForceProduction: true})
	c := byName(r)
	if c["config"].Status != StatusFail || !strings.Contains(c["config"].Detail, "ALLOW_MISSING_AUDIENCE=true is forbidden") {
		t.Fatalf("production profile must fail on the audience override: %+v", c["config"])
	}
	if r.ExitCode(false) != 1 {
		t.Fatalf("exit code: %d", r.ExitCode(false))
	}
}

// `doctor --profile production` fails on ALLOW_UNBOUND_MULTI_ISSUER=true and
// warns about a single unbound issuer (legal, but a choice to make explicit).
func TestDoctorProductionProfileIssuerBindings(t *testing.T) {
	resetEnv(t)
	jwks := writeJWKS(t)
	base := func(t *testing.T) {
		t.Helper()
		t.Setenv("SEARCH_REQUIRED_ROLE", "authz_auditor")
		t.Setenv("EXPLAIN_REQUIRED_ROLE", "authz_auditor")
	}
	t.Run("override is fatal", func(t *testing.T) {
		base(t)
		t.Setenv("JWT_ISSUERS", `[{"issuer":"https://auth.example.com","audience":"authz-api","jwks_file":"`+jwks+`","stores":["demo"]}]`)
		t.Setenv("ALLOW_UNBOUND_MULTI_ISSUER", "true")
		r := Run(context.Background(), Options{Version: "test", HTTP: &http.Client{}, ForceProduction: true})
		c := byName(r)
		if c["config"].Status != StatusFail || !strings.Contains(c["config"].Detail, "ALLOW_UNBOUND_MULTI_ISSUER=true is forbidden") {
			t.Fatalf("production profile must fail on the unbound-issuer override: %+v", c["config"])
		}
	})
	t.Run("single unbound issuer warns, bound issuer is ok", func(t *testing.T) {
		base(t)
		t.Setenv("JWT_ISSUERS", `[{"issuer":"https://auth.example.com","audience":"authz-api","jwks_file":"`+jwks+`"}]`)
		r := Run(context.Background(), Options{Version: "test", HTTP: &http.Client{}, ForceProduction: true})
		c := byName(r)
		if c["issuer bindings"].Status != StatusWarn || !strings.Contains(c["issuer bindings"].Detail, "auth.example.com") {
			t.Fatalf("unbound single issuer should warn in production: %+v", c["issuer bindings"])
		}
		t.Setenv("JWT_ISSUERS", `[{"issuer":"https://auth.example.com","audience":"authz-api","jwks_file":"`+jwks+`","stores":["demo"]}]`)
		r = Run(context.Background(), Options{Version: "test", HTTP: &http.Client{}, ForceProduction: true})
		if c := byName(r); c["issuer bindings"].Status != StatusOK {
			t.Fatalf("bound issuer: %+v", c["issuer bindings"])
		}
	})
}
