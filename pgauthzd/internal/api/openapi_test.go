package api

// Contract tests for openapi.yaml (the served API description):
//
//   1. the document itself is a valid OpenAPI 3 description;
//   2. spec → code: every path+method in the document resolves in the
//      PRODUCTION mux (newPublicMux) — a route removed/renamed in code fails
//      here until the document follows;
//   3. code → spec: every route registered in this package appears in the
//      document — a route added in code fails here until documented;
//   4. real handler responses validate against the documented schemas.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(openapiYAML)
	if err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("openapi.yaml is not a valid OpenAPI 3 document: %v", err)
	}
	return doc
}

func TestOpenAPISpecValidates(t *testing.T) {
	loadSpec(t)
}

// fullMux is the production public mux in its widest shape (full profile, not
// fronting OPA, openapi endpoints on) — the configuration the document
// describes.
func fullMux() *http.ServeMux {
	h := &Handler{cfg: &config.Config{Profile: config.ProfileFull, OpenAPIEnabled: true}}
	return newPublicMux(h, false)
}

// Spec → code: every documented path+method must be a registered route.
func TestOpenAPIPathsAreRegistered(t *testing.T) {
	doc := loadSpec(t)
	mux := fullMux()
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			url := strings.ReplaceAll(path, "{store}", "demo")
			if !routeExists(mux, method, url) {
				t.Errorf("documented but not registered: %s %s", method, path)
			}
		}
	}
}

// Code → spec: every route registered in this package must be documented.
// Route registration is centralized here (handler.go/openapi.go), so a source
// scan for HandleFunc patterns is authoritative; if registration moves to
// another package this test must move with it.
func TestRegisteredRoutesAreDocumented(t *testing.T) {
	doc := loadSpec(t)
	pat := regexp.MustCompile(`HandleFunc\("([A-Z]+) ([^"]+)"`)

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range pat.FindAllStringSubmatch(string(src), -1) {
			seen[m[1]+" "+m[2]] = true
		}
	}
	if len(seen) < 20 {
		t.Fatalf("route scan looks broken: found only %d patterns", len(seen))
	}
	for route := range seen {
		method, path, _ := strings.Cut(route, " ")
		item := doc.Paths.Find(path)
		if item == nil || item.GetOperation(method) == nil {
			t.Errorf("registered but not documented in openapi.yaml: %s", route)
		}
	}
}

// ── response contract validation ─────────────────────────────────────────────

// contractStub extends freshStub with the full authz.Backend so the AuthZEN
// read handlers answer (freshStub alone leaves the embedded Backend nil).
type contractStub struct {
	freshStub
}

func (contractStub) CheckAccess(context.Context, authz.EvalRequest) (bool, error) {
	return true, nil
}
func (contractStub) CheckAccessBatch(_ context.Context, _ string, reqs []authz.EvalRequest, _ map[string]any, _ string) ([]authz.EvalResult, error) {
	out := make([]authz.EvalResult, len(reqs))
	for i := range out {
		out[i] = authz.EvalResult{Decision: true}
	}
	return out, nil
}
func (contractStub) ListResources(context.Context, string, string, string, string, string, map[string]any, *authz.PageRequest) ([]string, *authz.PageResponse, error) {
	return []string{"doc_1", "doc_2"}, &authz.PageResponse{HasMore: true, NextToken: "keyset-doc_2"}, nil
}
func (contractStub) ListSubjects(context.Context, string, string, string, string, string, map[string]any, *authz.PageRequest) ([]string, *authz.PageResponse, error) {
	return []string{"alice"}, nil, nil
}
func (contractStub) ListActions(context.Context, string, string, string, string, string, map[string]any) ([]string, error) {
	return []string{"can_read"}, nil
}
func (contractStub) Healthz(context.Context) error { return nil }

// validateAgainstSpec serves the request through the production mux and
// validates the response (status, content type, body) against the document.
func validateAgainstSpec(t *testing.T, doc *openapi3.T, mux *http.ServeMux, r *http.Request, wantStatus int) {
	t.Helper()
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != wantStatus {
		t.Fatalf("%s %s: got status %d, want %d (body=%s)", r.Method, r.URL.Path, w.Code, wantStatus, w.Body.String())
	}
	route, pathParams, err := router.FindRoute(r)
	if err != nil {
		t.Fatalf("%s %s: no route in spec: %v", r.Method, r.URL.Path, err)
	}
	in := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: r, PathParams: pathParams, Route: route,
			Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
		},
		Status: w.Code,
		Header: w.Header(),
		Body:   io.NopCloser(bytes.NewReader(w.Body.Bytes())),
	}
	if err := openapi3filter.ValidateResponse(context.Background(), in); err != nil {
		t.Errorf("%s %s: response does not match the spec: %v\nbody: %s", r.Method, r.URL.Path, err, w.Body.String())
	}
}

func jsonReq(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestResponsesMatchOpenAPISpec(t *testing.T) {
	doc := loadSpec(t)
	b := &contractStub{freshStub{epoch: 1, lsn: "0/AA", verdict: "stale"}}
	h := NewHandler(b, b, b, &config.Config{
		Profile: config.ProfileFull, DefaultStore: "demo", FreshnessKeys: testFreshKeys,
		OpenAPIEnabled: true,
	})
	mux := newPublicMux(h, false)
	staleTok := authz.EncodeFreshnessToken(testKeyring[0], 1, "FF/0")

	cases := []struct {
		name   string
		req    *http.Request
		status int
	}{
		{"healthz (deprecated alias)", httptest.NewRequest("GET", "/healthz", nil), 200},
		{"livez", httptest.NewRequest("GET", "/livez", nil), 200},
		{"readyz", httptest.NewRequest("GET", "/readyz", nil), 200},
		{"openapi.json", httptest.NewRequest("GET", "/pgauthz/v1/openapi.json", nil), 200},
		{"authzen evaluation", jsonReq("POST", "/access/v1/evaluation",
			`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"readme"}}`), 200},
		{"authzen evaluations", jsonReq("POST", "/access/v1/evaluations",
			`{"subject":{"type":"user","id":"alice"},"evaluations":[{"action":{"name":"can_read"},"resource":{"type":"document","id":"readme"}}]}`), 200},
		{"authzen search resource (store-scoped)", jsonReq("POST", "/stores/demo/access/v1/search/resource",
			`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document"}}`), 200},
		{"authzen search subject", jsonReq("POST", "/access/v1/search/subject",
			`{"subject":{"type":"user"},"action":{"name":"can_read"},"resource":{"type":"document","id":"readme"}}`), 200},
		{"authzen search action", jsonReq("POST", "/access/v1/search/action",
			`{"subject":{"type":"user","id":"alice"},"resource":{"type":"document","id":"readme"}}`), 200},
		{"well-known", httptest.NewRequest("GET", "/.well-known/authzen-configuration", nil), 200},
		{"native write", jsonReq("POST", "/pgauthz/v1/write",
			`{"tuples":[{"user_type":"user","user_id":"alice","relation":"viewer","object_type":"document","object_id":"readme"}],"performed_by":"contract-tester"}`), 200},
		{"native write bad json is documented 400", jsonReq("POST", "/pgauthz/v1/write", `{`), 400},
		{"native check 501 without a direct reader", jsonReq("POST", "/pgauthz/v1/check",
			`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"readme"}}`), 501},
		{"freshness 409 is documented", func() *http.Request {
			r := jsonReq("POST", "/pgauthz/v1/check",
				`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"readme"}}`)
			r.Header.Set(ConsistencyHeader, "at_least_as_fresh")
			r.Header.Set(RevisionHeader, staleTok)
			return r
		}(), 409},
		{"freshness bad token is documented 400", func() *http.Request {
			r := jsonReq("POST", "/pgauthz/v1/check", `{}`)
			r.Header.Set(ConsistencyHeader, "at_least_as_fresh")
			r.Header.Set(RevisionHeader, "garbage")
			return r
		}(), 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validateAgainstSpec(t, doc, mux, tc.req, tc.status)
		})
	}
}

// The served JSON carries the stamped version, decodes, and matches the YAML
// source's path count (same document, two encodings).
func TestOpenAPIEndpointsServeTheDocument(t *testing.T) {
	doc := loadSpec(t)
	h := &Handler{cfg: &config.Config{}}

	w := httptest.NewRecorder()
	h.OpenAPIJSON(w, httptest.NewRequest("GET", "/pgauthz/v1/openapi.json", nil))
	var got struct {
		Info  struct{ Version string } `json:"info"`
		Paths map[string]any           `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("served openapi.json does not decode: %v", err)
	}
	if got.Info.Version == "" {
		t.Fatal("served document has no info.version")
	}
	if len(got.Paths) != doc.Paths.Len() {
		t.Fatalf("served document has %d paths, source has %d", len(got.Paths), doc.Paths.Len())
	}

	wy := httptest.NewRecorder()
	h.OpenAPIYAML(wy, httptest.NewRequest("GET", "/pgauthz/v1/openapi.yaml", nil))
	if ct := wy.Header().Get("Content-Type"); ct != "application/yaml" {
		t.Fatalf("yaml endpoint content type: %q", ct)
	}
}

// An OPA-fronted instance's served document is INSTANCE-ACCURATE (review #6):
// the native paths its public listener does not register are omitted (except
// the openapi meta endpoints, which stay registered), while AuthZEN remains.
func TestOpenAPIServedDocIsInstanceAccurate(t *testing.T) {
	h := &Handler{cfg: &config.Config{OPAURL: "http://opa:8181", OpenAPIEnabled: true}}
	w := httptest.NewRecorder()
	h.OpenAPIJSON(w, httptest.NewRequest("GET", "/pgauthz/v1/openapi.json", nil))
	var got struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for p := range got.Paths {
		if strings.HasPrefix(p, "/pgauthz/v1/openapi.") {
			continue
		}
		if strings.HasPrefix(p, "/pgauthz/v1/") || strings.HasPrefix(p, "/stores/{store}/pgauthz/v1/") {
			t.Errorf("OPA-fronted served doc must not describe native path %s", p)
		}
	}
	for _, want := range []string{"/access/v1/evaluation", "/pgauthz/v1/openapi.json", "/healthz"} {
		if _, ok := got.Paths[want]; !ok {
			t.Errorf("OPA-fronted served doc must keep %s", want)
		}
	}

	// The YAML form of the filtered variant agrees.
	wy := httptest.NewRecorder()
	h.OpenAPIYAML(wy, httptest.NewRequest("GET", "/pgauthz/v1/openapi.yaml", nil))
	if strings.Contains(wy.Body.String(), "/pgauthz/v1/check:") {
		t.Error("OPA-fronted YAML form must not describe native paths")
	}
}

// OPENAPI_ENABLED=false removes the endpoints entirely (exposure minimization).
func TestOpenAPIEndpointsCanBeDisabled(t *testing.T) {
	h := &Handler{cfg: &config.Config{Profile: config.ProfileFull}} // OpenAPIEnabled false
	mux := newPublicMux(h, false)
	if routeExists(mux, "GET", "/pgauthz/v1/openapi.json") || routeExists(mux, "GET", "/pgauthz/v1/openapi.yaml") {
		t.Fatal("OPENAPI_ENABLED=false must not register the openapi endpoints")
	}
}
