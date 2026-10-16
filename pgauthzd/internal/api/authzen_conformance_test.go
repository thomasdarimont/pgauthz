package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// The behaviours the OpenID conformance suite's AuthZEN PDP plans exercise
// against the HTTP layer (openid/authzen issue #433 and AuthZEN 1.0 §7, §8,
// §10, §11), driven through the public mux with a scripted backend that
// answers the certification fixture: alice reads and writes record-1, bob
// only reads it.

// certBackend answers the certification fixture and records what the batch
// path asked it to evaluate.
type certBackend struct {
	authz.Backend
	batches [][]authz.EvalRequest
}

func fixtureDecision(r authz.EvalRequest) bool {
	if r.ObjectType != "record" || r.ObjectID != "record-1" || r.SubjectType != "user" {
		return false
	}
	switch r.SubjectID + "/" + r.Action {
	case "alice/read", "alice/write", "bob/read":
		return true
	}
	return false
}

func (b *certBackend) CheckAccess(_ context.Context, req authz.EvalRequest) (bool, error) {
	return fixtureDecision(req), nil
}

// CheckAccessBatch mirrors authz.check_access_batch: every item gets a result,
// items past a short-circuit come back as false (the engine's NULL).
func (b *certBackend) CheckAccessBatch(_ context.Context, _ string, reqs []authz.EvalRequest, _ map[string]any, semantic string) ([]authz.EvalResult, error) {
	b.batches = append(b.batches, reqs)
	out := make([]authz.EvalResult, len(reqs))
	short := false
	for i, r := range reqs {
		if short {
			continue
		}
		d := fixtureDecision(r)
		out[i].Decision = d
		if (semantic == "deny_on_first_deny" && !d) || (semantic == "permit_on_first_permit" && d) {
			short = true
		}
	}
	return out, nil
}

func (b *certBackend) ListSubjects(context.Context, string, string, string, string, string, map[string]any, *authz.PageRequest) ([]string, *authz.PageResponse, error) {
	return []string{"alice", "bob"}, nil, nil
}
func (b *certBackend) ListResources(context.Context, string, string, string, string, string, map[string]any, *authz.PageRequest) ([]string, *authz.PageResponse, error) {
	return []string{"record-1"}, nil, nil
}
func (b *certBackend) ListActions(context.Context, string, string, string, string, string, map[string]any) ([]string, error) {
	return []string{"read", "write"}, nil
}

// certMux is the public mux (no JWT middleware) in trusted-PEP mode: the
// suite names alice and bob in the body under one credential, so the body
// subject wins, as ALLOW_SUBJECT_OVERRIDE=true gives a conformance run.
func certMux(t *testing.T, allowOverride bool) (*http.ServeMux, *certBackend) {
	t.Helper()
	b := &certBackend{}
	h := NewHandler(b, b, nil, &config.Config{
		DefaultStore:         "authzen_cert",
		StoreHeader:          "X-PGAuthz-Store",
		AllowSubjectOverride: allowOverride,
	})
	return newPublicMux(h, false), b
}

// pep sends body to path as the suite does: authenticated with the PEP's
// credential, a token that carries NO user subject (the JWT middleware sets
// only the subject type for a token without sub/preferred_username). The body
// subject is therefore the only principal — a conformance api_key must be
// minted that way, or the JWT-subject fallback answers for the PEP itself.
func pep(mux *http.ServeMux, method, path, contentType, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	ctx := context.WithValue(r.Context(), ctxSubjectType, "internal_user")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r.WithContext(ctx))
	return w
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not a JSON object: %v\n%s", err, w.Body.String())
	}
	return m
}

func decisions(t *testing.T, w *httptest.ResponseRecorder) []bool {
	t.Helper()
	m := decodeJSON(t, w)
	raw, ok := m["evaluations"].([]any)
	if !ok {
		t.Fatalf("no evaluations array in %s", w.Body.String())
	}
	out := make([]bool, len(raw))
	for i, e := range raw {
		out[i] = e.(map[string]any)["decision"].(bool)
	}
	return out
}

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// §7.1: a batch request without an evaluations array — absent or empty — is
// handled like the single Access Evaluation API: {"decision": …}, and never an
// evaluations array (modules …-missing-evaluations-array-backward-compat and
// …-empty-evaluations-array-backward-compat).
func TestEvaluationsWithoutArrayAnswersInSingleForm(t *testing.T) {
	mux, _ := certMux(t, true)
	for name, body := range map[string]string{
		"absent": `{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`,
		"empty":  `{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"},"evaluations":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			w := pep(mux, http.MethodPost, "/access/v1/evaluations", "application/json", body)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			m := decodeJSON(t, w)
			if m["decision"] != true {
				t.Fatalf("want decision true, got %s", w.Body.String())
			}
			if _, has := m["evaluations"]; has {
				t.Fatalf("single-form response must not carry an evaluations array: %s", w.Body.String())
			}
		})
	}
	// …and a single-form request that resolves to nothing is still the single
	// API's 400, not a batch of one.
	w := pep(mux, http.MethodPost, "/access/v1/evaluations", "application/json", `{"action":{"name":"read"},"evaluations":[]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty array without subject/resource: want 400, got %d: %s", w.Code, w.Body.String())
	}
}

// §7.1.1 / certification profile 3.4.1: an evaluation that cannot be resolved
// is a decision-false item in a 200 response, not a 400 for the batch
// (modules …-evaluation-level-errors and …-missing-subject-returns-decision-false).
func TestEvaluationsUnresolvedItemIsDecisionFalse(t *testing.T) {
	mux, b := certMux(t, true)

	w := pep(mux, http.MethodPost, "/access/v1/evaluations", "application/json",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"evaluations":[{"resource":{"type":"record","id":"record-1"}},{}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("empty item: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decisions(t, w); !equalBools(got, []bool{true, false}) {
		t.Fatalf("empty item: want [true false], got %v", got)
	}
	if len(b.batches) != 1 || len(b.batches[0]) != 1 {
		t.Fatalf("only the resolvable item reaches the engine, got %v", b.batches)
	}

	w = pep(mux, http.MethodPost, "/access/v1/evaluations", "application/json",
		`{"action":{"name":"read"},"evaluations":[{"resource":{"type":"record","id":"record-1"}}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("no subject anywhere: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decisions(t, w); !equalBools(got, []bool{false}) {
		t.Fatalf("no subject anywhere: want [false], got %v", got)
	}
	if len(b.batches) != 1 {
		t.Fatalf("nothing resolvable: the engine must not be called, got %v", b.batches)
	}

	// With a user subject on the credential the documented JWT fallback still
	// applies: the missing body subject resolves to the token's subject and
	// the item is evaluated, not failed.
	r := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", strings.NewReader(
		`{"action":{"name":"read"},"evaluations":[{"resource":{"type":"record","id":"record-1"}}]}`))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), ctxSubjectType, "user")
	ctx = context.WithValue(ctx, ctxSubjectID, "alice")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r.WithContext(ctx))
	if got := decisions(t, w); !equalBools(got, []bool{true}) {
		t.Fatalf("JWT fallback: want [true], got %v (%s)", got, w.Body.String())
	}
}

// The secure default is unchanged: a body subject that contradicts the
// authenticated subject is an impersonation attempt and stays a 403 for the
// whole batch — it is not an "unresolvable item".
func TestEvaluationsSubjectOverrideStillForbidden(t *testing.T) {
	mux, _ := certMux(t, false)
	r := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", strings.NewReader(
		`{"action":{"name":"read"},"evaluations":[{"subject":{"type":"user","id":"bob"},"resource":{"type":"record","id":"record-1"}}]}`))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), ctxSubjectType, "user")
	ctx = context.WithValue(ctx, ctxSubjectID, "alice")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r.WithContext(ctx))
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
}

// §7.1.2.1: the semantic is options.evaluations_semantic (the pre-1.0 top-level
// `semantic` is still read), an unknown value is a 400, and a short-circuit is
// visible on the wire — the array ends with the decision that stopped
// processing (modules …-unknown-semantic-value, …-deny-on-first-deny,
// …-permit-on-first-permit, …-execute-all-explicit).
func TestEvaluationsSemantic(t *testing.T) {
	mux, _ := certMux(t, true)
	batch := func(options string) string {
		return `{"subject":{"type":"user","id":"bob"},"resource":{"type":"record","id":"record-1"},` +
			`"evaluations":[{"action":{"name":"read"}},{"action":{"name":"write"}},{"action":{"name":"read"}}]` + options + `}`
	}
	cases := []struct {
		name    string
		options string
		status  int
		want    []bool
	}{
		{"default execute_all", "", 200, []bool{true, false, true}},
		{"explicit execute_all", `,"options":{"evaluations_semantic":"execute_all"}`, 200, []bool{true, false, true}},
		{"deny_on_first_deny truncates", `,"options":{"evaluations_semantic":"deny_on_first_deny"}`, 200, []bool{true, false}},
		{"permit_on_first_permit truncates", `,"options":{"evaluations_semantic":"permit_on_first_permit"}`, 200, []bool{true}},
		{"legacy top-level semantic", `,"semantic":"deny_on_first_deny"`, 200, []bool{true, false}},
		{"options win over legacy", `,"semantic":"execute_all","options":{"evaluations_semantic":"deny_on_first_deny"}`, 200, []bool{true, false}},
		{"unknown value", `,"options":{"evaluations_semantic":"bogus_value"}`, 400, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := pep(mux, http.MethodPost, "/access/v1/evaluations", "application/json", batch(c.options))
			if w.Code != c.status {
				t.Fatalf("want %d, got %d: %s", c.status, w.Code, w.Body.String())
			}
			if c.want != nil {
				if got := decisions(t, w); !equalBools(got, c.want) {
					t.Fatalf("want %v, got %v", c.want, got)
				}
			}
		})
	}

	// An unresolvable item under deny_on_first_deny is the first deny: the
	// array ends there and the engine never sees what follows.
	mux, b := certMux(t, true)
	w := pep(mux, http.MethodPost, "/access/v1/evaluations", "application/json",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"options":{"evaluations_semantic":"deny_on_first_deny"},`+
			`"evaluations":[{"resource":{"type":"record","id":"record-1"}},{},{"resource":{"type":"record","id":"record-1"}}]}`)
	if got := decisions(t, w); !equalBools(got, []bool{true, false}) {
		t.Fatalf("want [true false], got %v (%s)", got, w.Body.String())
	}
	if len(b.batches) != 1 || len(b.batches[0]) != 1 {
		t.Fatalf("only the item before the unresolvable one reaches the engine, got %v", b.batches)
	}
}

// §10.1: requests carry Content-Type application/json. A declared other media
// type is refused with 415 on every AuthZEN route; a charset parameter is fine;
// a request without the header is still read as JSON.
func TestAuthZENContentType(t *testing.T) {
	mux, _ := certMux(t, true)
	routes := map[string]string{
		"/access/v1/evaluation":              `{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`,
		"/access/v1/evaluations":             `{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"evaluations":[{"resource":{"type":"record","id":"record-1"}}]}`,
		"/access/v1/search/subject":          `{"subject":{"type":"user"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`,
		"/access/v1/search/resource":         `{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"record"}}`,
		"/access/v1/search/action":           `{"subject":{"type":"user","id":"alice"},"resource":{"type":"record","id":"record-1"}}`,
		"/stores/other/access/v1/evaluation": `{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`,
	}
	for path, body := range routes {
		t.Run(path, func(t *testing.T) {
			if w := pep(mux, http.MethodPost, path, "text/plain", body); w.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("text/plain: want 415, got %d: %s", w.Code, w.Body.String())
			}
			if w := pep(mux, http.MethodPost, path, "application/x-www-form-urlencoded", body); w.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("form: want 415, got %d: %s", w.Code, w.Body.String())
			}
			for _, ct := range []string{"application/json", "application/json; charset=utf-8", "APPLICATION/JSON", ""} {
				if w := pep(mux, http.MethodPost, path, ct, body); w.Code != http.StatusOK {
					t.Fatalf("%q: want 200, got %d: %s", ct, w.Code, w.Body.String())
				}
			}
		})
	}
	// The guard decides on the header alone; a bad body behind a good header
	// is still the parser's 400.
	if w := pep(mux, http.MethodPost, "/access/v1/evaluation", "application/json", `{ "subject": broken`); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON: want 400, got %d", w.Code)
	}
}

// §8.4.2 / §8.5.2 / §8.6.2: `results` holds the entity objects themselves —
// {type, id} for subjects and resources, {name} for actions — not the pre-1.0
// draft's wrapped {"subject": {…}} items, and `page` precedes `results`
// (the three search plans failed every result-bearing module on the old shape).
func TestSearchResultsAreEntityObjects(t *testing.T) {
	mux, _ := certMux(t, true)
	cases := []struct {
		path, body string
		want       []map[string]any
	}{
		{"/access/v1/search/subject", `{"subject":{"type":"user"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"},"page":{"limit":1}}`,
			[]map[string]any{{"type": "user", "id": "alice"}, {"type": "user", "id": "bob"}}},
		{"/access/v1/search/resource", `{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"record"}}`,
			[]map[string]any{{"type": "record", "id": "record-1"}}},
		{"/access/v1/search/action", `{"subject":{"type":"user","id":"alice"},"resource":{"type":"record","id":"record-1"}}`,
			[]map[string]any{{"name": "read"}, {"name": "write"}}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			w := pep(mux, http.MethodPost, c.path, "application/json", c.body)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			var resp struct {
				Results []map[string]any `json:"results"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if len(resp.Results) != len(c.want) {
				t.Fatalf("want %d results, got %s", len(c.want), w.Body.String())
			}
			for i, want := range c.want {
				for k, v := range want {
					if resp.Results[i][k] != v {
						t.Fatalf("result %d: want %v, got %v (%s)", i, want, resp.Results[i], w.Body.String())
					}
				}
				for _, wrapped := range []string{"subject", "resource", "action"} {
					if _, has := resp.Results[i][wrapped]; has {
						t.Fatalf("result %d is still wrapped in %q: %s", i, wrapped, w.Body.String())
					}
				}
			}
		})
	}
}

// §10.1 transport negatives the mux answers on its own: GET/PUT on a POST
// route is a 405, a top-level array / string subject / empty body a 400.
func TestAuthZENTransportNegatives(t *testing.T) {
	mux, _ := certMux(t, true)
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		if w := pep(mux, method, "/access/v1/evaluation", "application/json", `{}`); w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: want 405, got %d", method, w.Code)
		}
	}
	for name, body := range map[string]string{
		"top-level array":      `[{"subject":{"type":"user","id":"alice"}}]`,
		"subject string":       `{"subject":"alice","action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`,
		"action number":        `{"subject":{"type":"user","id":"alice"},"action":{"name":1},"resource":{"type":"record","id":"record-1"}}`,
		"empty body":           ``,
		"missing subject":      `{"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`,
		"subject without type": `{"subject":{"id":"alice"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`,
		"subject without id":   `{"subject":{"type":"user"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			w := pep(mux, http.MethodPost, "/access/v1/evaluation", "application/json", body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

// A subject without a type is a 400 even when the credential carries a
// subject: the token's type must not complete the body's id (module
// authzen-pdp-evaluation-subject-missing-type ran into a 500 from the engine's
// 'Unknown type: internal_user' before this rule).
func TestPartialBodySubjectIsNotCompletedFromToken(t *testing.T) {
	mux, b := certMux(t, true)
	r := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", strings.NewReader(
		`{"subject":{"id":"alice"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), ctxSubjectType, "internal_user")
	ctx = context.WithValue(ctx, ctxSubjectID, "pep")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r.WithContext(ctx))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	if len(b.batches) != 0 {
		t.Fatalf("nothing must reach the engine: %v", b.batches)
	}
}

// §11.3: a 401 names the expected scheme.
func TestUnauthorizedCarriesWWWAuthenticate(t *testing.T) {
	w := httptest.NewRecorder()
	writeUnauthorized(w)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
		t.Fatalf("want a Bearer challenge, got %q", got)
	}
}

// §8.2: the page size is `limit`; the pre-1.0 `size` is still read.
func TestPageLimit(t *testing.T) {
	if got := decodePage(&PageToken{Limit: 1}, "").Limit; got != 1 {
		t.Fatalf("limit: want 1, got %d", got)
	}
	if got := decodePage(&PageToken{Size: 7}, "").Limit; got != 7 {
		t.Fatalf("legacy size: want 7, got %d", got)
	}
	if got := decodePage(&PageToken{Limit: 2, Size: 7}, "").Limit; got != 2 {
		t.Fatalf("limit wins over size: want 2, got %d", got)
	}
	var p PageToken
	if err := json.Unmarshal([]byte(`{"limit":1}`), &p); err != nil || p.Limit != 1 {
		t.Fatalf("limit does not decode: %v %+v", err, p)
	}
}
