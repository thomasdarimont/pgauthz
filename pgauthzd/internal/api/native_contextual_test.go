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

// ctxStub is the decision-log tests' direct backend, answering every
// contextual check with true and counting the calls.
type ctxStub struct {
	detailStub
	calls int
}

func (s *ctxStub) CheckWithContextualTuples(context.Context, authz.EvalRequest, json.RawMessage) (bool, error) {
	s.calls++
	return true, nil
}

// CONTEXTUAL_TUPLES on the native check: who may inject what-if tuples on
// the public listener — nobody (off), trusted PEPs (the default: a
// pep_clients entry for the store, or ALLOW_SUBJECT_OVERRIDE), everybody
// (any) — and the callback listener always; a malformed value is a 400, an
// empty array is a plain check, and the decision log counts the tuples.
func TestNativeCheckContextualTuplesPolicy(t *testing.T) {
	const withTuples = `{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"doc","id":"d1"},` +
		`"contextual_tuples":[{"user_type":"user","user_id":"alice","relation":"viewer","object_type":"doc","object_id":"d1"}]}`
	run := func(cfg *config.Config, listener string, body string, decorate func(*http.Request) *http.Request) (int, string, int) {
		t.Helper()
		b := &ctxStub{}
		h := NewHandler(b, b, b, cfg)
		h.listener = listener
		r := jsonReq("POST", "/pgauthz/v1/check", body)
		if decorate != nil {
			r = decorate(r)
		}
		w := httptest.NewRecorder()
		h.NativeCheck(w, r)
		return w.Code, w.Body.String(), b.calls
	}
	base := func(mode string) *config.Config {
		return &config.Config{DefaultStore: "demo", ContextualTuples: mode}
	}

	// off: refused on the public listener, however trusted the caller
	if code, body, calls := run(&config.Config{DefaultStore: "demo", ContextualTuples: config.ContextualTuplesOff, AllowSubjectOverride: true}, "public", withTuples, nil); code != http.StatusForbidden || calls != 0 || !strings.Contains(body, "CONTEXTUAL_TUPLES=off") {
		t.Errorf("off: %d %s (calls %d), want 403 and no engine call", code, body, calls)
	}
	// trusted-peps (the default): an untrusted caller is refused ...
	if code, body, calls := run(base(config.ContextualTuplesTrustedPEPs), "public", withTuples, nil); code != http.StatusForbidden || calls != 0 || !strings.Contains(body, "trusted PEPs only") {
		t.Errorf("trusted-peps, plain caller: %d %s (calls %d), want 403", code, body, calls)
	}
	// ... the coarse switch trusts everybody ...
	if code, _, calls := run(&config.Config{DefaultStore: "demo", ContextualTuples: config.ContextualTuplesTrustedPEPs, AllowSubjectOverride: true}, "public", withTuples, nil); code != http.StatusOK || calls != 1 {
		t.Errorf("trusted-peps + ALLOW_SUBJECT_OVERRIDE: %d (calls %d), want 200", code, calls)
	}
	// ... and a pep_clients entry trusts that client for its stores only
	pep := &config.Config{DefaultStore: "demo", ContextualTuples: config.ContextualTuplesTrustedPEPs, Issuers: []config.Issuer{
		{Issuer: "https://idp", JWKSFile: "x", Stores: []string{"demo", "other"}, PEPClients: map[string][]string{"svc": {"demo"}}},
	}}
	as := func(client, store string) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			ctx := context.WithValue(r.Context(), ctxIssuer, "https://idp")
			ctx = context.WithValue(ctx, ctxClient, client)
			ctx = context.WithValue(ctx, ctxSubjectType, "user")
			ctx = context.WithValue(ctx, ctxSubjectID, "alice")
			if store != "" {
				r.SetPathValue("store", store)
			}
			return r.WithContext(ctx)
		}
	}
	if code, body, calls := run(pep, "public", withTuples, as("svc", "")); code != http.StatusOK || calls != 1 {
		t.Errorf("pep client on its store: %d %s (calls %d), want 200", code, body, calls)
	}
	if code, _, calls := run(pep, "public", withTuples, as("svc", "other")); code != http.StatusForbidden || calls != 0 {
		t.Errorf("pep client outside its stores: %d (calls %d), want 403", code, calls)
	}
	if code, _, calls := run(pep, "public", withTuples, as("spa", "")); code != http.StatusForbidden || calls != 0 {
		t.Errorf("an unlisted client: %d (calls %d), want 403", code, calls)
	}
	// any: everybody
	if code, _, calls := run(base(config.ContextualTuplesAny), "public", withTuples, nil); code != http.StatusOK || calls != 1 {
		t.Errorf("any: %d (calls %d), want 200", code, calls)
	}
	// the callback listener: OPA is the caller, always allowed
	if code, _, calls := run(base(config.ContextualTuplesOff), "callback", withTuples, nil); code != http.StatusOK || calls != 1 {
		t.Errorf("callback listener: %d (calls %d), want 200 even with off", code, calls)
	}
	// a malformed value never reaches the policy or the engine
	bad := strings.Replace(withTuples, `"contextual_tuples":[`, `"contextual_tuples":{"x":[`, 1) + "}"
	if code, _, calls := run(base(config.ContextualTuplesAny), "public", bad, nil); code != http.StatusBadRequest || calls != 0 {
		t.Errorf("malformed contextual_tuples: %d (calls %d), want 400", code, calls)
	}
}

func TestContextualTupleCount(t *testing.T) {
	if n, err := contextualTupleCount(json.RawMessage(`[{"a":1},{"b":2}]`)); n != 2 || err != nil {
		t.Errorf("count: %d %v", n, err)
	}
	if n, err := contextualTupleCount(json.RawMessage(`[]`)); n != 0 || err != nil {
		t.Errorf("empty: %d %v", n, err)
	}
	if _, err := contextualTupleCount(json.RawMessage(`{"a":1}`)); err == nil {
		t.Error("an object must be refused")
	}
}

// A contextual check's decision-log line counts the injected tuples, so a
// reader can tell a hypothetical from a decision on the stored graph.
func TestDecisionLogCountsContextualTuples(t *testing.T) {
	h, buf := newLoggedHandler(t, &ctxStub{}, false)
	w := httptest.NewRecorder()
	h.NativeCheck(w, jsonReq("POST", "/pgauthz/v1/check",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"doc","id":"d1"},`+
			`"contextual_tuples":[{"user_type":"user","user_id":"alice","relation":"viewer","object_type":"doc","object_id":"d1"},`+
			`{"user_type":"user","user_id":"alice","relation":"member","object_type":"team","object_id":"eng"}]}`))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	l := lines(buf)[0]
	if l["contextual_tuples"] != float64(2) || l["endpoint"] != "check" {
		t.Fatalf("log line must count the contextual tuples: %v", l)
	}
	if strings.Contains(buf.String(), "team") {
		t.Fatalf("the tuples themselves must not be logged: %s", buf.String())
	}
	// a plain check carries no such field
	buf.Reset()
	w = httptest.NewRecorder()
	h.NativeCheck(w, jsonReq("POST", "/pgauthz/v1/check",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"doc","id":"d1"}}`))
	if _, ok := lines(buf)[0]["contextual_tuples"]; ok || w.Code != 200 {
		t.Fatalf("plain check: %d %v", w.Code, lines(buf)[0])
	}
}

// Per-check contextual tuples in check-batch are refused, not ignored
// (review #19): the batch checker only knows the stored graph.
func TestNativeCheckBatchRefusesContextualTuples(t *testing.T) {
	b := &ctxStub{}
	h := NewHandler(b, b, b, &config.Config{DefaultStore: "demo", AllowSubjectOverride: true, ContextualTuples: config.ContextualTuplesAny})
	w := httptest.NewRecorder()
	h.NativeCheckBatch(w, jsonReq("POST", "/pgauthz/v1/check-batch", `{"checks":[
		{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"doc","id":"d1"}},
		{"subject":{"type":"user","id":"bob"},"action":{"name":"can_read"},"resource":{"type":"doc","id":"d1"},
		 "contextual_tuples":[{"user_type":"user","user_id":"bob","relation":"viewer","object_type":"doc","object_id":"d1"}]}]}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "checks[1].contextual_tuples") {
		t.Fatalf("%d %s, want 400 naming the check", w.Code, w.Body.String())
	}
}
