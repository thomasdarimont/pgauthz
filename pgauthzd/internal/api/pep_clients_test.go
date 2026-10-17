package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// ADR 0014: who may assert a subject is decided per issuer, per client (azp),
// per store. Deny by default; the coarse ALLOW_SUBJECT_OVERRIDE still allows
// everyone; the same predicate guards the write-side audit actor.
func TestPEPClientsAssertion(t *testing.T) {
	const corp = "https://id.example.com/realms/corp"
	cfg := &config.Config{
		DefaultStore: "demo", StoreHeader: "X-PGAuthz-Store",
		Issuers: []config.Issuer{{
			Issuer: corp, JWKSFile: "x", Stores: []string{"demo", "documents", "tenant-.*"},
			PEPClients: map[string][]string{
				"document-service": {"documents", "tenant-.*"},
				"pep-gateway":      {".*"},
			},
		}},
	}
	b := &certBackend{}
	mux := newPublicMux(NewHandler(b, b, nil, cfg), false)

	// call sends a request as a client of the corp issuer whose token names
	// the service account `svc` (type service) — never alice.
	call := func(client, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(r.Context(), ctxIssuer, corp)
		ctx = context.WithValue(ctx, ctxSubjectType, "service")
		ctx = context.WithValue(ctx, ctxSubjectID, "svc")
		if client != "" {
			ctx = context.WithValue(ctx, ctxClient, client)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r.WithContext(ctx))
		return w
	}
	alice := `{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`

	// listed client, listed store: the body subject is asserted
	if w := call("document-service", "/stores/documents/access/v1/evaluation", alice); w.Code != http.StatusOK {
		t.Fatalf("listed client in listed store: %d %s", w.Code, w.Body.String())
	}
	if w := call("document-service", "/stores/tenant-7/access/v1/evaluation", alice); w.Code != http.StatusOK {
		t.Fatalf("pattern store: %d %s", w.Code, w.Body.String())
	}
	if last := b.singles[len(b.singles)-1]; last.SubjectID != "alice" || last.Store != "tenant-7" {
		t.Fatalf("asserted subject must reach the engine: %+v", last)
	}

	// listed client, other store: 403 naming client and store
	w := call("document-service", "/stores/demo/access/v1/evaluation", alice)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `client \"document-service\" may not assert subjects in store \"demo\"`) {
		t.Fatalf("listed client in another store: %d %s", w.Code, w.Body.String())
	}
	// unlisted client, no client claim: 403
	for _, client := range []string{"hr-app", ""} {
		if w := call(client, "/stores/documents/access/v1/evaluation", alice); w.Code != http.StatusForbidden {
			t.Fatalf("client %q: want 403, got %d %s", client, w.Code, w.Body.String())
		}
	}
	// …but asking about itself is always fine, and so is naming no subject
	if w := call("hr-app", "/stores/documents/access/v1/evaluation", `{"subject":{"type":"service","id":"svc"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`); w.Code != http.StatusOK {
		t.Fatalf("self-subject: %d %s", w.Code, w.Body.String())
	}
	if w := call("hr-app", "/stores/documents/access/v1/evaluation", `{"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}`); w.Code != http.StatusOK {
		t.Fatalf("token subject fallback: %d %s", w.Code, w.Body.String())
	}
	// the wildcard client asserts anywhere the issuer is bound
	if w := call("pep-gateway", "/stores/demo/access/v1/evaluation", alice); w.Code != http.StatusOK {
		t.Fatalf("wildcard client: %d %s", w.Code, w.Body.String())
	}
	// a batch item naming another subject fails the whole batch
	batch := `{"action":{"name":"read"},"resource":{"type":"record","id":"record-1"},"evaluations":[{"subject":{"type":"service","id":"svc"}},{"subject":{"type":"user","id":"alice"}}]}`
	if w := call("document-service", "/stores/demo/access/v1/evaluations", batch); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "evaluation[1]") {
		t.Fatalf("batch in another store: %d %s", w.Code, w.Body.String())
	}
	if w := call("document-service", "/stores/documents/access/v1/evaluations", batch); w.Code != http.StatusOK {
		t.Fatalf("batch in listed store: %d %s", w.Code, w.Body.String())
	}
	// a token from another issuer is not covered by corp's map
	r := httptest.NewRequest(http.MethodPost, "/stores/documents/access/v1/evaluation", strings.NewReader(alice))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), ctxIssuer, "https://other.idp")
	ctx = context.WithValue(ctx, ctxClient, "document-service")
	ctx = context.WithValue(ctx, ctxSubjectType, "service")
	ctx = context.WithValue(ctx, ctxSubjectID, "svc")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r.WithContext(ctx))
	if w.Code != http.StatusForbidden {
		t.Fatalf("other issuer: want 403, got %d %s", w.Code, w.Body.String())
	}

	// a service credential WITHOUT a subject claim is the case the grant exists
	// for: unlisted, it may not name anyone; listed, it may
	svc := func(client, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(alice))
		r.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(r.Context(), ctxIssuer, corp)
		ctx = context.WithValue(ctx, ctxClient, client)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r.WithContext(ctx))
		return w
	}
	if w := svc("hr-app", "/stores/documents/access/v1/evaluation"); w.Code != http.StatusForbidden {
		t.Fatalf("subject-less unlisted client: want 403, got %d %s", w.Code, w.Body.String())
	}
	if w := svc("document-service", "/stores/demo/access/v1/evaluation"); w.Code != http.StatusForbidden {
		t.Fatalf("subject-less listed client, other store: want 403, got %d %s", w.Code, w.Body.String())
	}
	if w := svc("document-service", "/stores/documents/access/v1/evaluation"); w.Code != http.StatusOK {
		t.Fatalf("subject-less listed client, its store: want 200, got %d %s", w.Code, w.Body.String())
	}

	// the coarse switch still allows everyone
	cfg2 := *cfg
	cfg2.AllowSubjectOverride = true
	mux2 := newPublicMux(NewHandler(b, b, nil, &cfg2), false)
	r = httptest.NewRequest(http.MethodPost, "/stores/demo/access/v1/evaluation", strings.NewReader(alice))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux2.ServeHTTP(w, r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxIssuer, corp), ctxClient, "hr-app")))
	if w.Code != http.StatusOK {
		t.Fatalf("coarse switch: %d %s", w.Code, w.Body.String())
	}
}

// The audit actor follows the same predicate: a writer may attribute a write
// to another user only where its client may assert subjects.
func TestPEPClientsGuardAuditActor(t *testing.T) {
	const corp = "https://id.example.com/realms/corp"
	h := NewHandler(nil, nil, nil, &config.Config{
		DefaultStore: "demo", StoreHeader: "X-PGAuthz-Store",
		Issuers: []config.Issuer{{Issuer: corp, JWKSFile: "x", PEPClients: map[string][]string{"document-service": {"documents"}}}},
	})
	h.requireWriterRole = true // public listener semantics
	try := func(client, store string) (string, int) {
		r := httptest.NewRequest(http.MethodPost, "/stores/"+store+"/pgauthz/v1/write", nil)
		ctx := context.WithValue(r.Context(), ctxIssuer, corp)
		ctx = context.WithValue(ctx, ctxSubjectType, "service")
		ctx = context.WithValue(ctx, ctxSubjectID, "svc")
		ctx = context.WithValue(ctx, ctxClient, client)
		r = r.WithContext(ctx)
		r.SetPathValue("store", store)
		w := httptest.NewRecorder()
		actor, ok := h.resolvePerformedBy(w, r, "alice")
		if !ok {
			return "", w.Code
		}
		return actor, http.StatusOK
	}
	if actor, code := try("document-service", "documents"); code != http.StatusOK || actor != "alice" {
		t.Fatalf("listed: %d %q", code, actor)
	}
	if _, code := try("document-service", "demo"); code != http.StatusForbidden {
		t.Fatalf("other store: want 403, got %d", code)
	}
	if _, code := try("hr-app", "documents"); code != http.StatusForbidden {
		t.Fatalf("unlisted client: want 403, got %d", code)
	}
}

// The decision log names the calling application even when the credential
// has no user subject.
func TestDecisionLogCarriesClient(t *testing.T) {
	h := NewHandler(nil, nil, nil, &config.Config{DefaultStore: "demo"})
	r := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxClient, "conformance-suite"))
	e := h.decisionEntry(r, "evaluation", authz.EvalRequest{Store: "demo", SubjectType: "user", SubjectID: "alice", Action: "read", ObjectType: "record", ObjectID: "record-1"}, "engine")
	if e.Client != "conformance-suite" || e.Actor != "" {
		t.Fatalf("entry: client=%q actor=%q", e.Client, e.Actor)
	}
}
