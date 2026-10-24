package main

// The CLI's admin-API mode without a running stack: a fake pgauthzd admin
// API (httptest) that records what it was asked, the client's credential
// handling (bearer token, mTLS client certificate, error mapping), and
// each verb's request shape and output.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAdmin is the admin API as the CLI sees it: the resources in memory,
// every request logged, bearer tokens checked.
type fakeAdmin struct {
	mu       sync.Mutex
	calls    []string // "METHOD path"
	auth     []string // Authorization headers seen
	bindings map[string]map[string]any
	stores   map[string]map[string]any
	versions map[string][]map[string]any
	blocked  bool // the plan reports blockers
}

func newFakeAdmin() *fakeAdmin {
	return &fakeAdmin{
		bindings: map[string]map[string]any{},
		stores:   map[string]map[string]any{"demo": {"name": "demo", "description": "the demo", "created_at": "2026-10-24T00:00:00Z", "model": map[string]any{"model_name": "core", "model_version": 2, "in_sync": true, "applied_at": "2026-10-24T00:00:00Z", "applied_by": "ci", "live_checksum": "abc"}}},
		versions: map[string][]map[string]any{},
	}
}

func (f *fakeAdmin) handler(_ *testing.T) http.Handler {
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	fail := func(w http.ResponseWriter, status int, msg string) {
		writeJSON(w, status, map[string]any{"status": status, "message": msg})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/subjects/{type}/{id}/objects", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("format") == "csv" {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			_, _ = w.Write([]byte("store,subject_type,subject_id,object_type,relation,object_id,is_wildcard,direct,truncated\n" +
				r.PathValue("store") + "," + r.PathValue("type") + "," + r.PathValue("id") + ",doc,can_read,d1,false,true,false\n"))
			return
		}
		writeJSON(w, 200, map[string]any{"store": r.PathValue("store"), "subject": map[string]string{"type": r.PathValue("type"), "id": r.PathValue("id")},
			"objects": []map[string]any{{"object_type": "doc", "relation": "can_read", "object_id": "d1", "is_wildcard": false, "direct": true, "truncated": false},
				{"object_type": "doc", "relation": "can_read", "object_id": "*", "is_wildcard": true, "direct": false, "truncated": true}}, "truncated": true})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/subjects/{type}/{id}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"subject": r.PathValue("type") + ":" + r.PathValue("id"), "direct": []any{}, "events_about": []any{}})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/issuers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"source": "env+db", "revision": 7, "issuers": []any{}})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/issuer-bindings", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []map[string]any{}
		for _, b := range f.bindings {
			out = append(out, b)
		}
		writeJSON(w, 200, map[string]any{"bindings": out})
	})
	mux.HandleFunc("PUT /pgauthz/v1/admin/issuer-bindings", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		iss, _ := b["issuer"].(string)
		if iss == "https://untrusted" {
			fail(w, 400, "issuer https://untrusted is not trusted by this instance (JWT_ISSUERS): a binding cannot add trust")
			return
		}
		f.mu.Lock()
		f.bindings[iss] = b
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"issuer": iss, "revision": 8})
	})
	mux.HandleFunc("DELETE /pgauthz/v1/admin/issuer-bindings", func(w http.ResponseWriter, r *http.Request) {
		iss := r.URL.Query().Get("issuer")
		f.mu.Lock()
		_, ok := f.bindings[iss]
		delete(f.bindings, iss)
		f.mu.Unlock()
		if !ok {
			fail(w, 404, "no binding for issuer "+iss)
			return
		}
		writeJSON(w, 200, map[string]any{"issuer": iss, "deleted": true})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/stores", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []map[string]any{}
		for _, s := range f.stores {
			out = append(out, s)
		}
		writeJSON(w, 200, map[string]any{"stores": out})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		s, ok := f.stores[r.PathValue("store")]
		f.mu.Unlock()
		if !ok {
			fail(w, 404, "no store "+r.PathValue("store"))
			return
		}
		writeJSON(w, 200, s)
	})
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		name := r.PathValue("store")
		s, found := f.stores[name]
		if !found {
			s = map[string]any{"name": name, "created_at": "2026-10-24T00:00:00Z"}
			f.stores[name] = s
		}
		for k, v := range req {
			if k == "retired" && v == true {
				s["retired_at"] = "2026-10-24T01:00:00Z"
			} else {
				s[map[string]string{"description": "description", "docs_url": "docs_url"}[k]] = v
			}
		}
		status := 200
		if !found {
			status = 201
		}
		writeJSON(w, status, map[string]any{"store": s, "created": !found})
	})
	mux.HandleFunc("DELETE /pgauthz/v1/admin/stores/{store}/decisions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"store": r.PathValue("store"), "store_id": r.URL.Query().Get("store_id"), "purged_decisions": true, "deleted_at": "2026-10-25T09:00:00Z", "decisions": 12})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/deletions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"store": r.PathValue("store"), "deletions": []map[string]any{{"store_id": 7, "deleted_at": "2026-10-25T09:00:00Z", "deleted_by": "ci"}}})
	})
	mux.HandleFunc("DELETE /pgauthz/v1/admin/stores/{store}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		_, ok := f.stores[r.PathValue("store")]
		delete(f.stores, r.PathValue("store"))
		f.mu.Unlock()
		if !ok {
			fail(w, 404, "no store")
			return
		}
		writeJSON(w, 200, map[string]any{"store": r.PathValue("store"), "deleted": true, "purged_audit": r.URL.Query().Get("purge_audit") == "true"})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/model", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{"store": r.PathValue("store"), "definition": map[string]any{"format": 1, "types": []any{map[string]any{"name": "doc"}}, "relations": []any{}, "rules": []any{}, "type_restrictions": []any{}, "conditions": []any{}}, "status": map[string]any{"model_name": "core", "model_version": 2, "in_sync": true, "applied_at": "2026-10-24T00:00:00Z", "applied_by": "ci"}}
		if r.URL.Query().Get("dsl") == "true" {
			out["dsl"] = "model\n  schema 1.1\ntype doc\n"
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}/model", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		plan := map[string]any{"store": r.PathValue("store"), "model": "core", "version": 2, "can_apply": !f.blocked, "changes": map[string]any{"relations": map[string]any{"add": []any{map[string]any{"name": "can_share"}}}}}
		if f.blocked {
			plan["blockers"] = []any{"type rogue still has tuples"}
		}
		if r.URL.Query().Get("plan") == "true" {
			writeJSON(w, 200, map[string]any{"store": r.PathValue("store"), "model": req["model"], "plan": plan, "can_apply": !f.blocked})
			return
		}
		if f.blocked {
			writeJSON(w, 409, map[string]any{"status": 409, "message": "the plan reports blockers; nothing was applied", "plan": plan, "can_apply": false})
			return
		}
		writeJSON(w, 200, map[string]any{"store": r.PathValue("store"), "model": "core", "applied": 2, "plan": plan})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/models", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []map[string]any{}
		for name, vs := range f.versions {
			if q := r.URL.Query().Get("name"); q != "" && q != name {
				continue
			}
			out = append(out, vs...)
		}
		writeJSON(w, 200, map[string]any{"versions": out})
	})
	mux.HandleFunc("POST /pgauthz/v1/admin/models/{name}/versions", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if _, ok := req["openfga"]; !ok {
			fail(w, 400, "the CLI publishes openfga")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		name := r.PathValue("name")
		v := len(f.versions[name]) + 1
		f.versions[name] = append(f.versions[name], map[string]any{"name": name, "version": v, "checksum": "abcdef0123456789", "description": req["description"], "created_at": "2026-10-24T00:00:00Z", "created_by": "cert:ci"})
		writeJSON(w, 200, map[string]any{"model": name, "version": v})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/models/{name}/rollout", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"model": r.PathValue("name"), "stores": []any{map[string]any{"store": "demo", "model_version": 1, "latest_version": 2, "in_sync": true, "applied_at": "2026-10-24T00:00:00Z"}}})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/recorders", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"store": r.PathValue("store"), "recorders": []any{map[string]any{"db_role": "svc", "actions": []string{"pay"}}}})
	})
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}/recorders/{role}", func(w http.ResponseWriter, r *http.Request) {
		var req map[string][]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, 200, map[string]any{"store": r.PathValue("store"), "db_role": r.PathValue("role"), "actions": req["actions"]})
	})
	mux.HandleFunc("DELETE /pgauthz/v1/admin/stores/{store}/recorders/{role}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"deleted": true})
	})
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/namespaces", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"store": r.PathValue("store"), "namespaces": []any{map[string]any{"name": "hr", "types": []string{"doc"}, "access": []any{map[string]any{"db_role": "app_hr", "can_read": true, "can_write": false}}}}})
	})
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}/namespaces/{ns}/access/{role}", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]bool
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, 200, map[string]any{"store": r.PathValue("store"), "namespace": r.PathValue("ns"), "db_role": r.PathValue("role"), "can_read": req["can_read"], "can_write": req["can_write"]})
	})
	mux.HandleFunc("DELETE /pgauthz/v1/admin/stores/{store}/namespaces/{ns}/access/{role}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"deleted": true})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		if r.Header.Get("Authorization") == "Bearer bad" {
			fail(w, 403, "management refused: the token does not hold the admin role (ADMIN_ROLE)")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (f *fakeAdmin) called(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// capture runs fn with stdout captured.
func capture(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := fn()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), err
}

func serverEnv(t *testing.T, url, token string) {
	t.Helper()
	t.Setenv("PGAUTHZ_SERVER", url)
	t.Setenv("PGAUTHZ_TOKEN", token)
	t.Setenv("PGAUTHZ_DSN", "")
	t.Setenv("PGAUTHZ_CLIENT_CERT", "")
	t.Setenv("PGAUTHZ_CLIENT_KEY", "")
	t.Setenv("PGAUTHZ_CA", "")
}

func TestClientCredentialsAndErrors(t *testing.T) {
	f := newFakeAdmin()
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	serverEnv(t, srv.URL, "tok")

	// the bearer token travels; a refusal is the API's message
	out, err := capture(t, func() error { return cmdIssuersList([]string{}) })
	if err != nil || !strings.HasPrefix(out, "revision 7") || f.auth[len(f.auth)-1] != "Bearer tok" {
		t.Fatalf("list: %v %q auth=%v", err, out, f.auth)
	}
	t.Setenv("PGAUTHZ_TOKEN", "bad")
	_, err = capture(t, func() error { return cmdIssuersList([]string{}) })
	var ae *apiError
	if err == nil || !errorsAsAPI(err, &ae) || ae.Status != 403 || !strings.Contains(err.Error(), "does not hold the admin role") {
		t.Fatalf("403: %v", err)
	}
	// no credential at all is refused before any request
	t.Setenv("PGAUTHZ_TOKEN", "")
	if _, err := capture(t, func() error { return cmdIssuersList([]string{}) }); err == nil || !strings.Contains(err.Error(), "needs a credential") {
		t.Fatalf("no credential: %v", err)
	}
	// --server wins over --dsn, and must be a URL
	if _, err := capture(t, func() error { return cmdIssuersList([]string{"--server", "nope", "--token", "x"}) }); err == nil || !strings.Contains(err.Error(), "http(s) URL") {
		t.Fatalf("bad server: %v", err)
	}
	if _, err := capture(t, func() error { return cmdIssuersList([]string{"--server", srv.URL, "--token", "x", "--cert", "/c.pem"}) }); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Fatalf("cert without key: %v", err)
	}
}

func errorsAsAPI(err error, target **apiError) bool {
	for err != nil {
		if e, ok := err.(*apiError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestIssuersVerbsOverAPI(t *testing.T) {
	f := newFakeAdmin()
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	serverEnv(t, srv.URL, "tok")
	dir := t.TempDir()
	file := filepath.Join(dir, "issuers.json")
	if err := os.WriteFile(file, []byte(`{"bindings":[{"issuer":"https://a","stores":["a_.*"],"db_roles":[],"client_db_roles":{},"pep_clients":{},"enabled":true,"description":"tenant a"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := capture(t, func() error { return cmdIssuersImport([]string{file}) })
	if err != nil || !strings.Contains(out, "+ create https://a") || !strings.Contains(out, "applied over the admin API: 1 created") {
		t.Fatalf("import: %v %q", err, out)
	}
	if !f.called("PUT /pgauthz/v1/admin/issuer-bindings") {
		t.Fatalf("no PUT: %v", f.calls)
	}
	out, err = capture(t, func() error { return cmdIssuersImport([]string{file}) })
	if err != nil || !strings.HasPrefix(out, "no changes") {
		t.Fatalf("idempotent: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdIssuersExport([]string{}) })
	if err != nil || !strings.Contains(out, `"issuer": "https://a"`) || strings.Contains(out, "updated_by") {
		t.Fatalf("export: %v %q", err, out)
	}
	// a refusal names the issuer and what was applied before it
	if err := os.WriteFile(file, []byte(`{"bindings":[{"issuer":"https://untrusted","stores":["x"],"enabled":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = capture(t, func() error { return cmdIssuersImport([]string{file, "--prune"}) })
	if err == nil || !strings.Contains(err.Error(), "cannot add trust") || !strings.Contains(err.Error(), "0 change(s) before it") {
		t.Fatalf("refused import: %v", err)
	}
	out, err = capture(t, func() error { return cmdIssuersDelete([]string{"https://a"}) })
	if err != nil || !strings.HasPrefix(out, "deleted the binding of https://a") || !f.called("DELETE /pgauthz/v1/admin/issuer-bindings?issuer=https%3A%2F%2Fa") {
		t.Fatalf("delete: %v %q %v", err, out, f.calls)
	}
	if _, err := capture(t, func() error { return cmdIssuersDelete([]string{"https://a"}) }); err == nil || !strings.Contains(err.Error(), "no binding") {
		t.Fatalf("delete again: %v", err)
	}
}

func TestModelVerbsOverAPI(t *testing.T) {
	f := newFakeAdmin()
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	serverEnv(t, srv.URL, "tok")

	out, err := capture(t, func() error { return cmdPublish([]string{"testdata/model.fga", "--name", "core", "--message", "v1"}) })
	if err != nil || !strings.Contains(out, "published core@1") || !f.called("POST /pgauthz/v1/admin/models/core/versions") {
		t.Fatalf("publish: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdPlan([]string{"core@2", "--store", "demo"}) })
	if err != nil || !strings.Contains(out, "plan: store demo") || !f.called("PUT /pgauthz/v1/admin/stores/demo/model?plan=true") {
		t.Fatalf("plan: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdDiff([]string{"core", "--store", "demo"}) })
	if err != nil || !strings.Contains(out, "+ relations") {
		t.Fatalf("diff: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdApply([]string{"core@2", "--store", "demo"}) })
	if err != nil || !strings.Contains(out, "applied core@2 to demo") {
		t.Fatalf("apply: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdApply([]string{"core", "--stores", "demo,other"}) })
	if err != nil || strings.Count(out, "applied core@2") != 2 {
		t.Fatalf("fleet apply: %v %q", err, out)
	}
	f.blocked = true
	_, err = capture(t, func() error { return cmdApply([]string{"core", "--store", "demo"}) })
	if err == nil || !strings.Contains(err.Error(), "apply refused") || !strings.Contains(err.Error(), "blockers") {
		t.Fatalf("blocked apply: %v", err)
	}
	f.blocked = false
	out, err = capture(t, func() error { return cmdStatus([]string{"--store", "demo"}) })
	if err != nil || !strings.Contains(out, "store demo: core@2") || !strings.Contains(out, "in_sync: true") {
		t.Fatalf("status: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdVersions([]string{"core"}) })
	if err != nil || !strings.HasPrefix(out, "core@1  abcdef012345") {
		t.Fatalf("versions: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdRollout([]string{"core"}) })
	if err != nil || !strings.Contains(out, "demo  @1/latest 2") || !strings.Contains(out, "(outdated)") {
		t.Fatalf("rollout: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdExport([]string{"--store", "demo"}) })
	if err != nil || !strings.Contains(out, `"format": 1`) {
		t.Fatalf("export: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdExport([]string{"--store", "demo", "--dsl"}) })
	if err != nil || !strings.HasPrefix(out, "model\n") || !f.called("GET /pgauthz/v1/admin/stores/demo/model?dsl=true") {
		t.Fatalf("export dsl: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdExport([]string{"--store", "demo", "--sql"}) })
	if err != nil || !strings.Contains(out, "model_register_type") {
		t.Fatalf("export sql: %v %q", err, out)
	}
}

func TestStoreVerbsOverAPI(t *testing.T) {
	f := newFakeAdmin()
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	serverEnv(t, srv.URL, "")
	if err := cmdStore("list", nil); err == nil || !strings.Contains(err.Error(), "needs a credential") {
		t.Fatalf("store without a credential: %v", err)
	}
	serverEnv(t, "", "")
	if err := cmdStore("list", nil); err == nil || !strings.Contains(err.Error(), "admin API only") {
		t.Fatalf("store without --server: %v", err)
	}
	serverEnv(t, srv.URL, "tok")

	out, err := capture(t, func() error { return cmdStore("set", []string{"tenant_a", "--description", "tenant A"}) })
	if err != nil || !strings.HasPrefix(out, "created store tenant_a") {
		t.Fatalf("set: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdStore("set", []string{"tenant_a", "--retired"}) })
	if err != nil || !strings.HasPrefix(out, "updated store tenant_a") {
		t.Fatalf("retire: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdStore("list", nil) })
	if err != nil || !strings.Contains(out, "tenant_a") || !strings.Contains(out, "RETIRED") || !strings.Contains(out, "unmanaged") {
		t.Fatalf("list: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdStore("get", []string{"tenant_a"}) })
	if err != nil || !strings.Contains(out, `"description": "tenant A"`) {
		t.Fatalf("get: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdStore("recorder-set", []string{"demo", "svc", "pay,approve"}) })
	if err != nil || !strings.Contains(out, "svc may record pay,approve in demo") {
		t.Fatalf("recorder-set: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdStore("recorders", []string{"demo"}) })
	if err != nil || !strings.Contains(out, "svc") || !strings.Contains(out, "pay") {
		t.Fatalf("recorders: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdStore("namespace-grant", []string{"demo", "hr", "app_hr", "--read"}) })
	if err != nil || !strings.Contains(out, "read=true write=false") || !f.called("PUT /pgauthz/v1/admin/stores/demo/namespaces/hr/access/app_hr") {
		t.Fatalf("namespace-grant: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdStore("namespaces", []string{"demo"}) })
	if err != nil || !strings.Contains(out, "access=app_hr:r-") {
		t.Fatalf("namespaces: %v %q", err, out)
	}
	out, err = capture(t, func() error {
		return cmdStore("purge-decisions", []string{"tenant_a", "--store-id", "7"})
	})
	if err != nil || !strings.HasPrefix(out, "purged the decision-log lines of tenant_a, incarnation 7 (deleted 2026-10-25T09:00:00Z): 12 deleted now") || !strings.HasSuffix(f.calls[len(f.calls)-1], "DELETE /pgauthz/v1/admin/stores/tenant_a/decisions?store_id=7") {
		t.Fatalf("purge-decisions: %v %q %s", err, out, f.calls[len(f.calls)-1])
	}
	if err := cmdStore("purge-decisions", []string{"tenant_a"}); err == nil || !strings.Contains(err.Error(), "--store-id") {
		t.Fatalf("purge-decisions without an incarnation: %v", err)
	}
	out, err = capture(t, func() error { return cmdStore("deletions", []string{"tenant_a"}) })
	if err != nil || !strings.Contains(out, "7          2026-10-25T09:00:00Z         ci") {
		t.Fatalf("purge-decisions: %v %q %s", err, out, f.calls[len(f.calls)-1])
	}
	out, err = capture(t, func() error { return cmdStore("delete", []string{"tenant_a", "--purge-audit", "--purge-decisions"}) })
	if err != nil || !strings.HasPrefix(out, "deleted store tenant_a") || !f.called("DELETE /pgauthz/v1/admin/stores/tenant_a?purge_audit=true") {
		t.Fatalf("delete: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdStore("recorders", []string{"demo", "--json"}) })
	if err != nil || !strings.Contains(out, `"db_role": "svc"`) {
		t.Fatalf("json: %v %q", err, out)
	}
}

// A client certificate as the credential: the CLI's --cert/--key/--ca reach
// an mTLS server; without the certificate the handshake fails.
func TestClientCertificate(t *testing.T) {
	now := time.Now()
	mk := func(tmpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signer, signerKey := tmpl, key
		if parent != nil {
			signer, signerKey = parent, parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		return cert, key
	}
	ca, caKey := mk(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}, nil, nil)
	srvCert, srvKey := mk(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "pgauthzd"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, caKey)
	cliCert, cliKey := mk(&x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "terraform"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ca, caKey)

	dir := t.TempDir()
	write := func(name string, block *pem.Block) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caFile := write("ca.pem", &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	certFile := write("cli.pem", &pem.Block{Type: "CERTIFICATE", Bytes: cliCert.Raw})
	keyDER, _ := x509.MarshalECPrivateKey(cliKey)
	keyFile := write("cli.key", &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	f := newFakeAdmin()
	srv := httptest.NewUnstartedServer(f.handler(t))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert.Raw}, PrivateKey: srvKey, Leaf: srvCert}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the failed handshakes below are the point
	srv.StartTLS()
	defer srv.Close()

	serverEnv(t, srv.URL, "")
	out, err := capture(t, func() error { return cmdIssuersList([]string{"--cert", certFile, "--key", keyFile, "--ca", caFile}) })
	if err != nil || !strings.HasPrefix(out, "revision 7") || f.auth[len(f.auth)-1] != "" {
		t.Fatalf("mTLS: %v %q auth=%v", err, out, f.auth)
	}
	if _, err := capture(t, func() error { return cmdIssuersList([]string{"--token", "tok", "--ca", caFile}) }); err == nil {
		t.Fatal("without the client certificate the handshake must fail")
	}
	if _, err := capture(t, func() error { return cmdIssuersList([]string{"--cert", certFile, "--key", keyFile}) }); err == nil {
		t.Fatal("without --ca the server certificate is not trusted")
	}
}

// The subject verbs: the table, the CSV to a file, the export, flags as
// query parameters; erase is no verb.
func TestSubjectVerbsOverAPI(t *testing.T) {
	f := newFakeAdmin()
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	serverEnv(t, "", "")
	if err := cmdSubject("objects", []string{"demo", "user:alice"}); err == nil || !strings.Contains(err.Error(), "admin API only") {
		t.Fatalf("without --server: %v", err)
	}
	serverEnv(t, srv.URL, "tok")
	if err := cmdSubject("objects", []string{"demo", "alice"}); err == nil || !strings.Contains(err.Error(), "type:id") {
		t.Fatalf("bad subject: %v", err)
	}
	out, err := capture(t, func() error {
		return cmdSubject("objects", []string{"demo", "user:alice", "--relations", "can_read,owner", "--object-types", "doc", "--limit", "7"})
	})
	if err != nil || !strings.Contains(out, "doc                      can_read                 d1  (direct)") || !strings.Contains(out, "(wildcard: every object)  (truncated)") || !strings.Contains(out, "some pair hit the limit") {
		t.Fatalf("objects table: %v %q", err, out)
	}
	last := f.calls[len(f.calls)-1]
	if !strings.Contains(last, "/subjects/user/alice/objects?") || !strings.Contains(last, "limit=7") || !strings.Contains(last, "object_types=doc") || !strings.Contains(last, "relations=can_read%2Cowner") {
		t.Fatalf("objects query: %s", last)
	}
	csvFile := t.TempDir() + "/alice.csv"
	if _, err := capture(t, func() error { return cmdSubject("objects", []string{"demo", "user:alice", "--csv", "--out", csvFile}) }); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(csvFile)
	if !strings.HasPrefix(string(b), "store,subject_type,subject_id,") || !strings.Contains(string(b), "demo,user,alice,doc,can_read,d1,") {
		t.Fatalf("csv file: %q", b)
	}
	out, err = capture(t, func() error { return cmdSubject("export", []string{"demo", "user:alice"}) })
	if err != nil || !strings.Contains(out, `"events_about"`) {
		t.Fatalf("export: %v %q", err, out)
	}
	if err := cmdSubject("erase", []string{"demo", "user:alice"}); err == nil || !strings.Contains(err.Error(), "unknown subject verb") {
		t.Fatalf("erase is not a verb: %v", err)
	}
}
