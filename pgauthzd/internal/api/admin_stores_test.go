package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

// storeStub is the store and model admin behind the handlers in these tests:
// stores by name, a registry of versions, a fixed plan verdict per store.
type storeStub struct {
	authz.Backend
	stores   map[string]*authz.StoreRow
	versions map[string][]int
	blocked  map[string]bool // store → the plan reports blockers
	actors   []string
}

func (s *storeStub) ListStores(context.Context) ([]authz.StoreRow, error) {
	out := []authz.StoreRow{}
	for _, r := range s.stores {
		out = append(out, *r)
	}
	return out, nil
}
func (s *storeStub) GetStore(_ context.Context, name string) (authz.StoreRow, bool, error) {
	if r, ok := s.stores[name]; ok {
		return *r, true, nil
	}
	return authz.StoreRow{}, false, nil
}
func (s *storeStub) UpsertStore(_ context.Context, name string, desc, docs *string, retired *bool, actor string) (authz.StoreRow, bool, error) {
	s.actors = append(s.actors, actor)
	r, found := s.stores[name]
	if !found {
		r = &authz.StoreRow{Name: name, CreatedAt: time.Now()}
		s.stores[name] = r
	}
	if desc != nil {
		r.Description = *desc
	}
	if docs != nil {
		r.DocsURL = *docs
	}
	if retired != nil && *retired && r.RetiredAt == nil {
		now := time.Now()
		r.RetiredAt = &now
	}
	return *r, !found, nil
}
func (s *storeStub) DeleteStore(_ context.Context, name string, _ bool, actor string) (bool, error) {
	s.actors = append(s.actors, actor)
	_, ok := s.stores[name]
	delete(s.stores, name)
	return ok, nil
}
func (s *storeStub) ExportModel(_ context.Context, store string) (json.RawMessage, error) {
	if _, ok := s.stores[store]; !ok {
		return nil, fmt.Errorf("%w: store %s not found", authz.ErrInvalidRequest, store)
	}
	return json.RawMessage(`{"format":1,"types":[{"name":"doc"}]}`), nil
}
func (s *storeStub) ModelStatus(context.Context, string) (json.RawMessage, error) {
	return json.RawMessage(`{"model_name":null,"live_checksum":"abc"}`), nil
}
func (s *storeStub) PlanApply(_ context.Context, store, name string, version *int) (json.RawMessage, error) {
	if _, ok := s.versions[name]; !ok {
		return nil, fmt.Errorf("%w: no registry entry for model %s", authz.ErrInvalidRequest, name)
	}
	if s.blocked[store] {
		return json.RawMessage(`{"can_apply":false,"blockers":["type rogue has tuples"]}`), nil
	}
	return json.RawMessage(`{"can_apply":true,"changes":[]}`), nil
}
func (s *storeStub) ApplyModel(_ context.Context, store, name string, version *int, actor string) (int, error) {
	s.actors = append(s.actors, actor)
	vs := s.versions[name]
	if version != nil {
		return *version, nil
	}
	return vs[len(vs)-1], nil
}
func (s *storeStub) ListModelVersions(_ context.Context, name string) ([]json.RawMessage, error) {
	out := []json.RawMessage{}
	for n, vs := range s.versions {
		if name != "" && n != name {
			continue
		}
		for _, v := range vs {
			out = append(out, json.RawMessage(fmt.Sprintf(`{"name":%q,"version":%d}`, n, v)))
		}
	}
	return out, nil
}
func (s *storeStub) RolloutStatus(_ context.Context, name string) ([]json.RawMessage, error) {
	return []json.RawMessage{json.RawMessage(fmt.Sprintf(`{"store":"a_docs","model_version":1,"latest_version":%d}`, len(s.versions[name])))}, nil
}
func (s *storeStub) DescribeModel(context.Context, string) (string, error) {
	return "model\n  schema 1.1\n", nil
}
func (s *storeStub) PublishModel(_ context.Context, name, fromStore string, def, openfga json.RawMessage, _ string, actor string) (int, error) {
	s.actors = append(s.actors, actor)
	if fromStore != "" {
		if _, ok := s.stores[fromStore]; !ok {
			return 0, fmt.Errorf("%w: store %s not found", authz.ErrInvalidRequest, fromStore)
		}
	}
	s.versions[name] = append(s.versions[name], len(s.versions[name])+1)
	return len(s.versions[name]), nil
}

func storesFixture(t *testing.T) (*Handler, *storeStub) {
	t.Helper()
	h, _ := adminFixture(t)
	stub := &storeStub{
		stores:   map[string]*authz.StoreRow{"a_docs": {Name: "a_docs"}, "b_docs": {Name: "b_docs"}, "shared": {Name: "shared"}},
		versions: map[string][]int{"core": {1, 2}},
		blocked:  map[string]bool{"b_docs": true},
	}
	h.rawWrite = stub
	return h, stub
}

func serveAdmin(h *Handler, r *http.Request) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	registerAdmin(mux, h)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// Stores: a tenant admin sees and manages the stores its issuer is bound
// to, a platform admin every store; create (201) / update (200) / retire /
// delete, the name rule, the actor.
func TestAdminStores(t *testing.T) {
	h, stub := storesFixture(t)
	w := serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "a_docs") || strings.Contains(w.Body.String(), "b_docs") || strings.Contains(w.Body.String(), "shared") {
		t.Fatalf("tenant a's stores: %d %s", w.Code, w.Body.String())
	}
	w = serveAdmin(h, platformAdmin.request("GET", "/pgauthz/v1/admin/stores", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "b_docs") || !strings.Contains(w.Body.String(), "shared") {
		t.Fatalf("platform's stores: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/b_docs", "")); w.Code != 403 {
		t.Fatalf("another tenant's store: %d", w.Code)
	}
	if w := serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/a_nope", "")); w.Code != 404 {
		t.Fatalf("an unknown store in scope: %d", w.Code)
	}
	if w := serveAdmin(h, platformAdmin.request("GET", "/pgauthz/v1/admin/stores/bad-name", "")); w.Code != 400 {
		t.Fatalf("a bad store name: %d", w.Code)
	}
	// an issuer-scoped admin whose issuer is unbound manages no store
	w = serveAdmin(h, token{iss: "https://tenant-b", sub: "root", roles: nil, client: "x"}.request("GET", "/pgauthz/v1/admin/stores", ""))
	if w.Code != 403 {
		t.Fatalf("no admin binding: %d", w.Code)
	}

	// create, update, retire, delete — within scope, recorded
	w = serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_mail", `{"description":"tenant a mail"}`))
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"created":true`) {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	w = serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_mail", `{"docs_url":"https://docs"}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"created":false`) || stub.stores["a_mail"].Description != "tenant a mail" || stub.stores["a_mail"].DocsURL != "https://docs" {
		t.Fatalf("update keeps what was not sent: %d %s %+v", w.Code, w.Body.String(), stub.stores["a_mail"])
	}
	if w := serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/b_mail", `{}`)); w.Code != 403 {
		t.Fatalf("creating outside the scope: %d", w.Code)
	}
	if w := serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_mail", `{"bogus":1}`)); w.Code != 400 {
		t.Fatalf("unknown field: %d", w.Code)
	}
	w = serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_mail", `{"retired":true}`))
	if w.Code != 200 || stub.stores["a_mail"].RetiredAt == nil {
		t.Fatalf("retire: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/a_mail?purge_audit=true", "")); w.Code != 200 || !strings.Contains(w.Body.String(), `"purged_audit":true`) {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/a_mail", "")); w.Code != 404 {
		t.Fatalf("delete again: %d", w.Code)
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/shared", "")); w.Code != 403 {
		t.Fatalf("deleting outside the scope: %d", w.Code)
	}
	for _, a := range stub.actors {
		if a != "user:alice via terraform-a" {
			t.Fatalf("actor: %q", a)
		}
	}
}

// Models: the store's model and state; apply plans first (409 with the plan
// on blockers, ?plan=true never applies); the registry needs platform scope.
func TestAdminModels(t *testing.T) {
	h, stub := storesFixture(t)
	w := serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/a_docs/model", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"definition":{"format":1`) || !strings.Contains(w.Body.String(), `"live_checksum":"abc"`) {
		t.Fatalf("model: %d %s", w.Code, w.Body.String())
	}
	w = serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_docs/model?plan=true", `{"model":"core@2"}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"can_apply":true`) || strings.Contains(w.Body.String(), `"applied"`) {
		t.Fatalf("plan: %d %s", w.Code, w.Body.String())
	}
	w = serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_docs/model", `{"model":"core@2"}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"applied":2`) {
		t.Fatalf("apply: %d %s", w.Code, w.Body.String())
	}
	w = serveAdmin(h, platformAdmin.request("PUT", "/pgauthz/v1/admin/stores/b_docs/model", `{"model":"core"}`))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "rogue") || !strings.Contains(w.Body.String(), `"can_apply":false`) {
		t.Fatalf("blockers: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, platformAdmin.request("PUT", "/pgauthz/v1/admin/stores/shared/model", `{"model":"nope"}`)); w.Code != 400 {
		t.Fatalf("unknown model: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, platformAdmin.request("PUT", "/pgauthz/v1/admin/stores/shared/model", `{"model":"core@zero"}`)); w.Code != 400 {
		t.Fatalf("bad ref: %d", w.Code)
	}

	// the registry: platform only
	if w := serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/models", "")); w.Code != 403 {
		t.Fatalf("tenant admin reads the registry: %d", w.Code)
	}
	w = serveAdmin(h, platformAdmin.request("GET", "/pgauthz/v1/admin/models?name=core", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"version":2`) {
		t.Fatalf("versions: %d %s", w.Code, w.Body.String())
	}
	w = serveAdmin(h, platformAdmin.request("POST", "/pgauthz/v1/admin/models/core/versions", `{"from_store":"a_docs","description":"v3"}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"version":3`) {
		t.Fatalf("publish from a store: %d %s", w.Code, w.Body.String())
	}
	w = serveAdmin(h, platformAdmin.request("POST", "/pgauthz/v1/admin/models/fresh/versions", `{"definition":{"format":1,"types":[{"name":"doc"}],"relations":[],"rules":[],"type_restrictions":[],"conditions":[]}}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"version":1`) {
		t.Fatalf("publish a definition: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, platformAdmin.request("POST", "/pgauthz/v1/admin/models/core/versions", `{"from_store":"a_docs","definition":{"format":1}}`)); w.Code != 400 {
		t.Fatalf("both sources: %d", w.Code)
	}
	if w := serveAdmin(h, platformAdmin.request("POST", "/pgauthz/v1/admin/models/core/versions", `{}`)); w.Code != 400 {
		t.Fatalf("no source: %d", w.Code)
	}
	w = serveAdmin(h, platformAdmin.request("POST", "/pgauthz/v1/admin/models/fga/versions", `{"openfga":{"schema_version":"1.1","type_definitions":[]}}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"version":1`) {
		t.Fatalf("publish an OpenFGA model: %d %s", w.Code, w.Body.String())
	}
	w = serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/a_docs/model?dsl=true", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"dsl":"model\n`) {
		t.Fatalf("model with dsl: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("POST", "/pgauthz/v1/admin/models/core/versions", `{"from_store":"a_docs"}`)); w.Code != 403 {
		t.Fatalf("tenant admin publishes: %d", w.Code)
	}
	w = serveAdmin(h, platformAdmin.request("GET", "/pgauthz/v1/admin/models/core/rollout", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"latest_version":3`) {
		t.Fatalf("rollout: %d %s", w.Code, w.Body.String())
	}
	if len(stub.actors) < 3 || stub.actors[len(stub.actors)-1] != "user:ops" {
		t.Fatalf("actors: %v", stub.actors)
	}
}
