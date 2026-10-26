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

	"thomasdarimont.de/authz/pgauthzadm"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

// storeStub is the store and model admin behind the handlers in these tests:
// stores by name, a registry of versions, a fixed plan verdict per store.
type storeStub struct {
	authz.Backend
	grantStub
	stores     map[string]*authz.StoreRow
	versions   map[string][]int
	blocked    map[string]bool // store → the plan reports blockers
	actors     []string
	recorders  map[string]map[string][]string           // store → role → actions
	deletions  map[string][]authz.StoreDeletion         // store → receipts
	namespaces map[string]map[string]map[string][2]bool // store → namespace → role → (read, write)
	tests      []testModelCall
}

// the data-subject methods: canned rows, the arguments remembered
type subjectCall struct {
	store, typ, id          string
	relations, objectTypes  []string
	limit                   int
	purgeEvents, purgeAudit bool
	actor                   string
}

func (s *storeStub) SubjectObjects(_ context.Context, store, typ, id string, relations, objectTypes []string, limit int) ([]authz.SubjectObjectRow, error) {
	if _, ok := s.stores[store]; !ok {
		return nil, fmt.Errorf("%w: Unknown store: %s", authz.ErrInvalidRequest, store)
	}
	subjectCalls = append(subjectCalls, subjectCall{store: store, typ: typ, id: id, relations: relations, objectTypes: objectTypes, limit: limit})
	return []authz.SubjectObjectRow{
		{ObjectType: "doc", Relation: "can_read", ObjectID: "d1", Direct: true},
		{ObjectType: "doc", Relation: "can_read", ObjectID: "d,2\"q", Truncated: true},
	}, nil
}

func (s *storeStub) ExportSubject(_ context.Context, store, typ, id string, relations []string, limit int) (json.RawMessage, error) {
	subjectCalls = append(subjectCalls, subjectCall{store: store, typ: typ, id: id, relations: relations, limit: limit})
	return json.RawMessage(`{"subject":"` + typ + ":" + id + `","direct":[]}`), nil
}

var subjectCalls []subjectCall

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
func (s *storeStub) DeleteStore(_ context.Context, name string, _ bool, actor string) (int32, time.Time, bool, error) {
	s.actors = append(s.actors, actor)
	_, ok := s.stores[name]
	delete(s.stores, name)
	if ok {
		if s.deletions == nil {
			s.deletions = map[string][]authz.StoreDeletion{}
		}
		s.deletions[name] = append(s.deletions[name], authz.StoreDeletion{StoreID: 7, DeletedAt: time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC), DeletedBy: actor})
	}
	return 7, time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC), ok, nil
}

func (s *storeStub) StoreDeletions(_ context.Context, name string) ([]authz.StoreDeletion, error) {
	return s.deletions[name], nil
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
func (s *storeStub) PlanApply(_ context.Context, store, name string, _ *int) (json.RawMessage, error) {
	if _, ok := s.versions[name]; !ok {
		return nil, fmt.Errorf("%w: no registry entry for model %s", authz.ErrInvalidRequest, name)
	}
	if s.blocked[store] {
		return json.RawMessage(`{"can_apply":false,"blockers":["type rogue has tuples"]}`), nil
	}
	return json.RawMessage(`{"can_apply":true,"changes":[]}`), nil
}
func (s *storeStub) ApplyModel(_ context.Context, _, name string, version *int, actor string) (int, error) {
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
func (s *storeStub) RecorderActions(_ context.Context, store string) ([]authz.RecorderRow, error) {
	out := []authz.RecorderRow{}
	for role, acts := range s.recorders[store] {
		out = append(out, authz.RecorderRow{DBRole: role, Actions: acts})
	}
	return out, nil
}
func (s *storeStub) SetRecorderActions(_ context.Context, store, role string, actions []string, actor string) error {
	s.actors = append(s.actors, actor)
	for _, a := range actions {
		if a == "nope" {
			return fmt.Errorf("%w: relation nope not declared", authz.ErrInvalidRequest)
		}
	}
	if s.recorders[store] == nil {
		s.recorders[store] = map[string][]string{}
	}
	s.recorders[store][role] = actions
	return nil
}
func (s *storeStub) RevokeRecorderActions(_ context.Context, store, role, actor string) (bool, error) {
	s.actors = append(s.actors, actor)
	_, ok := s.recorders[store][role]
	delete(s.recorders[store], role)
	return ok, nil
}
func (s *storeStub) Namespaces(_ context.Context, store string) ([]authz.NamespaceRow, error) {
	out := []authz.NamespaceRow{}
	for ns, grants := range s.namespaces[store] {
		acc, _ := json.Marshal(grants)
		out = append(out, authz.NamespaceRow{Name: ns, Types: []string{ns + "_doc"}, Access: acc})
	}
	return out, nil
}
func (s *storeStub) SetNamespaceAccess(_ context.Context, store, ns, role string, canRead, canWrite bool, actor string) error {
	s.actors = append(s.actors, actor)
	if s.namespaces[store] == nil {
		s.namespaces[store] = map[string]map[string][2]bool{}
	}
	if s.namespaces[store][ns] == nil {
		s.namespaces[store][ns] = map[string][2]bool{}
	}
	if !canRead && !canWrite {
		delete(s.namespaces[store][ns], role)
		return nil
	}
	s.namespaces[store][ns][role] = [2]bool{canRead, canWrite}
	return nil
}
func (s *storeStub) RevokeNamespaceAccess(_ context.Context, store, ns, role, actor string) (bool, error) {
	s.actors = append(s.actors, actor)
	_, ok := s.namespaces[store][ns][role]
	delete(s.namespaces[store][ns], role)
	return ok, nil
}
func (s *storeStub) PublishModel(_ context.Context, name, fromStore string, _, _ json.RawMessage, _ string, actor string) (int, error) {
	s.actors = append(s.actors, actor)
	if fromStore != "" {
		if _, ok := s.stores[fromStore]; !ok {
			return 0, fmt.Errorf("%w: store %s not found", authz.ErrInvalidRequest, fromStore)
		}
	}
	s.versions[name] = append(s.versions[name], len(s.versions[name])+1)
	return len(s.versions[name]), nil
}

// TestModel: the fixture and the model remembered, a canned report with
// one failed check — the handler is the scope and the shape, the runner
// is the library's.
type testModelCall struct {
	fix     *pgauthzadm.Fixture
	openfga string
	keep    bool
	actor   string
}

func (s *storeStub) TestModel(_ context.Context, fix *pgauthzadm.Fixture, modelJSON []byte, keep bool, actor string) (*pgauthzadm.RunReport, error) {
	s.actors = append(s.actors, actor)
	s.tests = append(s.tests, testModelCall{fix: fix, openfga: string(modelJSON), keep: keep, actor: actor})
	if fix.Store != "" {
		if _, ok := s.stores[fix.Store]; !ok {
			return nil, fmt.Errorf("%w: store %s not found", authz.ErrInvalidRequest, fix.Store)
		}
	}
	return &pgauthzadm.RunReport{Store: "pgauthzd_test_abc", Failed: 1, Duration: 1500 * time.Millisecond, Results: []pgauthzadm.Result{
		{Name: "alice can_read doc:a = true", Kind: "check", User: "user:alice", Relation: "can_read", Object: "doc:a", Expected: []string{"true"}, Actual: []string{"true"}},
		{Name: "bob can_read doc:a = false", Kind: "check", Failed: true, Detail: "got true", User: "user:bob", Relation: "can_read", Object: "doc:a", Expected: []string{"false"}, Actual: []string{"true"}},
	}}, nil
}

func storesFixture(t *testing.T) (*Handler, *storeStub) {
	t.Helper()
	h, _ := adminFixture(t)
	stub := &storeStub{
		stores:     map[string]*authz.StoreRow{"a_docs": {Name: "a_docs"}, "b_docs": {Name: "b_docs"}, "shared": {Name: "shared"}, "c_docs": {Name: "c_docs"}, "c_other": {Name: "c_other"}},
		versions:   map[string][]int{"core": {1, 2}},
		blocked:    map[string]bool{"b_docs": true},
		recorders:  map[string]map[string][]string{},
		namespaces: map[string]map[string]map[string][2]bool{},
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
	// a requested decision purge on an instance without the postgres sink is
	// refused before anything is deleted (review #27); the retry route too
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/a_mail?purge_decisions=true", "")); w.Code != 501 || stub.stores["a_mail"] == nil {
		t.Fatalf("purge_decisions without a sink must refuse and keep the store: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/a_mail/decisions?store_id=7", "")); w.Code != 501 {
		t.Fatalf("purge route without a sink: %d", w.Code)
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/b_mail/decisions", "")); w.Code != 403 {
		t.Fatalf("purge route outside the scope: %d", w.Code)
	}
	if w := serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/a_mail/deletions", "")); w.Code != 200 || !strings.Contains(w.Body.String(), `"deletions":[]`) {
		t.Fatalf("no receipts before the deletion: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/a_mail?purge_audit=true", "")); w.Code != 200 || !strings.Contains(w.Body.String(), `"purged_audit":true`) || !strings.Contains(w.Body.String(), `"purged_decisions":false`) || !strings.Contains(w.Body.String(), `"store_id":7`) || !strings.Contains(w.Body.String(), `"deleted_at":"2026-10-25T09:00:00Z"`) {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/a_mail/deletions", "")); w.Code != 200 || !strings.Contains(w.Body.String(), `"store_id":7`) || !strings.Contains(w.Body.String(), `"deleted_by":`) {
		t.Fatalf("the receipt after the deletion: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/b_mail/deletions", "")); w.Code != 403 {
		t.Fatalf("receipts outside the scope: %d", w.Code)
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

// Recorder allowlists and namespace grants: set exactly, list, lift; the
// store scope and the name rules apply; the engine's refusals are 400.
func TestAdminRecordersAndNamespaces(t *testing.T) {
	h, stub := storesFixture(t)
	w := serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_docs/recorders/svc_a", `{"actions":["download","pay"]}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"actions":["download","pay"]`) {
		t.Fatalf("set recorder: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_docs/recorders/svc_a", `{"actions":[]}`)); w.Code != 400 {
		t.Fatalf("empty allowlist: %d", w.Code)
	}
	if w := serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_docs/recorders/svc_a", `{"actions":["nope"]}`)); w.Code != 400 {
		t.Fatalf("undeclared action: %d", w.Code)
	}
	if w := serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/b_docs/recorders/svc_a", `{"actions":["download"]}`)); w.Code != 403 {
		t.Fatalf("outside the scope: %d", w.Code)
	}
	if w := serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_docs/recorders/bad-role", `{"actions":["download"]}`)); w.Code != 400 {
		t.Fatalf("bad role name: %d", w.Code)
	}
	w = serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/a_docs/recorders", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"db_role":"svc_a"`) {
		t.Fatalf("list recorders: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/a_docs/recorders/svc_a", "")); w.Code != 200 {
		t.Fatalf("lift: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/a_docs/recorders/svc_a", "")); w.Code != 404 {
		t.Fatalf("lift again: %d", w.Code)
	}

	w = serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_docs/namespaces/hr/access/app_hr", `{"can_read":true,"can_write":true}`))
	if w.Code != 200 || stub.namespaces["a_docs"]["hr"]["app_hr"] != [2]bool{true, true} {
		t.Fatalf("grant: %d %s", w.Code, w.Body.String())
	}
	w = serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_docs/namespaces/hr/access/app_hr", `{"can_read":true}`))
	if w.Code != 200 || stub.namespaces["a_docs"]["hr"]["app_hr"] != [2]bool{true, false} {
		t.Fatalf("narrow to read: %d %+v", w.Code, stub.namespaces["a_docs"]["hr"])
	}
	w = serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/a_docs/namespaces", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"name":"hr"`) || !strings.Contains(w.Body.String(), `"app_hr"`) {
		t.Fatalf("list namespaces: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/stores/a_docs/namespaces/bad%20ns/access/app_hr", `{"can_read":true}`)); w.Code != 400 {
		t.Fatalf("bad namespace: %d", w.Code)
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/a_docs/namespaces/hr/access/app_hr", "")); w.Code != 200 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/a_docs/namespaces/hr/access/app_hr", "")); w.Code != 404 {
		t.Fatalf("revoke again: %d", w.Code)
	}
	for _, a := range stub.actors {
		if a != "user:alice via terraform-a" {
			t.Fatalf("actor: %q", a)
		}
	}
}

// The data-subject routes: rows as JSON and CSV (quoting kept), the export
// passed through, no erasure route; store scope and input validation like
// every other store route.
func TestAdminSubjects(t *testing.T) {
	h, _ := storesFixture(t)
	subjectCalls = nil
	w := serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/a_docs/subjects/user/alice/objects?relations=can_read,can_write&object_types=doc&limit=50", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"object_id":"d1"`) || !strings.Contains(w.Body.String(), `"truncated":true}`) {
		t.Fatalf("objects: %d %s", w.Code, w.Body.String())
	}
	if c := subjectCalls[len(subjectCalls)-1]; c.store != "a_docs" || c.typ != "user" || c.id != "alice" || len(c.relations) != 2 || c.relations[1] != "can_write" || len(c.objectTypes) != 1 || c.limit != 50 {
		t.Fatalf("objects arguments: %+v", c)
	}
	w = serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/a_docs/subjects/user/alice/objects?format=csv", ""))
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") || !strings.Contains(w.Header().Get("Content-Disposition"), "a_docs-user-alice.csv") {
		t.Fatalf("csv headers: %d %v", w.Code, w.Header())
	}
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(lines) != 3 || lines[0] != "store,subject_type,subject_id,object_type,relation,object_id,is_wildcard,direct,truncated" ||
		lines[1] != "a_docs,user,alice,doc,can_read,d1,false,true,false" || lines[2] != `a_docs,user,alice,doc,can_read,"d,2""q",false,false,true` {
		t.Fatalf("csv body: %q", lines)
	}
	if c := subjectCalls[len(subjectCalls)-1]; c.relations != nil || c.objectTypes != nil || c.limit != 10000 {
		t.Fatalf("defaults: %+v", c)
	}
	w = serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores/a_docs/subjects/user/alice", ""))
	if w.Code != 200 || w.Body.String() != `{"subject":"user:alice","direct":[]}` {
		t.Fatalf("export: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantAAdmin.request("DELETE", "/pgauthz/v1/admin/stores/a_docs/subjects/user/alice", "")); w.Code != 404 && w.Code != 405 {
		t.Fatalf("erasure must not be reachable over the API: %d", w.Code)
	}
	for _, bad := range []string{
		"/pgauthz/v1/admin/stores/b_docs/subjects/user/alice/objects", // outside the scope → 403
	} {
		if w := serveAdmin(h, tenantAAdmin.request("GET", bad, "")); w.Code != 403 {
			t.Fatalf("%s: %d", bad, w.Code)
		}
	}
	for _, bad := range []string{
		"/pgauthz/v1/admin/stores/a_docs/subjects/user/*/objects",
		"/pgauthz/v1/admin/stores/a_docs/subjects/bad-type/alice/objects",
		"/pgauthz/v1/admin/stores/a_docs/subjects/user/alice/objects?limit=0",
		"/pgauthz/v1/admin/stores/a_docs/subjects/user/alice/objects?limit=x",
		"/pgauthz/v1/admin/stores/a_missing/subjects/user/alice/objects", // in scope, unknown to the engine → its refusal
	} {
		if w := serveAdmin(h, tenantAAdmin.request("GET", bad, "")); w.Code != 400 {
			t.Fatalf("%s: %d %s", bad, w.Code, w.Body.String())
		}
	}
}

// Model test over the API: the fixture text runs through the backend's
// runner; a fixture bringing its own model needs platform scope and the
// OpenFGA model its model_file resolved to; a fixture naming a live store
// is that store's business (the request's store fills a fixture without a
// model line); failed checks are a 200 with the report; the actor is the
// credential.
func TestAdminTestModel(t *testing.T) {
	h, stub := storesFixture(t)
	const fileFixture = "model_file: model.fga\ntuples:\n  - {user: \"user:alice\", relation: owner, object: \"doc:a\"}\ntests:\n  - name: owner reads\n    check:\n      - {user: \"user:alice\", object: \"doc:a\", assertions: {can_read: true}}\n"
	const storeFixture = "store: a_docs\ntests:\n  - name: owner reads\n    check:\n      - {user: \"user:alice\", object: \"doc:a\", assertions: {can_read: true}}\n"
	const bareFixture = "tests:\n  - name: owner reads\n    check:\n      - {user: \"user:alice\", object: \"doc:a\", assertions: {can_read: true}}\n"
	body := func(v map[string]any) string {
		b, _ := json.Marshal(v)
		return string(b)
	}
	post := func(tk token, v map[string]any) *httptest.ResponseRecorder {
		return serveAdmin(h, tk.request("POST", "/pgauthz/v1/admin/models/test", body(v)))
	}

	// platform scope, model_file + openfga: the report, both checks, the model and actor remembered
	w := post(platformAdmin, map[string]any{"fixture": fileFixture, "openfga": map[string]any{"schema_version": "1.1", "type_definitions": []any{}}})
	if w.Code != 200 {
		t.Fatalf("platform test: %d %s", w.Code, w.Body.String())
	}
	var rep struct {
		Store      string `json:"store"`
		Passed     int    `json:"passed"`
		Failed     int    `json:"failed"`
		DurationMS int    `json:"duration_ms"`
		Results    []struct {
			Name   string `json:"name"`
			Failed bool   `json:"failed"`
			Kind   string `json:"kind"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Store != "pgauthzd_test_abc" || rep.Passed != 1 || rep.Failed != 1 || rep.DurationMS != 1500 || len(rep.Results) != 2 || !rep.Results[1].Failed || rep.Results[0].Kind != "check" {
		t.Fatalf("report: %+v", rep)
	}
	if len(stub.tests) != 1 || stub.tests[0].fix.ModelFile != "model.fga" || !strings.Contains(stub.tests[0].openfga, "type_definitions") || stub.tests[0].keep || stub.tests[0].actor != "user:ops" {
		t.Fatalf("call: %+v", stub.tests)
	}
	// keep_store reaches the runner
	if w := post(platformAdmin, map[string]any{"fixture": fileFixture, "openfga": map[string]any{"schema_version": "1.1"}, "keep_store": true}); w.Code != 200 || !stub.tests[1].keep {
		t.Fatalf("keep_store: %d %s %+v", w.Code, w.Body.String(), stub.tests[1])
	}

	// a model_file fixture without the model is a 400, as is openfga without a model_file
	if w := post(platformAdmin, map[string]any{"fixture": fileFixture}); w.Code != 400 || !strings.Contains(w.Body.String(), "openfga is required") {
		t.Fatalf("missing openfga: %d %s", w.Code, w.Body.String())
	}
	if w := post(platformAdmin, map[string]any{"fixture": storeFixture, "openfga": map[string]any{"schema_version": "1.1"}}); w.Code != 400 || !strings.Contains(w.Body.String(), "only taken with") {
		t.Fatalf("stray openfga: %d %s", w.Code, w.Body.String())
	}
	// no fixture, bad YAML, an unknown field, a store override on a fixture that names its model
	if w := post(platformAdmin, map[string]any{"fixture": "  "}); w.Code != 400 || !strings.Contains(w.Body.String(), "fixture is required") {
		t.Fatalf("empty fixture: %d %s", w.Code, w.Body.String())
	}
	if w := post(platformAdmin, map[string]any{"fixture": "tests: [\n"}); w.Code != 400 || !strings.Contains(w.Body.String(), "fixture:") {
		t.Fatalf("bad yaml: %d %s", w.Code, w.Body.String())
	}
	if w := post(platformAdmin, map[string]any{"fixture": bareFixture}); w.Code != 400 {
		t.Fatalf("no model at all: %d %s", w.Code, w.Body.String())
	}
	if w := post(platformAdmin, map[string]any{"fixture": fileFixture, "openfga": map[string]any{}, "store": "a_docs"}); w.Code != 400 || !strings.Contains(w.Body.String(), "already names its model") {
		t.Fatalf("store on a model_file fixture: %d %s", w.Code, w.Body.String())
	}
	if w := post(platformAdmin, map[string]any{"fixture": fileFixture, "openfga": map[string]any{}, "nope": 1}); w.Code != 400 {
		t.Fatalf("unknown field: %d %s", w.Code, w.Body.String())
	}

	// a tenant admin: its own store's fixture runs (store: in the file, or the request's store on a bare fixture)
	if w := post(tenantAAdmin, map[string]any{"fixture": storeFixture}); w.Code != 200 {
		t.Fatalf("tenant a tests a_docs: %d %s", w.Code, w.Body.String())
	}
	if w := post(tenantAAdmin, map[string]any{"fixture": bareFixture, "store": "a_docs"}); w.Code != 200 || stub.tests[len(stub.tests)-1].fix.Store != "a_docs" {
		t.Fatalf("tenant a tests a_docs via the request: %d %s", w.Code, w.Body.String())
	}
	// not another tenant's store, not a model of its own
	if w := post(tenantAAdmin, map[string]any{"fixture": bareFixture, "store": "b_docs"}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "does not manage store 'b_docs'") {
		t.Fatalf("tenant a tests b_docs: %d %s", w.Code, w.Body.String())
	}
	// a model of its own (model_file, a registry ref) touches no store of anyone's: any admin runs it …
	if w := post(tenantAAdmin, map[string]any{"fixture": fileFixture, "openfga": map[string]any{}}); w.Code != 200 {
		t.Fatalf("tenant a brings a model: %d %s", w.Code, w.Body.String())
	}
	// … but keeping its store commits one outside every binding: platform only
	if w := post(tenantAAdmin, map[string]any{"fixture": fileFixture, "openfga": map[string]any{}, "keep_store": true}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "keep_store") {
		t.Fatalf("tenant a keeps a store: %d %s", w.Code, w.Body.String())
	}

	// the CI credential (admin rule: client ci-a, capabilities [test], stores [a_docs]):
	// tests a_docs and a model of its own, nothing else — not a_other (within the
	// issuer's binding but outside the rule), not keep_store, not any other verb
	if w := post(tenantACI, map[string]any{"fixture": bareFixture, "store": "a_docs"}); w.Code != 200 {
		t.Fatalf("ci-a tests a_docs: %d %s", w.Code, w.Body.String())
	}
	if w := post(tenantACI, map[string]any{"fixture": fileFixture, "openfga": map[string]any{}}); w.Code != 200 {
		t.Fatalf("ci-a tests a model file: %d %s", w.Code, w.Body.String())
	}
	if w := post(tenantACI, map[string]any{"fixture": bareFixture, "store": "a_other"}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "does not manage store 'a_other'") {
		t.Fatalf("ci-a tests a_other: %d %s", w.Code, w.Body.String())
	}
	if w := post(tenantACI, map[string]any{"fixture": bareFixture, "store": "a_docs", "keep_store": true}); w.Code != http.StatusForbidden {
		t.Fatalf("ci-a keeps a store: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantACI.request("GET", "/pgauthz/v1/admin/stores", "")); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "may only test") || !strings.Contains(w.Body.String(), "needs read") {
		t.Fatalf("ci-a lists stores: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantACI.request("PUT", "/pgauthz/v1/admin/stores/a_docs", `{"description":"x"}`)); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "needs manage") {
		t.Fatalf("ci-a upserts a store: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantACI.request("DELETE", "/pgauthz/v1/admin/stores/a_docs", "")); w.Code != http.StatusForbidden {
		t.Fatalf("ci-a deletes a store: %d %s", w.Code, w.Body.String())
	}
	// the terraform-a rule still manages (first rule, manage by default); ci-a's actor label is the credential
	if w := serveAdmin(h, tenantAAdmin.request("GET", "/pgauthz/v1/admin/stores", "")); w.Code != 200 {
		t.Fatalf("terraform-a lists stores: %d %s", w.Code, w.Body.String())
	}
	if last := stub.tests[len(stub.tests)-1]; last.actor != "user:ci via ci-a" {
		t.Fatalf("ci-a actor: %q", last.actor)
	}
	// the engine's refusal (a missing store) is a 400 with its message
	if w := post(platformAdmin, map[string]any{"fixture": bareFixture, "store": "nope"}); w.Code != 400 || !strings.Contains(w.Body.String(), "store nope not found") {
		t.Fatalf("missing store: %d %s", w.Code, w.Body.String())
	}
	// a store name the engine would not take
	if w := post(platformAdmin, map[string]any{"fixture": bareFixture, "store": "a-docs"}); w.Code != 400 {
		t.Fatalf("bad store name: %d %s", w.Code, w.Body.String())
	}
}

// Delegated admin rules: the console store decides. A person becomes
// user:<preferred_username> with their roles and scopes as contextual team
// memberships; a client credentials token service_account:<azp>; each
// admin verb asks for the console relation the console itself checks.
func TestAdminDelegated(t *testing.T) {
	h, stub := storesFixture(t)
	stub.grants = map[string]bool{
		"user:carol can_view store:c_docs":                true,
		"user:carol can_run_tests store:c_docs":           true,
		"user:carol can_rollout store:c_docs":             true,
		"service_account:ci-c can_run_tests store:c_docs": true,
	}
	const bare = "tests:\n  - name: t\n    check:\n      - {user: \"user:a\", object: \"doc:a\", assertions: {can_read: true}}\n"
	const file = "model_file: m.fga\n" + bare
	body := func(v map[string]any) string { b, _ := json.Marshal(v); return string(b) }

	// carol: sees the one store the console grants her, may test and roll out on it, nothing else
	w := serveAdmin(h, tenantCUser.request("GET", "/pgauthz/v1/admin/stores", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "c_docs") || strings.Contains(w.Body.String(), "c_other") || strings.Contains(w.Body.String(), "a_docs") {
		t.Fatalf("carol's stores: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("POST", "/pgauthz/v1/admin/models/test", body(map[string]any{"fixture": bare, "store": "c_docs"}))); w.Code != 200 {
		t.Fatalf("carol tests c_docs: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("PUT", "/pgauthz/v1/admin/stores/c_docs/model", `{"model":"core"}`)); w.Code != 200 {
		t.Fatalf("carol applies on c_docs: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("PUT", "/pgauthz/v1/admin/stores/c_docs", `{"description":"x"}`)); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "does not grant user:carol can_manage_access on store:c_docs") {
		t.Fatalf("carol edits c_docs: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("PUT", "/pgauthz/v1/admin/stores/c_new", `{"description":"x"}`)); w.Code != http.StatusForbidden {
		t.Fatalf("carol creates a store: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("GET", "/pgauthz/v1/admin/models", "")); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "can_view on registry:default") {
		t.Fatalf("carol reads the registry: %d %s", w.Code, w.Body.String())
	}
	// the platform's grants open the rest: creating a store, the registry
	stub.grants["user:carol can_create_store platform:default"] = true
	stub.grants["user:carol can_view registry:default"] = true
	if w := serveAdmin(h, tenantCUser.request("PUT", "/pgauthz/v1/admin/stores/c_new", `{"description":"x"}`)); w.Code != http.StatusCreated {
		t.Fatalf("carol creates a store with can_create_store: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("GET", "/pgauthz/v1/admin/models", "")); w.Code != 200 {
		t.Fatalf("carol reads the registry with can_view: %d %s", w.Code, w.Body.String())
	}
	// her roles and scopes travelled as contextual team memberships
	found := false
	for _, c := range stub.checks {
		if strings.HasPrefix(c, "console user:carol ") && strings.Contains(c, `"object_id":"role_console_admin"`) && strings.Contains(c, `"object_id":"scope_pgauthz:admin"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("contextual memberships: %v", stub.checks)
	}

	// the ci-c client: service_account:ci-c may run fixtures on c_docs — and nothing else
	if w := serveAdmin(h, tenantCCI.request("POST", "/pgauthz/v1/admin/models/test", body(map[string]any{"fixture": bare, "store": "c_docs"}))); w.Code != 200 {
		t.Fatalf("ci-c tests c_docs: %d %s", w.Code, w.Body.String())
	}
	if last := stub.tests[len(stub.tests)-1]; last.actor != "user:ci-uuid via ci-c" {
		t.Fatalf("ci-c actor: %q", last.actor)
	}
	if w := serveAdmin(h, tenantCCI.request("POST", "/pgauthz/v1/admin/models/test", body(map[string]any{"fixture": bare, "store": "c_other"}))); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "does not grant service_account:ci-c can_run_tests on store:c_other") {
		t.Fatalf("ci-c tests c_other: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCCI.request("POST", "/pgauthz/v1/admin/models/test", body(map[string]any{"fixture": file, "openfga": map[string]any{}}))); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "registry:default") {
		t.Fatalf("ci-c tests a model of its own: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCCI.request("POST", "/pgauthz/v1/admin/models/test", body(map[string]any{"fixture": bare, "store": "c_docs", "keep_store": true}))); w.Code != http.StatusForbidden {
		t.Fatalf("ci-c keeps a store: %d %s", w.Code, w.Body.String())
	}
	// the token's scope caps it before the store is even asked: pgauthz:test covers no GET
	if w := serveAdmin(h, tenantCCI.request("GET", "/pgauthz/v1/admin/stores", "")); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "pgauthz:test) do not cover this call; it needs pgauthz:read") {
		t.Fatalf("ci-c lists stores: %d %s", w.Code, w.Body.String())
	}
	// pgauthz:manage: the store writes the store grants, test and read too — nothing platform-level
	stub.grants["user:dave can_manage_access store:c_docs"] = true
	stub.grants["user:dave can_run_tests store:c_docs"] = true
	stub.grants["user:dave can_create_store platform:default"] = true
	stub.grants["user:dave can_publish registry:default"] = true
	if w := serveAdmin(h, tenantCManage.request("PUT", "/pgauthz/v1/admin/stores/c_docs", `{"description":"x"}`)); w.Code != 200 {
		t.Fatalf("dave edits c_docs: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCManage.request("POST", "/pgauthz/v1/admin/models/test", body(map[string]any{"fixture": bare, "store": "c_docs"}))); w.Code != 200 {
		t.Fatalf("dave tests c_docs: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCManage.request("PUT", "/pgauthz/v1/admin/stores/c_brand_new", `{"description":"x"}`)); w.Code != http.StatusForbidden {
		t.Fatalf("dave creates a store without pgauthz:admin: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCManage.request("POST", "/pgauthz/v1/admin/models/core/versions", `{"from_store":"c_docs"}`)); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "needs pgauthz:admin") {
		t.Fatalf("dave publishes without pgauthz:admin: %d %s", w.Code, w.Body.String())
	}
	// the platform itself is admin's, reading included
	if w := serveAdmin(h, tenantCManage.request("GET", "/pgauthz/v1/admin/issuer-bindings", "")); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "needs pgauthz:admin") || strings.Contains(w.Body.String(), "(or pgauthz:admin)") {
		t.Fatalf("dave reads the issuers without pgauthz:admin: %d %s", w.Code, w.Body.String())
	}
	// no pgauthz scope at all: the delegated rule is not satisfied
	if w := serveAdmin(h, tenantCNoScope.request("GET", "/pgauthz/v1/admin/stores", "")); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "carries no pgauthz scope") {
		t.Fatalf("erin without a pgauthz scope: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCCI.request("PUT", "/pgauthz/v1/admin/stores/c_docs", `{"description":"x"}`)); w.Code != http.StatusForbidden {
		t.Fatalf("ci-c edits c_docs: %d %s", w.Code, w.Body.String())
	}
	// a token that satisfies no rule: not the ci client, no preferred_username for the people rule
	if w := serveAdmin(h, tenantCNobody.request("GET", "/pgauthz/v1/admin/stores", "")); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "no preferred_username claim") {
		t.Fatalf("nobody: %d %s", w.Code, w.Body.String())
	}
	// the deciding store unreachable: a refusal that says so, never an allow
	stub.grants["err"] = true
	if w := serveAdmin(h, tenantCUser.request("GET", "/pgauthz/v1/admin/stores/c_docs", "")); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "could not decide") {
		t.Fatalf("store down: %d %s", w.Code, w.Body.String())
	}
}
