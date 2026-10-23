package api

// The admin API's store and model resources (ADR 0016): the second resource
// family after the issuer bindings, in the same shape — PUT as upsert,
// read-back, tenant scope. A tenant admin (an issuer-scoped admin binding
// or certificate) reaches the stores its issuer is bound to and nothing
// else; the registry (models, versions, rollout) is the fleet's and needs
// platform scope.
//
//   GET    /pgauthz/v1/admin/stores                  the stores in scope, with their model state
//   GET    /pgauthz/v1/admin/stores/{store}
//   PUT    /pgauthz/v1/admin/stores/{store}          {description, docs_url, retired}: create or update, retire
//   DELETE /pgauthz/v1/admin/stores/{store}?purge_audit=true
//   GET    /pgauthz/v1/admin/stores/{store}/model    {definition, status}
//   PUT    /pgauthz/v1/admin/stores/{store}/model    {model: "name[@version]"} apply; ?plan=true dry run; 409 + plan on blockers
//   GET    /pgauthz/v1/admin/models[?name=]          the registry versions
//   POST   /pgauthz/v1/admin/models/{name}/versions  {from_store | definition, description} publish
//   GET    /pgauthz/v1/admin/models/{name}/rollout   every store under the model

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

// StoreAdmin is what the store and model resources need from the backend.
type StoreAdmin interface {
	ListStores(ctx context.Context) ([]authz.StoreRow, error)
	GetStore(ctx context.Context, name string) (authz.StoreRow, bool, error)
	UpsertStore(ctx context.Context, name string, description, docsURL *string, retired *bool, actor string) (authz.StoreRow, bool, error)
	DeleteStore(ctx context.Context, name string, purgeAudit bool, actor string) (bool, error)
	ExportModel(ctx context.Context, store string) (json.RawMessage, error)
	ModelStatus(ctx context.Context, store string) (json.RawMessage, error)
	PlanApply(ctx context.Context, store, name string, version *int) (json.RawMessage, error)
	ApplyModel(ctx context.Context, store, name string, version *int, actor string) (int, error)
	ListModelVersions(ctx context.Context, name string) ([]json.RawMessage, error)
	RolloutStatus(ctx context.Context, name string) ([]json.RawMessage, error)
	PublishModel(ctx context.Context, name, fromStore string, definition, openfga json.RawMessage, description, actor string) (int, error)
	DescribeModel(ctx context.Context, store string) (string, error)
}

var storeNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)
var modelNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func (h *Handler) storeAdmin(w http.ResponseWriter) (StoreAdmin, bool) {
	a, ok := h.rawWrite.(StoreAdmin)
	if !ok {
		writeError(w, http.StatusNotImplemented, "store and model management needs the direct PostgreSQL backend of a full instance")
		return nil, false
	}
	return a, true
}

// requireStoreScope: the gate, then the scope must cover the path's store.
func (h *Handler) requireStoreScope(w http.ResponseWriter, r *http.Request) (adminScope, string, bool) {
	scope, ok := h.requireAdmin(w, r)
	if !ok {
		return scope, "", false
	}
	store := r.PathValue("store")
	if !storeNameRe.MatchString(store) {
		writeBadRequest(w, "store names are [a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters")
		return scope, "", false
	}
	if !scope.coversStore(store) {
		metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
		writeForbidden(w, "management refused: this credential does not manage store '"+store+"' (its issuer's stores binding decides)")
		return scope, "", false
	}
	return scope, store, true
}

// requirePlatform: the registry is the fleet's.
func (h *Handler) requirePlatform(w http.ResponseWriter, r *http.Request) bool {
	scope, ok := h.requireAdmin(w, r)
	if !ok {
		return false
	}
	if !scope.platform {
		metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
		writeForbidden(w, "management refused: the model registry needs platform scope")
		return false
	}
	return true
}

func (h *Handler) adminStores(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	all, err := a.ListStores(r.Context())
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	stores := []authz.StoreRow{}
	for _, s := range all {
		if scope.coversStore(s.Name) {
			stores = append(stores, s)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"stores": stores})
}

func (h *Handler) adminStore(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	row, found, err := a.GetStore(r.Context(), store)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "no store "+store)
		return
	}
	writeJSON(w, http.StatusOK, row)
}

type storeUpsertReq struct {
	Description *string `json:"description"`
	DocsURL     *string `json:"docs_url"`
	Retired     *bool   `json:"retired"`
}

func (h *Handler) adminUpsertStore(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	var req storeUpsertReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	row, created, err := a.UpsertStore(r.Context(), store, req.Description, req.DocsURL, req.Retired, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"store": row, "created": created})
}

func (h *Handler) adminDeleteStore(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	purge := r.URL.Query().Get("purge_audit") == "true"
	existed, err := a.DeleteStore(r.Context(), store, purge, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if !existed {
		writeError(w, http.StatusNotFound, "no store "+store)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "deleted": true, "purged_audit": purge})
}

func (h *Handler) adminStoreModel(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	def, err := a.ExportModel(r.Context(), store)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	st, err := a.ModelStatus(r.Context(), store)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	out := map[string]any{"store": store, "definition": def, "status": st}
	if r.URL.Query().Get("dsl") == "true" {
		text, err := a.DescribeModel(r.Context(), store)
		if err != nil {
			writeDecisionError(w, err)
			return
		}
		out["dsl"] = text
	}
	writeJSON(w, http.StatusOK, out)
}

// parseModelRef: "name" or "name@version".
func parseModelRef(s string) (string, *int, bool) {
	name, v, hasVersion := strings.Cut(strings.TrimSpace(s), "@")
	if !modelNameRe.MatchString(name) {
		return "", nil, false
	}
	if !hasVersion {
		return name, nil, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return "", nil, false
	}
	return name, &n, true
}

type applyModelReq struct {
	Model string `json:"model"`
}

func (h *Handler) adminApplyModel(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	var req applyModelReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	name, version, ok := parseModelRef(req.Model)
	if !ok {
		writeBadRequest(w, `model must be "name" or "name@version"`)
		return
	}
	plan, err := a.PlanApply(r.Context(), store, name, version)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	var verdict struct {
		CanApply bool `json:"can_apply"`
	}
	_ = json.Unmarshal(plan, &verdict)
	if r.URL.Query().Get("plan") == "true" {
		writeJSON(w, http.StatusOK, map[string]any{"store": store, "model": req.Model, "plan": plan, "can_apply": verdict.CanApply})
		return
	}
	if !verdict.CanApply {
		writeJSON(w, http.StatusConflict, map[string]any{"status": http.StatusConflict, "message": "the plan reports blockers; nothing was applied", "store": store, "model": req.Model, "plan": plan, "can_apply": false})
		return
	}
	applied, err := a.ApplyModel(r.Context(), store, name, version, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "model": name, "applied": applied, "plan": plan})
}

func (h *Handler) adminModels(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r) {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name != "" && !modelNameRe.MatchString(name) {
		writeBadRequest(w, "model names are [a-zA-Z_][a-zA-Z0-9_]*")
		return
	}
	versions, err := a.ListModelVersions(r.Context(), name)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

func (h *Handler) adminModelRollout(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r) {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !modelNameRe.MatchString(name) {
		writeBadRequest(w, "model names are [a-zA-Z_][a-zA-Z0-9_]*")
		return
	}
	rows, err := a.RolloutStatus(r.Context(), name)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"model": name, "stores": rows})
}

type publishReq struct {
	FromStore   string          `json:"from_store"`
	Definition  json.RawMessage `json:"definition"`
	OpenFGA     json.RawMessage `json:"openfga"`
	Description string          `json:"description"`
}

func rawSet(j json.RawMessage) bool { return len(j) > 0 && string(j) != "null" }

func (h *Handler) adminPublishModel(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r) {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !modelNameRe.MatchString(name) {
		writeBadRequest(w, "model names are [a-zA-Z_][a-zA-Z0-9_]*")
		return
	}
	var req publishReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	sources := 0
	for _, set := range []bool{req.FromStore != "", rawSet(req.Definition), rawSet(req.OpenFGA)} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		writeBadRequest(w, "exactly one of from_store (a store's live model), definition (the export shape) or openfga (an OpenFGA model, converted on the server) publishes the next version")
		return
	}
	if req.FromStore != "" && !storeNameRe.MatchString(req.FromStore) {
		writeBadRequest(w, "store names are [a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters")
		return
	}
	if !rawSet(req.OpenFGA) {
		req.OpenFGA = nil
	}
	version, err := a.PublishModel(r.Context(), name, req.FromStore, req.Definition, req.OpenFGA, req.Description, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"model": name, "version": version})
}

// registerAdminStores mounts the store and model resources.
func registerAdminStores(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("GET /pgauthz/v1/admin/stores", h.adminStores)
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}", h.adminStore)
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}", h.adminUpsertStore)
	mux.HandleFunc("DELETE /pgauthz/v1/admin/stores/{store}", h.adminDeleteStore)
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/model", h.adminStoreModel)
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}/model", h.adminApplyModel)
	mux.HandleFunc("GET /pgauthz/v1/admin/models", h.adminModels)
	mux.HandleFunc("POST /pgauthz/v1/admin/models/{name}/versions", h.adminPublishModel)
	mux.HandleFunc("GET /pgauthz/v1/admin/models/{name}/rollout", h.adminModelRollout)
}
