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
	RecorderActions(ctx context.Context, store string) ([]authz.RecorderRow, error)
	SetRecorderActions(ctx context.Context, store, role string, actions []string, actor string) error
	RevokeRecorderActions(ctx context.Context, store, role, actor string) (bool, error)
	Namespaces(ctx context.Context, store string) ([]authz.NamespaceRow, error)
	SetNamespaceAccess(ctx context.Context, store, namespace, role string, canRead, canWrite bool, actor string) error
	RevokeNamespaceAccess(ctx context.Context, store, namespace, role, actor string) (bool, error)
	// Data subject requests (PRODUCTION.md → Data subject requests): the
	// takeout and the export. No erasure over the API (see admin_subjects.go).
	SubjectObjects(ctx context.Context, store, subjectType, subjectID string, relations, objectTypes []string, limit int) ([]authz.SubjectObjectRow, error)
	ExportSubject(ctx context.Context, store, subjectType, subjectID string, relations []string, limit int) (json.RawMessage, error)
}

var roleNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)
var namespaceRe = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,62}$`)

var storeNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)
var modelNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func (h *Handler) storeAdmin(w http.ResponseWriter) (StoreAdmin, bool) {
	a, ok := h.adminBackend().(StoreAdmin)
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
	purgeDecisions := r.URL.Query().Get("purge_decisions") == "true"
	// The decision log's lines go only when asked (like the audit history, a
	// record of what was decided may have to outlive the store), and only
	// from the postgres sink this instance writes — asked for without one,
	// the whole request is refused BEFORE anything is deleted (review #27:
	// a requested purge is never reported done without running).
	sink := h.decisionSink()
	if purgeDecisions && sink == nil {
		writeError(w, http.StatusNotImplemented, "purge_decisions: this instance writes no postgres decision-log sink (DECISION_LOG=postgres); delete without it, or purge from the console or an instance that does")
		return
	}
	existed, err := a.DeleteStore(r.Context(), store, purge, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if !existed {
		writeError(w, http.StatusNotFound, "no store "+store)
		return
	}
	out := map[string]any{"store": store, "deleted": true, "purged_audit": purge, "purged_decisions": false}
	if purgeDecisions {
		// behind the store fence (PurgeStore). The engine part is done
		// either way: a sink failure answers 502 `partial`, and
		// DELETE …/stores/{store}/decisions retries the purge alone — the
		// store itself is gone by then.
		n, err := sink.PurgeStore(r.Context(), store, actorLabel(r))
		if err != nil {
			out["partial"] = true
			out["error"] = "the store is deleted but its decision-log lines could not be: retry with DELETE /pgauthz/v1/admin/stores/" + store + "/decisions: " + err.Error()
			writeJSON(w, http.StatusBadGateway, out)
			return
		}
		out["purged_decisions"] = true
		out["decisions"] = n
	}
	writeJSON(w, http.StatusOK, out)
}

// adminPurgeStoreDecisions — DELETE /pgauthz/v1/admin/stores/{store}/decisions:
// the decision log's lines and tombstones of a store, behind the store
// fence, whether or not the store still exists in the engine — the retry
// of a store deletion whose purge failed, or a purge decided later. Needs
// the postgres sink on this instance; idempotent.
func (h *Handler) adminPurgeStoreDecisions(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	sink := h.decisionSink()
	if sink == nil {
		writeError(w, http.StatusNotImplemented, "this instance writes no postgres decision-log sink (DECISION_LOG=postgres)")
		return
	}
	n, err := sink.PurgeStore(r.Context(), store, actorLabel(r))
	if err != nil {
		writeError(w, http.StatusBadGateway, "decision log: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "purged_decisions": true, "decisions": n})
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

// ── recorder allowlists: who may record which actions (ADR 0012) ─────────

func (h *Handler) adminRecorders(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	rows, err := a.RecorderActions(r.Context(), store)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "recorders": rows})
}

func (h *Handler) adminSetRecorder(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	role := r.PathValue("role")
	if !roleNameRe.MatchString(role) {
		writeBadRequest(w, "db roles are [a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters")
		return
	}
	var req struct {
		Actions []string `json:"actions"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if len(req.Actions) == 0 {
		writeBadRequest(w, "actions must name at least one declared relation (DELETE lifts the allowlist)")
		return
	}
	if err := a.SetRecorderActions(r.Context(), store, role, req.Actions, actorLabel(r)); err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "db_role": role, "actions": req.Actions})
}

func (h *Handler) adminDeleteRecorder(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	role := r.PathValue("role")
	existed, err := a.RevokeRecorderActions(r.Context(), store, role, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if !existed {
		writeError(w, http.StatusNotFound, "no allowlist for "+role+" in store "+store)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "db_role": role, "deleted": true})
}

// ── namespaces: per-application slices and their role grants ────────────

func (h *Handler) adminNamespaces(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	rows, err := a.Namespaces(r.Context(), store)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "namespaces": rows})
}

func (h *Handler) namespaceAndRole(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	ns, role := r.PathValue("ns"), r.PathValue("role")
	if !namespaceRe.MatchString(ns) {
		writeBadRequest(w, "namespaces are [a-zA-Z0-9_][a-zA-Z0-9_.-]*, at most 63 characters")
		return "", "", false
	}
	if !roleNameRe.MatchString(role) {
		writeBadRequest(w, "db roles are [a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters")
		return "", "", false
	}
	return ns, role, true
}

func (h *Handler) adminSetNamespaceAccess(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	ns, role, ok := h.namespaceAndRole(w, r)
	if !ok {
		return
	}
	var req struct {
		CanRead  bool `json:"can_read"`
		CanWrite bool `json:"can_write"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if err := a.SetNamespaceAccess(r.Context(), store, ns, role, req.CanRead, req.CanWrite, actorLabel(r)); err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "namespace": ns, "db_role": role, "can_read": req.CanRead, "can_write": req.CanWrite})
}

func (h *Handler) adminDeleteNamespaceAccess(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	ns, role, ok := h.namespaceAndRole(w, r)
	if !ok {
		return
	}
	existed, err := a.RevokeNamespaceAccess(r.Context(), store, ns, role, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if !existed {
		writeError(w, http.StatusNotFound, "no grant for "+role+" on namespace "+ns+" in store "+store)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "namespace": ns, "db_role": role, "deleted": true})
}

// registerAdminStores mounts the store and model resources.
func registerAdminStores(mux *http.ServeMux, h *Handler) {
	registerAdminSubjects(mux, h)
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/recorders", h.adminRecorders)
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}/recorders/{role}", h.adminSetRecorder)
	mux.HandleFunc("DELETE /pgauthz/v1/admin/stores/{store}/recorders/{role}", h.adminDeleteRecorder)
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/namespaces", h.adminNamespaces)
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}/namespaces/{ns}/access/{role}", h.adminSetNamespaceAccess)
	mux.HandleFunc("DELETE /pgauthz/v1/admin/stores/{store}/namespaces/{ns}/access/{role}", h.adminDeleteNamespaceAccess)
	mux.HandleFunc("GET /pgauthz/v1/admin/stores", h.adminStores)
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}", h.adminStore)
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}", h.adminUpsertStore)
	mux.HandleFunc("DELETE /pgauthz/v1/admin/stores/{store}", h.adminDeleteStore)
	mux.HandleFunc("DELETE /pgauthz/v1/admin/stores/{store}/decisions", h.adminPurgeStoreDecisions)
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/model", h.adminStoreModel)
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}/model", h.adminApplyModel)
	mux.HandleFunc("GET /pgauthz/v1/admin/models", h.adminModels)
	mux.HandleFunc("POST /pgauthz/v1/admin/models/{name}/versions", h.adminPublishModel)
	mux.HandleFunc("GET /pgauthz/v1/admin/models/{name}/rollout", h.adminModelRollout)
}
