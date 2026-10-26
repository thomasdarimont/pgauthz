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
//   POST   /pgauthz/v1/admin/models/test            {fixture, openfga?, store?, keep_store?} run a tests.authz.yaml in an ephemeral store
//   GET    /pgauthz/v1/admin/groups                  the store groups (ADR 0017), platform scope
//   PUT    /pgauthz/v1/admin/groups/{group}          {description}: create (201) or update (200)
//   DELETE /pgauthz/v1/admin/groups/{group}          an empty group; never default
//   PUT    /pgauthz/v1/admin/stores/{store}/group    {group: "name" | ""}: attach, or detach (its own group of one)

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"thomasdarimont.de/authz/pgauthzadm"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

// StoreAdmin is what the store and model resources need from the backend.
type StoreAdmin interface {
	ListStores(ctx context.Context) ([]authz.StoreRow, error)
	GetStore(ctx context.Context, name string) (authz.StoreRow, bool, error)
	UpsertStore(ctx context.Context, name string, description, docsURL *string, retired *bool, actor string) (authz.StoreRow, bool, error)
	// DeleteStore returns the engine's deletion receipt: the incarnation
	// that went and when, read inside the store's lifecycle lock.
	DeleteStore(ctx context.Context, name string, purgeAudit bool, actor string) (storeID int32, deletedAt time.Time, existed bool, err error)
	// StoreDeletions lists the receipts for a name, newest first.
	StoreDeletions(ctx context.Context, name string) ([]authz.StoreDeletion, error)
	// Store groups (ADR 0017): the platform's tenancy — a group is a named
	// set of stores; a store belongs to one or to none.
	ListStoreGroups(ctx context.Context) ([]authz.StoreGroupRow, error)
	UpsertStoreGroup(ctx context.Context, name string, description *string, actor string) (created bool, err error)
	DeleteStoreGroup(ctx context.Context, name, actor string) (bool, error)
	SetStoreGroup(ctx context.Context, store, group, actor string) error
	ExportModel(ctx context.Context, store string) (json.RawMessage, error)
	ModelStatus(ctx context.Context, store string) (json.RawMessage, error)
	PlanApply(ctx context.Context, store, name string, version *int) (json.RawMessage, error)
	ApplyModel(ctx context.Context, store, name string, version *int, actor string) (int, error)
	ListModelVersions(ctx context.Context, name string) ([]json.RawMessage, error)
	RolloutStatus(ctx context.Context, name string) ([]json.RawMessage, error)
	PublishModel(ctx context.Context, name, fromStore string, definition, openfga json.RawMessage, description, actor string) (int, error)
	DescribeModel(ctx context.Context, store string) (string, error)
	// TestModel runs a fixture (pgauthzadm.RunFixture) in an ephemeral store
	// as the actor; modelJSON resolves the fixture's model_file, keep
	// retains the store. The report is the answer even when checks fail.
	TestModel(ctx context.Context, fix *pgauthzadm.Fixture, modelJSON []byte, keep bool, actor string) (*pgauthzadm.RunReport, error)
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
		// the store's refusal is the answer — unless a delegated credential
		// may create a store it does not own yet (the platform's
		// can_create_store, PUT on the store itself)
		refusal := scope.refusal("this credential does not manage store '" + store + "' (its issuer's stores binding, narrowed by its admin rule's stores, decides)")
		creating := scope.decide != nil && (scope.decide.scopes["admin"] || scope.decide.scopes["ci"]) && r.Method == http.MethodPut && r.URL.Path == "/pgauthz/v1/admin/stores/"+store && scope.platformWide()
		if !creating {
			metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
			writeForbidden(w, refusal)
			return scope, "", false
		}
	}
	return scope, store, true
}

// requirePlatform: the registry is the fleet's.
func (h *Handler) requirePlatform(w http.ResponseWriter, r *http.Request) bool {
	scope, ok := h.requireAdmin(w, r)
	if !ok {
		return false
	}
	if !scope.platformWide() {
		metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
		writeForbidden(w, scope.refusal("the model registry needs platform scope"))
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
	storeID, deletedAt, existed, err := a.DeleteStore(r.Context(), store, purge, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if !existed {
		writeError(w, http.StatusNotFound, "no store "+store)
		return
	}
	out := map[string]any{"store": store, "store_id": storeID, "deleted": true, "deleted_at": deletedAt, "purged_audit": purge, "purged_decisions": false}
	if purgeDecisions {
		// the deleted incarnation's lines (a namesake created later is
		// untouched); a failure answers 502 `partial`, and
		// DELETE …/stores/{store}/decisions?store_id= retries it from the receipt
		n, err := sink.PurgeStore(r.Context(), store, storeID, actorLabel(r), deletedAt)
		if err != nil {
			out["partial"] = true
			out["error"] = fmt.Sprintf("the store is deleted but its decision-log lines could not be: retry with DELETE /pgauthz/v1/admin/stores/%s/decisions?store_id=%d: %v", store, storeID, err)
			writeJSON(w, http.StatusBadGateway, out)
			return
		}
		out["purged_decisions"] = true
		out["decisions"] = n
	}
	writeJSON(w, http.StatusOK, out)
}

// adminPurgeStoreDecisions — DELETE /pgauthz/v1/admin/stores/{store}/decisions?store_id=:
// the decision log's lines of one DELETED incarnation of a store, behind the
// store fence — the retry of a deletion whose purge failed. The incarnation
// must have the engine's deletion receipt (the deletion's answer and
// GET …/deletions carry it): a live store cannot be fenced by mistake, and
// the receipt's deletion time bounds the lines without an id. Needs the
// postgres sink; idempotent.
func (h *Handler) adminPurgeStoreDecisions(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	n64, err := strconv.ParseInt(r.URL.Query().Get("store_id"), 10, 32)
	if err != nil || n64 <= 0 {
		writeBadRequest(w, "store_id is required: the deleted incarnation, from the deletion's answer or GET …/stores/{store}/deletions")
		return
	}
	storeID := int32(n64)
	sink := h.decisionSink()
	if sink == nil {
		writeError(w, http.StatusNotImplemented, "this instance writes no postgres decision-log sink (DECISION_LOG=postgres)")
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	receipts, err := a.StoreDeletions(r.Context(), store)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	var receipt *authz.StoreDeletion
	for i := range receipts {
		if receipts[i].StoreID == storeID {
			receipt = &receipts[i]
		}
	}
	if receipt == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no deletion receipt for incarnation %d of store %s (GET …/stores/%s/deletions lists them)", storeID, store, store))
		return
	}
	n, err := sink.PurgeStore(r.Context(), store, storeID, actorLabel(r), receipt.DeletedAt)
	if err != nil {
		writeError(w, http.StatusBadGateway, "decision log: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "store_id": storeID, "purged_decisions": true, "deleted_at": receipt.DeletedAt, "decisions": n})
}

// adminStoreDeletions — GET /pgauthz/v1/admin/stores/{store}/deletions: the
// engine's deletion receipts for the name, newest first.
func (h *Handler) adminStoreDeletions(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	rows, err := a.StoreDeletions(r.Context(), store)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if rows == nil {
		rows = []authz.StoreDeletion{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "deletions": rows})
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

// ── store groups (ADR 0017): the platform's tenancy ──────────────────────

func (h *Handler) adminGroups(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r) {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	groups, err := a.ListStoreGroups(r.Context())
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

type groupUpsertReq struct {
	Description *string `json:"description"`
}

func (h *Handler) adminUpsertGroup(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r) {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	name := r.PathValue("group")
	if !storeNameRe.MatchString(name) {
		writeBadRequest(w, "store group names are [a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters")
		return
	}
	var req groupUpsertReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	created, err := a.UpsertStoreGroup(r.Context(), name, req.Description, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"group": name, "created": created})
}

func (h *Handler) adminDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r) {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	name := r.PathValue("group")
	if !storeNameRe.MatchString(name) {
		writeBadRequest(w, "store group names are [a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters")
		return
	}
	deleted, err := a.DeleteStoreGroup(r.Context(), name, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "no store group "+name)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": name, "deleted": true})
}

type setGroupReq struct {
	Group string `json:"group"`
}

// adminSetStoreGroup: moving a store between groups is the platform's —
// it changes who administers the store and which issuers reach it.
func (h *Handler) adminSetStoreGroup(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r) {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	store := r.PathValue("store")
	if !storeNameRe.MatchString(store) {
		writeBadRequest(w, "store names are [a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters")
		return
	}
	var req setGroupReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if req.Group != "" && !storeNameRe.MatchString(req.Group) {
		writeBadRequest(w, "store group names are [a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters (empty detaches)")
		return
	}
	if err := a.SetStoreGroup(r.Context(), store, req.Group, actorLabel(r)); err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "group": req.Group})
}

// ── model test: a fixture run in an ephemeral store ──────────────────────

// testModelReq is a tests.authz.yaml plus what the file could not carry:
// the OpenFGA model its model_file resolved to (the client parses a .fga),
// a live store to test when the fixture names no model, keep_store.
type testModelReq struct {
	Fixture   string          `json:"fixture"`
	OpenFGA   json.RawMessage `json:"openfga"`
	Store     string          `json:"store"`
	KeepStore bool            `json:"keep_store"`
}

// adminTestModel: POST /pgauthz/v1/admin/models/test — what `pgauthzctl
// model test --server` and a CI job with a token call; the `test`
// capability (requireAdmin). A fixture naming a live store (`store:` or
// the request's store) is that store's business: a credential whose scope
// covers the store may test it. A fixture bringing its own model
// (model_file, a registry ref) touches no store of anyone's — the
// ephemeral store lives and dies inside the transaction — so any admin
// credential may run it; keep_store, which commits that store, needs
// platform scope. Failed checks are a 200 with the report, not an error.
func (h *Handler) adminTestModel(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	var req testModelReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Fixture) == "" {
		writeBadRequest(w, "fixture is required: the tests.authz.yaml text")
		return
	}
	var fix pgauthzadm.Fixture
	if err := pgauthzadm.UnmarshalFixture([]byte(req.Fixture), &fix); err != nil {
		writeBadRequest(w, "fixture: "+err.Error())
		return
	}
	if req.Store != "" {
		if fix.ModelFile != "" || fix.Model != "" {
			writeBadRequest(w, "store: the fixture already names its model (model_file / model)")
			return
		}
		fix.Store = req.Store
	}
	if err := fix.Validate(); err != nil {
		writeBadRequest(w, "fixture: "+err.Error())
		return
	}
	if !rawSet(req.OpenFGA) {
		req.OpenFGA = nil
	}
	if fix.ModelFile != "" && req.OpenFGA == nil {
		writeBadRequest(w, "openfga is required when the fixture names a model_file: the OpenFGA model the file parses to (the server cannot read the client's files)")
		return
	}
	if fix.ModelFile == "" && req.OpenFGA != nil {
		writeBadRequest(w, "openfga is only taken with a fixture that names a model_file")
		return
	}
	switch {
	case fix.Store != "":
		if !storeNameRe.MatchString(fix.Store) {
			writeBadRequest(w, "store names are [a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters")
			return
		}
		if !scope.coversStore(fix.Store) {
			metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
			writeForbidden(w, scope.refusal("this credential does not manage store '"+fix.Store+"' (its issuer's stores binding, narrowed by its admin rule's stores, decides)"))
			return
		}
	case scope.decide != nil && !scope.platformWide():
		// a model of its own, decided by the console store: reading the registry
		metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
		writeForbidden(w, scope.refusal("a fixture with a model of its own needs the registry"))
		return
	}
	keepAllowed := scope.platform
	if scope.decide != nil {
		keepAllowed = (scope.decide.scopes["admin"] || scope.decide.scopes["ci"]) && scope.decide.allowed("can_create_store", "platform", "default")
	}
	if req.KeepStore && !keepAllowed {
		metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
		writeForbidden(w, scope.refusal("keep_store commits a store outside every issuer binding; it needs platform scope"))
		return
	}
	report, err := a.TestModel(r.Context(), &fix, req.OpenFGA, req.KeepStore, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	results := report.Results
	if results == nil {
		results = []pgauthzadm.Result{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"store":       report.Store,
		"passed":      len(report.Results) - report.Failed,
		"failed":      report.Failed,
		"results":     results,
		"duration_ms": report.Duration.Milliseconds(),
	})
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
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/deletions", h.adminStoreDeletions)
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/model", h.adminStoreModel)
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}/model", h.adminApplyModel)
	mux.HandleFunc("GET /pgauthz/v1/admin/groups", h.adminGroups)
	mux.HandleFunc("PUT /pgauthz/v1/admin/groups/{group}", h.adminUpsertGroup)
	mux.HandleFunc("DELETE /pgauthz/v1/admin/groups/{group}", h.adminDeleteGroup)
	mux.HandleFunc("PUT /pgauthz/v1/admin/stores/{store}/group", h.adminSetStoreGroup)
	mux.HandleFunc("GET /pgauthz/v1/admin/models", h.adminModels)
	mux.HandleFunc("POST /pgauthz/v1/admin/models/test", h.adminTestModel)
	mux.HandleFunc("POST /pgauthz/v1/admin/models/{name}/versions", h.adminPublishModel)
	mux.HandleFunc("GET /pgauthz/v1/admin/models/{name}/rollout", h.adminModelRollout)
}
