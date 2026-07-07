package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

var (
	errSubjectRequired  = errors.New("subject.type and subject.id are required")
	errSubjectForbidden = errors.New("request subject does not match the authenticated subject (body-subject override is disabled)")
)

const defaultPageSize = 100

// Handler wires all AuthZEN endpoints to a backend.
type Handler struct {
	// issuerStores maps a verified issuer to the store patterns (anchored
	// regexes) its tokens may access. Only issuers with a non-empty `stores`
	// list appear here; absent = unrestricted.
	issuerStores map[string][]*regexp.Regexp
	// backend serves the AuthZEN surface (/access/v1): the OPA backend when
	// OPA_URL is set (policy enrichment), else the direct pgx backend.
	backend authz.Backend
	// raw serves the native /pgauthz/v1 READ surface and is ALWAYS a direct pgx
	// backend — never OPA. When not fronting OPA, raw == backend; when fronting
	// OPA it is the separate direct pgx backend, which is what keeps the native
	// raw endpoints policy-free (no re-entry into the OPA policy layer).
	raw authz.Backend
	// rawWrite serves the native /pgauthz/v1 WRITE surface — a WRITER-capable
	// direct pgx backend (set only on a full instance). nil = writes unavailable
	// (decision-only), and the write routes return 501/403.
	rawWrite authz.Backend
	// requireWriterRole gates the native write endpoints behind the WRITER_ROLE
	// claim. Set on the PUBLIC (JWT) router — pgauthzd authorizes writes itself.
	// Left false on the service-token CALLBACK router, which trusts the upstream
	// OPA's asserted X-PGAuthz-Role instead of a JWT role claim.
	requireWriterRole bool
	cfg               *config.Config
	// freshKeys is the freshness-token keyring derived once from
	// cfg.FreshnessKeys: freshKeys[0] mints, every entry verifies (rotation
	// overlap, ADR 0009). Empty = feature disabled.
	freshKeys authz.Keyring
}

func NewHandler(backend, raw, rawWrite authz.Backend, cfg *config.Config) *Handler {
	h := &Handler{backend: backend, raw: raw, rawWrite: rawWrite, cfg: cfg, issuerStores: map[string][]*regexp.Regexp{},
		freshKeys: authz.NewKeyring(cfg.FreshnessKeys)}
	for _, iss := range cfg.Issuers {
		if iss.Issuer == "" || len(iss.Stores) == 0 {
			continue
		}
		pats := make([]*regexp.Regexp, len(iss.Stores))
		for i, p := range iss.Stores {
			// validated in config.Load — anchored so plain names match exactly
			pats[i] = regexp.MustCompile("^(?:" + p + ")$")
		}
		h.issuerStores[iss.Issuer] = pats
	}
	return h
}

// NewRouter returns the main JWT-authed listener: the AuthZEN /access/v1 surface
// (served by `backend` — the OPA sidecar when OPA_URL is set, else direct pgx).
//
// The native /pgauthz/v1 surface (served by `raw`/`rawWrite`, always direct pgx)
// is exposed on the public listener ONLY when this instance is NOT fronting OPA.
// The native path bypasses OPA policy, so when OPA fronts /access/v1 it stays
// off the public listener and lives only on the internal callback listener OPA
// calls back into — a client can't sidestep policy via the raw API. When native
// IS exposed here, pgauthzd authorizes writes itself, so the write routes are
// gated by the WRITER_ROLE claim (requireWriterRole).
func NewRouter(backend, raw, rawWrite authz.Backend, cfg *config.Config, jwtMW *JWTMiddleware) http.Handler {
	h := NewHandler(backend, raw, rawWrite, cfg)
	h.requireWriterRole = true
	return withMiddleware(newPublicMux(h, cfg.UsesOPA()), jwtMW, cfg.HTTPMaxBodyBytes)
}

// newPublicMux wires the PUBLIC listener's route set. Kept as its own function
// so the OpenAPI route-coverage test (openapi_test.go) introspects exactly the
// mux production uses — not a re-declared copy that could drift.
func newPublicMux(h *Handler, usesOPA bool) *http.ServeMux {
	mux := http.NewServeMux()
	registerAuthZEN(mux, h)
	if !usesOPA {
		registerNativeRead(mux, h)
		registerNativeWrite(mux, h)
	}
	mux.HandleFunc("GET /healthz", h.Healthz) // deprecated alias of /readyz
	mux.HandleFunc("GET /livez", h.Livez)
	mux.HandleFunc("GET /readyz", h.Readyz)
	// The API contract, served unauthenticated (exempted in the JWT
	// middleware) and INSTANCE-ACCURATE (an OPA-fronted instance's copy omits
	// the native paths its public listener does not register). OPENAPI_ENABLED
	// (default true) turns the endpoints off entirely.
	if h.cfg.OpenAPIEnabled {
		mux.HandleFunc("GET /pgauthz/v1/openapi.json", h.OpenAPIJSON)
		mux.HandleFunc("GET /pgauthz/v1/openapi.yaml", h.OpenAPIYAML)
	}
	return mux
}

// NewCallbackRouter is the OPA CALLBACK listener: the native surface an OPA
// sidecar calls back into, guarded by a shared SERVICE credential (not the
// end-user JWT) — OPA already authenticated the caller and asserts the subject
// + per-app role. It serves native READS, plus native WRITES when this instance
// is writer-capable (rawWrite != nil), so a read-only instance's callback stays
// structurally read-only. Capability follows the instance's role; reader/writer
// separation is achieved by pointing OPA at different instances. Must not be
// exposed to untrusted callers.
func NewCallbackRouter(h *Handler, serviceToken string) http.Handler {
	mux := http.NewServeMux()
	registerNativeRead(mux, h)
	if h.rawWrite != nil {
		registerNativeWrite(mux, h)
	}
	mux.HandleFunc("GET /healthz", h.Healthz) // deprecated alias of /readyz
	mux.HandleFunc("GET /livez", h.Livez)
	mux.HandleFunc("GET /readyz", h.Readyz)
	var handler http.Handler = mux
	handler = MaxBody(h.cfg.HTTPMaxBodyBytes)(handler)
	handler = ServiceAuthMiddleware(serviceToken)(handler)
	handler = RequestID(handler)
	handler = Logging(handler)
	handler = Recovery(handler)
	return Metrics(mux, handler)
}

func withMiddleware(mux *http.ServeMux, jwtMW *JWTMiddleware, maxBodyBytes int64) http.Handler {
	var handler http.Handler = mux
	handler = MaxBody(maxBodyBytes)(handler)
	handler = jwtMW.Middleware(handler)
	handler = RequestID(handler)
	handler = Logging(handler)
	handler = Recovery(handler)
	return Metrics(mux, handler)
}

// MaxBody caps request bodies via http.MaxBytesReader (review #9): an
// oversized body fails the handler's JSON decode with a clear error instead of
// buffering without bound. n <= 0 disables the cap.
func MaxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// registerAuthZEN wires the spec-compliant AuthZEN surface + tenant discovery.
func registerAuthZEN(mux *http.ServeMux, h *Handler) {
	// Read routes carry the freshness guard (ADR 0009): a no-op unless the caller
	// sends X-PGAuthz-Consistency: at_least_as_fresh + a token.
	eval := h.readGuard(h.Evaluation)
	evals := h.readGuard(h.Evaluations)
	searchSub := h.readGuard(h.SearchSubject)
	searchRes := h.readGuard(h.SearchResource)
	searchAct := h.readGuard(h.SearchAction)

	mux.HandleFunc("POST /access/v1/evaluation", eval)
	mux.HandleFunc("POST /access/v1/evaluations", evals)
	mux.HandleFunc("POST /access/v1/search/subject", searchSub)
	mux.HandleFunc("POST /access/v1/search/resource", searchRes)
	mux.HandleFunc("POST /access/v1/search/action", searchAct)
	mux.HandleFunc("GET /.well-known/authzen-configuration", h.WellKnown)

	// Store-scoped variants (OpenFGA-style): the path segment selects the
	// pgauthz store, so each store presents as its own AuthZEN PDP with its
	// own discovery document. Path beats the store header, which beats
	// DEFAULT_STORE — see store().
	mux.HandleFunc("POST /stores/{store}/access/v1/evaluation", eval)
	mux.HandleFunc("POST /stores/{store}/access/v1/evaluations", evals)
	mux.HandleFunc("POST /stores/{store}/access/v1/search/subject", searchSub)
	mux.HandleFunc("POST /stores/{store}/access/v1/search/resource", searchRes)
	mux.HandleFunc("POST /stores/{store}/access/v1/search/action", searchAct)
	mux.HandleFunc("GET /stores/{store}/.well-known/authzen-configuration", h.WellKnown)
	// AuthZEN 1.0 §9.2 tenant model: the well-known URI is INSERTED between
	// host and the tenant path, so discovery for the PDP identified by
	// .../stores/{store} lives at /.well-known/authzen-configuration/stores/{store}.
	mux.HandleFunc("GET /.well-known/authzen-configuration/stores/{store}", h.WellKnown)
}

// registerNativeRead wires the native raw decision + search + explain/watch
// surface. Policy-free (served by the direct `raw` backend); 501 if raw is not
// a direct backend.
func registerNativeRead(mux *http.ServeMux, h *Handler) {
	// Freshness guard (ADR 0009) on the point-read routes; not on watch (a
	// cursor-based changefeed, not a read-your-writes point query).
	explain := h.readGuard(h.Explain)
	check := h.readGuard(h.NativeCheck)
	checkBatch := h.readGuard(h.NativeCheckBatch)
	listObjects := h.readGuard(h.NativeListObjects)
	listSubjects := h.readGuard(h.NativeListSubjects)
	listActions := h.readGuard(h.NativeListActions)

	mux.HandleFunc("POST /pgauthz/v1/explain", explain)
	mux.HandleFunc("POST /pgauthz/v1/watch", h.Watch)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/explain", explain)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/watch", h.Watch)

	mux.HandleFunc("POST /pgauthz/v1/check", check)
	mux.HandleFunc("POST /pgauthz/v1/check-batch", checkBatch)
	mux.HandleFunc("POST /pgauthz/v1/list-objects", listObjects)
	mux.HandleFunc("POST /pgauthz/v1/list-subjects", listSubjects)
	mux.HandleFunc("POST /pgauthz/v1/list-actions", listActions)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/check", check)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/check-batch", checkBatch)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/list-objects", listObjects)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/list-subjects", listSubjects)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/list-actions", listActions)
}

// registerNativeWrite wires the native write path (full profile only; 403 on
// decision-only, 501 when raw is not a NativeWriter).
func registerNativeWrite(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("POST /pgauthz/v1/write", h.WriteTuples)
	mux.HandleFunc("POST /pgauthz/v1/delete", h.DeleteTuples)
	mux.HandleFunc("POST /pgauthz/v1/delete-user", h.DeleteUserTuples)
	mux.HandleFunc("POST /pgauthz/v1/write-checked", h.WriteTuplesChecked)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/write", h.WriteTuples)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/delete", h.DeleteTuples)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/delete-user", h.DeleteUserTuples)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/write-checked", h.WriteTuplesChecked)
}

// store resolves the pgauthz store for a request: the /stores/{store} path
// segment wins, then the store header (X-PGAuthz-Store), then DEFAULT_STORE.
// NOTE: store selection is caller-controlled — per-store access control (who
// may query which store) is a policy concern; SEARCH_REQUIRED_ROLE gates the
// search endpoints globally, not per store.
// storeChecked resolves the request's store AND enforces the per-issuer store
// binding (Issuer.Stores): tokens from an issuer with a configured store list
// may only access those stores (multi-tenant isolation). Issuers without a
// list — and the legacy unpinned validator — are unrestricted. Writes a 403
// and returns ok=false on a violation.
func (h *Handler) storeChecked(w http.ResponseWriter, r *http.Request) (string, bool) {
	store := h.store(r)
	allowed, restricted := h.issuerStores[IssuerFromContext(r.Context())]
	if !restricted {
		return store, true
	}
	for _, p := range allowed {
		if p.MatchString(store) {
			return store, true
		}
	}
	metrics.AuthzDenied.WithLabelValues("store_binding").Inc()
	writeForbidden(w, "issuer is not allowed to access store '"+store+"'")
	return "", false
}

func (h *Handler) store(r *http.Request) string {
	if s := r.PathValue("store"); s != "" {
		return s
	}
	if s := r.Header.Get(h.cfg.StoreHeader); s != "" {
		return s
	}
	return h.cfg.DefaultStore
}

// resolveSubjectPair applies the subject-override policy to a body-supplied
// subject and the JWT-derived subject.
//
//   - Secure default (AllowSubjectOverride=false): the authenticated JWT
//     subject is authoritative. A body subject is accepted only if it matches
//     the token; a differing one is rejected (errSubjectForbidden) — it would
//     be an impersonation attempt. When no JWT subject is present (e.g. a
//     no-auth/system deployment), the body subject is the only source.
//   - Override (AllowSubjectOverride=true): the trusted-PEP/PDP mode — the
//     body subject wins, with the JWT subject as a fallback.
func (h *Handler) resolveSubjectPair(bodyType, bodyID, jwtType, jwtID string) (subjectType, subjectID string, err error) {
	if h.cfg.AllowSubjectOverride {
		subjectType, subjectID = bodyType, bodyID
		if subjectType == "" {
			subjectType = jwtType
		}
		if subjectID == "" {
			subjectID = jwtID
		}
		if subjectType == "" || subjectID == "" {
			return "", "", errSubjectRequired
		}
		return subjectType, subjectID, nil
	}

	// Secure default: the JWT subject is authoritative when present.
	if jwtType != "" && jwtID != "" {
		if (bodyType != "" && bodyType != jwtType) || (bodyID != "" && bodyID != jwtID) {
			return "", "", errSubjectForbidden
		}
		return jwtType, jwtID, nil
	}

	// No authenticated subject: the body is the only available source.
	if bodyType == "" || bodyID == "" {
		return "", "", errSubjectRequired
	}
	return bodyType, bodyID, nil
}

// resolveSubject resolves the effective subject for single-subject endpoints,
// applying the override policy against the JWT-derived subject.
func (h *Handler) resolveSubject(r *http.Request, body Subject) (subjectType, subjectID string, err error) {
	jwtType, jwtID := SubjectFromContext(r.Context())
	return h.resolveSubjectPair(body.Type, body.ID, jwtType, jwtID)
}

// requireSearchRole gates the reverse-search endpoints: if SearchRequiredRole is
// configured, the caller must hold it (these queries enumerate the access graph).
// Returns false and writes 403 when the caller lacks it; true when allowed or when
// no role is required.
func (h *Handler) requireSearchRole(w http.ResponseWriter, r *http.Request) bool {
	if h.cfg.SearchRequiredRole == "" {
		return true
	}
	for _, role := range RolesFromContext(r.Context()) {
		if role == h.cfg.SearchRequiredRole {
			return true
		}
	}
	metrics.AuthzDenied.WithLabelValues("search_role").Inc()
	writeForbidden(w, "search requires the '"+h.cfg.SearchRequiredRole+"' role")
	return false
}

// requireWriter gates the native write endpoints on the PUBLIC listener: the
// caller must hold the configured WRITER_ROLE. pgauthzd is the write front door
// and authorizes writes itself (no OPA needed). Returns false and writes 403
// when the caller lacks the role. On the service-token CALLBACK listener the
// gate is disabled (requireWriterRole=false) — that path trusts the upstream
// OPA's asserted X-PGAuthz-Role, which pgbackend validates against the DB role.
func (h *Handler) requireWriter(w http.ResponseWriter, r *http.Request) bool {
	if !h.requireWriterRole || h.cfg.WriterRole == "" {
		return true
	}
	for _, role := range RolesFromContext(r.Context()) {
		if role == h.cfg.WriterRole {
			return true
		}
	}
	metrics.AuthzDenied.WithLabelValues("writer_role").Inc()
	writeForbidden(w, "writes require the '"+h.cfg.WriterRole+"' role")
	return false
}

// writeSubjectError maps a subject-resolution error to the right HTTP status:
// 403 for a rejected override attempt, 400 for a missing subject.
func writeSubjectError(w http.ResponseWriter, err error) {
	if errors.Is(err, errSubjectForbidden) {
		metrics.AuthzDenied.WithLabelValues("subject_override").Inc()
		writeForbidden(w, err.Error())
		return
	}
	writeBadRequest(w, err.Error())
}

// Evaluation handles POST /access/v1/evaluation
func (h *Handler) Evaluation(w http.ResponseWriter, r *http.Request) {
	var req EvalRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
		return
	}
	if req.Action.Name == "" {
		writeBadRequest(w, "action.name is required")
		return
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "resource.type and resource.id are required")
		return
	}

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	evalReq := authz.EvalRequest{
		Store:       store,
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Action:      req.Action.Name,
		ObjectType:  req.Resource.Type,
		ObjectID:    req.Resource.ID,
		Context:     req.Context,
	}

	// Opt-in rich result (X-PGAuthz-Detail): backends that support it return
	// state/missing_context/model for the AuthZEN response context field.
	if dc, ok := h.backend.(authz.DetailedChecker); ok && DetailFromContext(r.Context()) {
		decision, detail, err := dc.CheckAccessDetailed(r.Context(), evalReq)
		recordDecisionDetail(store, metrics.APIAuthZEN, detail, err)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, EvalResponseBody{Decision: decision, Context: detail})
		return
	}

	decision, err := h.backend.CheckAccess(r.Context(), evalReq)
	recordDecision(store, metrics.APIAuthZEN, decision, err)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, EvalResponseBody{Decision: decision})
}

// Evaluations handles POST /access/v1/evaluations
func (h *Handler) Evaluations(w http.ResponseWriter, r *http.Request) {
	var req EvalsBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	if len(req.Evaluations) == 0 {
		writeBadRequest(w, "evaluations array is required and must not be empty")
		return
	}

	semantic := req.Semantic
	if semantic == "" {
		semantic = "execute_all"
	}
	switch semantic {
	case "execute_all", "deny_on_first_deny", "permit_on_first_permit":
	default:
		writeBadRequest(w, "invalid semantic: "+semantic)
		return
	}

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	jwtType, jwtID := SubjectFromContext(r.Context())

	// Build individual eval requests, merging shared subject/action/resource
	evals := make([]authz.EvalRequest, len(req.Evaluations))
	for i, e := range req.Evaluations {
		// Effective body subject: per-evaluation, falling back to the
		// batch-level subject. The override policy (vs the JWT subject) is
		// then applied centrally by resolveSubjectPair.
		bodyType := e.Subject.Type
		if bodyType == "" && req.Subject != nil {
			bodyType = req.Subject.Type
		}
		bodyID := e.Subject.ID
		if bodyID == "" && req.Subject != nil {
			bodyID = req.Subject.ID
		}

		subType, subID, serr := h.resolveSubjectPair(bodyType, bodyID, jwtType, jwtID)
		if serr != nil {
			if errors.Is(serr, errSubjectForbidden) {
				writeForbidden(w, fmt.Sprintf("evaluation[%d]: %s", i, serr.Error()))
			} else {
				writeBadRequest(w, fmt.Sprintf("evaluation[%d]: %s", i, serr.Error()))
			}
			return
		}

		action := e.Action.Name
		if action == "" && req.Action != nil {
			action = req.Action.Name
		}
		if action == "" {
			writeBadRequest(w, fmt.Sprintf("evaluation[%d]: action.name is required", i))
			return
		}

		resType := e.Resource.Type
		if resType == "" && req.Resource != nil {
			resType = req.Resource.Type
		}
		resID := e.Resource.ID
		if resID == "" && req.Resource != nil {
			resID = req.Resource.ID
		}
		if resType == "" || resID == "" {
			writeBadRequest(w, fmt.Sprintf("evaluation[%d]: resource.type and resource.id are required", i))
			return
		}

		evals[i] = authz.EvalRequest{
			Store:       store,
			SubjectType: subType,
			SubjectID:   subID,
			Action:      action,
			ObjectType:  resType,
			ObjectID:    resID,
		}
	}

	results, err := h.backend.CheckAccessBatch(r.Context(), store, evals, req.Context, semantic)
	if err != nil {
		// A policy-hook veto (ADR 0011) rejects the whole batch: 403, never a
		// fake all-false result. The structured `denials` disclose hook
		// identities/reasons, so they are returned ONLY when the caller is
		// authorized for detail (X-PGAuthz-Detail) — same rule as allow_detailed;
		// otherwise just the error code.
		var hookErr *authz.PolicyHookDeniedError
		if errors.As(err, &hookErr) {
			body := map[string]any{"status": http.StatusForbidden, "error": "denied_by_policy_hook"}
			if DetailFromContext(r.Context()) {
				body["denials"] = hookErr.Denials
				body["denial_count"] = hookErr.Count // after per-hook caps
				if hookErr.Truncated {
					body["denials_truncated"] = true
					body["denials_dropped"] = hookErr.Dropped
				}
			}
			writeJSON(w, http.StatusForbidden, body)
			return
		}
		writeInternalError(w, err)
		return
	}

	resp := EvalsBatchResponse{Evaluations: make([]EvalResponseBody, len(results))}
	for i, res := range results {
		resp.Evaluations[i] = EvalResponseBody{Decision: res.Decision}
	}

	writeJSON(w, http.StatusOK, resp)
}

// SearchSubject handles POST /access/v1/search/subject
func (h *Handler) SearchSubject(w http.ResponseWriter, r *http.Request) {
	if !h.requireSearchRole(w, r) {
		return
	}
	var req SearchSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	if req.Subject.Type == "" {
		writeBadRequest(w, "subject.type is required for subject search")
		return
	}
	if req.Action.Name == "" {
		writeBadRequest(w, "action.name is required")
		return
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "resource.type and resource.id are required")
		return
	}

	freshTok, ok := h.pageFreshness(w, r, req.Page)
	if !ok {
		return
	}
	page := decodePage(req.Page)

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	subjects, pageResp, err := h.backend.ListSubjects(r.Context(), store,
		req.Subject.Type, req.Action.Name, req.Resource.Type, req.Resource.ID,
		req.Context, page)
	recordSearch(store, "subjects", len(subjects), err)
	if err != nil {
		writeSearchError(w, err)
		return
	}

	resp := SearchSubjectResponse{
		Results: make([]SubjectResult, len(subjects)),
	}
	for i, id := range subjects {
		resp.Results[i] = SubjectResult{Subject: Subject{Type: req.Subject.Type, ID: id}}
	}
	if pageResp != nil && pageResp.HasMore {
		resp.Page = &PageResult{NextToken: bindCursor(pageResp.NextToken, freshTok)}
	}

	writeJSON(w, http.StatusOK, resp)
}

// SearchResource handles POST /access/v1/search/resource
func (h *Handler) SearchResource(w http.ResponseWriter, r *http.Request) {
	if !h.requireSearchRole(w, r) {
		return
	}
	var req SearchResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
		return
	}
	if req.Action.Name == "" {
		writeBadRequest(w, "action.name is required")
		return
	}
	if req.Resource.Type == "" {
		writeBadRequest(w, "resource.type is required")
		return
	}

	freshTok, ok := h.pageFreshness(w, r, req.Page)
	if !ok {
		return
	}
	page := decodePage(req.Page)

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	resources, pageResp, err := h.backend.ListResources(r.Context(), store,
		subjectType, subjectID, req.Action.Name, req.Resource.Type,
		req.Context, page)
	recordSearch(store, "objects", len(resources), err)
	if err != nil {
		writeSearchError(w, err)
		return
	}

	resp := SearchResourceResponse{
		Results: make([]ResourceResult, len(resources)),
	}
	for i, id := range resources {
		resp.Results[i] = ResourceResult{Resource: Resource{Type: req.Resource.Type, ID: id}}
	}
	if pageResp != nil && pageResp.HasMore {
		resp.Page = &PageResult{NextToken: bindCursor(pageResp.NextToken, freshTok)}
	}

	writeJSON(w, http.StatusOK, resp)
}

// SearchAction handles POST /access/v1/search/action
func (h *Handler) SearchAction(w http.ResponseWriter, r *http.Request) {
	if !h.requireSearchRole(w, r) {
		return
	}
	var req SearchActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
		return
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "resource.type and resource.id are required")
		return
	}

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	actions, err := h.backend.ListActions(r.Context(), store,
		subjectType, subjectID, req.Resource.Type, req.Resource.ID,
		req.Context)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	resp := SearchActionResponse{
		Results: make([]ActionResult, len(actions)),
	}
	for i, a := range actions {
		resp.Results[i] = ActionResult{Action: Action{Name: a}}
	}

	writeJSON(w, http.StatusOK, resp)
}

// WellKnown handles GET /.well-known/authzen-configuration
func (h *Handler) WellKnown(w http.ResponseWriter, r *http.Request) {
	base := h.cfg.BaseURL
	if base == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}

	// Store-scoped (tenant) discovery: the PDP identifier and every endpoint
	// carry the /stores/{store} path, so each store presents as its own
	// AuthZEN PDP (AuthZEN 1.0 §9.2 tenant model). The path-insertion
	// discovery URL is /.well-known/authzen-configuration/stores/{store}
	// (see the route); the store is the same PathValue either way.
	if s := r.PathValue("store"); s != "" {
		base += "/stores/" + s
	}

	writeJSON(w, http.StatusOK, WellKnownResponse{
		PolicyDecisionPoint:    base,
		AccessEvaluationEndpt:  base + "/access/v1/evaluation",
		AccessEvaluationsEndpt: base + "/access/v1/evaluations",
		SearchSubjectEndpoint:  base + "/access/v1/search/subject",
		SearchResourceEndpoint: base + "/access/v1/search/resource",
		SearchActionEndpoint:   base + "/access/v1/search/action",
		Capabilities:           []string{"evaluation", "evaluations", "subject-search", "resource-search", "action-search"},
	})
}

// Healthz handles GET /healthz
// Livez — GET /livez: process liveness ONLY, no dependency checks (review #7).
// A PostgreSQL/OPA outage must NOT make Kubernetes restart healthy pgauthzd
// processes in a loop — dependency health is readiness's job (/readyz), which
// takes the instance out of rotation without killing it.
func (h *Handler) Livez(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyzProbeTimeout bounds the readiness backend ping server-side: a
// black-holed dependency must fail the probe promptly, not hang it until the
// kubelet's own timeout (review #9).
const readyzProbeTimeout = 5 * time.Second

// Readyz — GET /readyz: readiness — the backend (PostgreSQL, or OPA on an
// OPA-fronted instance) must be reachable and answering.
func (h *Handler) Readyz(w http.ResponseWriter, r *http.Request) {
	// The callback listener's handler has a nil AuthZEN backend (it only serves
	// the native surface), so fall back to whichever backend is present.
	b := h.backend
	if b == nil {
		b = h.raw
	}
	if b == nil {
		b = h.rawWrite
	}
	if b != nil {
		ctx, cancel := context.WithTimeout(r.Context(), readyzProbeTimeout)
		defer cancel()
		if err := b.Healthz(ctx); err != nil {
			// The probe endpoints are UNAUTHENTICATED — backend error text can
			// carry hostnames/DSN fragments, so the caller gets a generic body
			// (review #8) and the cause goes to the server log only.
			slog.Warn("readiness check failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, "unhealthy")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Healthz — GET /healthz: DEPRECATED alias of /readyz, kept for existing
// deployments/probes. Use /livez for livenessProbe and /readyz for
// readinessProbe.
func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	h.Readyz(w, r)
}

// --- Pagination helpers ---

// pageState is the decoded form of the opaque next_token. A is the keyset
// cursor (last id of the previous page); O is the legacy offset, still decoded
// so tokens minted before the keyset switch keep working.
type pageState struct {
	A string `json:"a,omitempty"`
	O int    `json:"o,omitempty"`
}

func decodePage(p *PageToken) *authz.PageRequest {
	if p == nil {
		return nil
	}
	size := p.Size
	if size <= 0 {
		size = defaultPageSize
	}
	var state pageState
	if p.Token != "" {
		data, err := base64.RawURLEncoding.DecodeString(p.Token)
		if err == nil {
			_ = json.Unmarshal(data, &state)
		}
	}
	return &authz.PageRequest{Limit: size, Offset: state.O, After: state.A}
}

// EncodePage mints a legacy offset cursor. Retained for back-compat; new pages
// use EncodePageAfter (keyset).
func EncodePage(offset int) string {
	data, _ := json.Marshal(pageState{O: offset})
	return base64.RawURLEncoding.EncodeToString(data)
}

// EncodePageAfter mints a keyset cursor carrying the last id of the page.
func EncodePageAfter(after string) string {
	data, _ := json.Marshal(pageState{A: after})
	return base64.RawURLEncoding.EncodeToString(data)
}

// --- JSON helpers ---

// writeRawJSON writes pre-serialized JSON (from the engine) verbatim.
func writeRawJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
