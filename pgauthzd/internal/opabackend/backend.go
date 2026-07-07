package opabackend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/api"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

// Backend implements authz.Backend by calling OPA HTTP endpoints.
type Backend struct {
	baseURL      string
	pkg          string // e.g. "authz"
	client       *http.Client
	forwardToken bool // add the verified bearer token to OPA input as input.token
	// deepReadinessRequired: fail readiness when the policy set lacks the
	// callback_healthy rule (OPA_DEEP_READINESS_REQUIRED, review #9).
	deepReadinessRequired bool
	// deploymentEnv is forwarded to policy hooks as input.deployment.environment
	// (server-derived; ADR 0011).
	deploymentEnv string
	// evalMetrics adds ?metrics=true to record OPA's Rego eval time.
	evalMetrics bool
}

// New builds an OPA backend. timeout bounds EVERY OPA HTTP call — Go's zero
// client timeout is unlimited, so a black-holed OPA would otherwise hang
// requests and startup (review #9); <=0 falls back to 10s rather than
// unlimited (fail bounded). deepReadinessRequired makes a policy set WITHOUT
// the callback_healthy rule fail readiness instead of degrading to the
// shallow OPA-/health-only check.
func New(baseURL, pkg string, forwardToken bool, timeout time.Duration, deepReadinessRequired bool, deploymentEnv string, evalMetrics bool) *Backend {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Backend{
		baseURL:               strings.TrimRight(baseURL, "/"),
		pkg:                   pkg,
		client:                &http.Client{Timeout: timeout},
		forwardToken:          forwardToken,
		deepReadinessRequired: deepReadinessRequired,
		deploymentEnv:         deploymentEnv,
		evalMetrics:           evalMetrics,
	}
}

func (b *Backend) CheckAccess(ctx context.Context, req authz.EvalRequest) (bool, error) {
	input := map[string]any{
		"subject": map[string]string{
			"type": req.SubjectType,
			"id":   req.SubjectID,
		},
		"action": req.Action,
		"resource": map[string]string{
			"type": req.ObjectType,
			"id":   req.ObjectID,
		},
	}
	if req.Store != "" {
		input["store"] = req.Store
	}
	if req.Context != nil {
		input["context"] = req.Context
	}

	var result bool
	err := b.query(ctx, "allow", input, &result)
	return result, err
}

// CheckAccessDetailed implements authz.DetailedChecker by querying the OPA
// `allow_detailed` rule (data.authz.allow_detailed), which forwards to the
// engine's check_access_detailed and returns the full report.
func (b *Backend) CheckAccessDetailed(ctx context.Context, req authz.EvalRequest) (bool, map[string]any, error) {
	input := map[string]any{
		"subject": map[string]string{
			"type": req.SubjectType,
			"id":   req.SubjectID,
		},
		"action": req.Action,
		"resource": map[string]string{
			"type": req.ObjectType,
			"id":   req.ObjectID,
		},
	}
	if req.Store != "" {
		input["store"] = req.Store
	}
	if req.Context != nil {
		input["context"] = req.Context
	}

	var report map[string]any
	if err := b.query(ctx, "allow_detailed", input, &report); err != nil {
		return false, nil, err
	}
	decision, _ := report["decision"].(bool)
	delete(report, "decision")
	delete(report, "store")
	return decision, report, nil
}

func (b *Backend) CheckAccessBatch(ctx context.Context, store string, reqs []authz.EvalRequest,
	globalContext map[string]any, semantic string) ([]authz.EvalResult, error) {

	evals := make([]map[string]any, len(reqs))
	for i, req := range reqs {
		eval := map[string]any{
			"subject": map[string]string{
				"type": req.SubjectType,
				"id":   req.SubjectID,
			},
			"action": req.Action,
			"resource": map[string]string{
				"type": req.ObjectType,
				"id":   req.ObjectID,
			},
		}
		evals[i] = eval
	}

	input := map[string]any{
		"evaluations": evals,
	}
	if store != "" {
		input["store"] = store
	}
	if semantic != "" && semantic != "execute_all" {
		input["semantic"] = semantic
		// OPA policy requires input.context to be defined when input.semantic
		// is set (line 160-168 of policy.rego), so always include it.
		if globalContext != nil {
			input["context"] = globalContext
		} else {
			input["context"] = map[string]any{}
		}
	} else if globalContext != nil {
		input["context"] = globalContext
	}

	var raw json.RawMessage
	if err := b.query(ctx, "evaluations", input, &raw); err != nil {
		return nil, err
	}
	// A policy-hook veto rejects the WHOLE batch with a structured error object
	// (ADR 0011) — never a misleading all-false array. Surface it typed so the
	// handler can map it to 403 with the denials.
	var rejection struct {
		Error     string           `json:"error"`
		Denials   []map[string]any `json:"denials"`
		Count     int              `json:"denial_count"`
		Truncated bool             `json:"denials_truncated"`
		Dropped   int              `json:"denials_dropped"`
	}
	if err := json.Unmarshal(raw, &rejection); err == nil && rejection.Error == "denied_by_policy_hook" {
		count := rejection.Count
		if count == 0 {
			count = len(rejection.Denials)
		}
		return nil, &authz.PolicyHookDeniedError{Denials: rejection.Denials, Count: count, Truncated: rejection.Truncated, Dropped: rejection.Dropped}
	}
	var results []struct {
		Decision bool `json:"decision"`
	}
	if err := json.Unmarshal(raw, &results); err != nil {
		return nil, fmt.Errorf("unexpected evaluations result shape: %w", err)
	}

	out := make([]authz.EvalResult, len(results))
	for i, r := range results {
		out[i] = authz.EvalResult{Decision: r.Decision}
	}
	return out, nil
}

// filteredPage is the paginated-search protocol object returned when
// hook-FILTERED enumeration is active (ADR 0011): ids are post-filter, but
// has_more and the keyset cursor are derived from the RAW page, so pagination
// traverses the full raw keyset space and never terminates early just because
// a page filtered below the client limit.
type filteredPage struct {
	HookFiltered bool     `json:"hook_filtered"`
	IDs          []string `json:"ids"`
	HasMore      bool     `json:"has_more"`
	Cursor       string   `json:"cursor"`
}

// decodeIDs unmarshals a search-rule result: an ID array, the filtered-page
// protocol object, or an enumeration-refusal object. The returned *filteredPage
// is non-nil only for the protocol shape.
func decodeIDs(raw json.RawMessage) ([]string, *filteredPage, error) {
	var refusal struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &refusal); err == nil {
		switch refusal.Error {
		case "enumeration_refused_with_hooks":
			return nil, nil, authz.ErrEnumerationRefused
		case "enumeration_refused_too_many_candidates":
			return nil, nil, authz.ErrEnumerationCapExceeded
		}
	}
	var fp filteredPage
	if err := json.Unmarshal(raw, &fp); err == nil && fp.HookFiltered {
		if fp.IDs == nil {
			fp.IDs = []string{}
		}
		return fp.IDs, &fp, nil
	}
	var ids []string
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &ids); err != nil {
			return nil, nil, fmt.Errorf("unexpected search result shape: %w", err)
		}
	}
	return ids, nil, nil
}

// pageFromFiltered maps the protocol object to the page response. The cursor
// is the last RAW consumed id — possibly one the hooks removed from the
// results — so it is SEALED (AES-GCM): opaque and integrity-protected, no
// existence leak through pagination metadata.
func pageFromFiltered(fp *filteredPage, aad string) *authz.PageResponse {
	if !fp.HasMore {
		return nil
	}
	tok := api.EncodeSealedPageAfter(fp.Cursor, aad)
	if tok == "" {
		return nil // no usable cipher: end pagination rather than leak
	}
	return &authz.PageResponse{HasMore: true, NextToken: tok}
}

func (b *Backend) ListResources(ctx context.Context, store string,
	subjectType, subjectID, action, objectType string,
	reqContext map[string]any, page *authz.PageRequest) ([]string, *authz.PageResponse, error) {

	input := map[string]any{
		"subject": map[string]string{
			"type": subjectType,
			"id":   subjectID,
		},
		"action":   action,
		"resource": map[string]string{"type": objectType},
	}
	if store != "" {
		input["store"] = store
	}
	if reqContext != nil {
		input["context"] = reqContext
	}

	if page != nil {
		input["page"] = pageInput(page)

		var raw json.RawMessage
		if err := b.query(ctx, "accessible_objects_page", input, &raw); err != nil {
			return nil, nil, err
		}
		ids, fp, err := decodeIDs(raw)
		if err != nil {
			return nil, nil, err
		}
		if fp != nil {
			_, actorID := api.SubjectFromContext(ctx)
			return ids, pageFromFiltered(fp, api.SealedCursorAAD("objects", store, actorID,
				subjectType, subjectID, action, objectType, "",
				api.CanonicalContextHash(reqContext))), nil
		}

		return buildPage(ids, page.Limit)
	}

	// Unpaginated — returns a set from OPA
	var raw json.RawMessage
	if err := b.query(ctx, "accessible_objects", input, &raw); err != nil {
		return nil, nil, err
	}
	ids, _, err := decodeIDs(raw)
	if err != nil {
		return nil, nil, err
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, nil, nil
}

func (b *Backend) ListSubjects(ctx context.Context, store string,
	subjectType, action, objectType, objectID string,
	reqContext map[string]any, page *authz.PageRequest) ([]string, *authz.PageResponse, error) {

	input := map[string]any{
		"subject_type": subjectType,
		"action":       action,
		"resource": map[string]string{
			"type": objectType,
			"id":   objectID,
		},
	}
	if store != "" {
		input["store"] = store
	}
	if reqContext != nil {
		input["context"] = reqContext
	}

	if page != nil {
		input["page"] = pageInput(page)

		var raw json.RawMessage
		if err := b.query(ctx, "accessible_subjects_page", input, &raw); err != nil {
			return nil, nil, err
		}
		ids, fp, err := decodeIDs(raw)
		if err != nil {
			return nil, nil, err
		}
		if fp != nil {
			_, actorID := api.SubjectFromContext(ctx)
			return ids, pageFromFiltered(fp, api.SealedCursorAAD("subjects", store, actorID,
				subjectType, "", action, objectType, objectID,
				api.CanonicalContextHash(reqContext))), nil
		}

		return buildPage(ids, page.Limit)
	}

	var raw json.RawMessage
	if err := b.query(ctx, "accessible_subjects", input, &raw); err != nil {
		return nil, nil, err
	}
	ids, _, err := decodeIDs(raw)
	if err != nil {
		return nil, nil, err
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, nil, nil
}

func (b *Backend) ListActions(ctx context.Context, store string,
	subjectType, subjectID, objectType, objectID string,
	reqContext map[string]any) ([]string, error) {

	input := map[string]any{
		"subject": map[string]string{
			"type": subjectType,
			"id":   subjectID,
		},
		"resource": map[string]string{
			"type": objectType,
			"id":   objectID,
		},
	}
	if store != "" {
		input["store"] = store
	}
	if reqContext != nil {
		input["context"] = reqContext
	}

	var actions []string
	if err := b.query(ctx, "permitted_actions", input, &actions); err != nil {
		return nil, err
	}
	if actions == nil {
		actions = []string{}
	}
	return actions, nil
}

func (b *Backend) Healthz(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", b.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OPA health check returned %d", resp.StatusCode)
	}
	// OPA's own /health proves only that OPA runs — not that a decision can
	// succeed (review #8). The pgauthz client policy exposes a deep-readiness
	// rule, data.pgauthz.callback_healthy, whose evaluation exercises the WHOLE
	// path: OPA policy eval → native callback listener → PostgreSQL. Fail
	// readiness when it reports false; a policy set without the rule (custom
	// Rego) degrades to the shallow check above.
	return b.callbackHealthy(ctx)
}

// callbackHealthy queries data.authz.pgauthz.callback_healthy (a bare boolean;
// the rule is defined in opa/policies/pgauthz.rego — package authz.pgauthz —
// and allowlisted in system_authz.rego).
func (b *Backend) callbackHealthy(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "POST",
		b.baseURL+"/v1/data/authz/pgauthz/callback_healthy", strings.NewReader(`{}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("OPA deep-readiness query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OPA deep-readiness query returned %d", resp.StatusCode)
	}
	var out struct {
		Result *bool `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("OPA deep-readiness response: %w", err)
	}
	if out.Result == nil {
		// Rule not defined in the loaded policy set. In strict mode
		// (OPA_DEEP_READINESS_REQUIRED) that FAILS readiness — an operator must
		// not believe end-to-end readiness is active when it isn't (review #9);
		// otherwise degrade to the shallow check, visibly (mode metric + log).
		metrics.SetOPAReadinessMode(false)
		if b.deepReadinessRequired {
			return fmt.Errorf("OPA_DEEP_READINESS_REQUIRED: the loaded policy set has no authz.pgauthz.callback_healthy rule")
		}
		slog.Debug("OPA policy set has no callback_healthy rule; readiness is OPA-shallow")
		return nil
	}
	metrics.SetOPAReadinessMode(true)
	if !*out.Result {
		return fmt.Errorf("authorization path unhealthy: OPA cannot reach the native callback (or its PostgreSQL)")
	}
	return nil
}

// query calls OPA's /v1/data/{pkg}/{rule} and unwraps the result.
func (b *Backend) query(ctx context.Context, rule string, input any, dest any) (err error) {
	// OPA request latency + result (ADR 0010) — single chokepoint for every rule.
	start := time.Now()
	defer func() {
		metrics.OPARequestDuration.Observe(time.Since(start).Seconds())
		result := "ok"
		if err != nil {
			result = "error"
		}
		metrics.OPARequests.WithLabelValues(result).Inc()
	}()
	// Forward the verified token so OPA can re-validate it (input.token path),
	// rather than trusting the forwarded subject. Applied at this single chokepoint
	// so every rule (allow, evaluations, accessible_*, permitted_actions) benefits.
	if b.forwardToken {
		if m, ok := input.(map[string]any); ok {
			if tok := api.TokenFromContext(ctx); tok != "" {
				m["token"] = tok
			}
		}
	}
	// Forward the derived per-app DB role (DB_ROLE_CLAIM / CLIENT_DB_ROLES,
	// already validated against the issuer's db_roles binding by the
	// middleware) as input.db_role. OPA forwards it to pgauthzd's native reader
	// callback as X-PGAuthz-Role, which pgauthzd validates + SET LOCAL ROLEs to
	// for per-app namespace isolation. In token mode OPA re-derives the role from the verified
	// claims and ignores this field; it is honored only in trusted-PEP mode
	// (require_token_for_reads=false).
	if m, ok := input.(map[string]any); ok {
		if role := api.DBRoleFromContext(ctx); role != "" {
			m["db_role"] = role
		}
	}
	// Caller sent Cache-Control: no-cache -> ask OPA to bypass its decision
	// cache for this request (input.no_cache -> 0-second http.send TTL).
	if m, ok := input.(map[string]any); ok {
		if api.NoCacheFromContext(ctx) {
			m["no_cache"] = true
		}
	}
	// Capture the decision timestamp ONCE and forward it (ADR 0011): every batch
	// item and every policy hook in this request then sees the same server clock
	// — no per-item skew, stable across INTERNAL retries of this request. Also
	// forward the server-configured deployment environment. Hooks read these
	// server-derived fields for time/environment gates instead of trusting
	// caller context.
	if m, ok := input.(map[string]any); ok {
		m["evaluated_at"] = time.Now().UnixNano()
		// An unset environment forwards the explicit sentinel "unknown", NOT ""
		// — an environment-gated veto comparing equality against a real value
		// would silently never fire on "" (fail-open). "unknown" makes the
		// unconfigured state visible; env-gated hooks must treat it as the most
		// restrictive environment (deny on unknown / allowlist-style gates).
		env := b.deploymentEnv
		if env == "" {
			env = "unknown"
		}
		m["deployment"] = map[string]any{"environment": env}
	}
	body, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		return fmt.Errorf("marshaling OPA input: %w", err)
	}

	// strict-builtin-errors=true makes a builtin error during evaluation (a
	// buggy hook or platform rule) FAIL the query instead of silently making
	// the affected expression undefined — a vanished `deny` must not fail open
	// (ADR 0011). OPA then returns HTTP 500, which the status check below turns
	// into an error → the handler fails the request closed (5xx), never a
	// phantom allow/deny. Our http.send calls use raise_error:false, so
	// expected downstream non-2xx responses stay handled and don't trip this.
	url := fmt.Sprintf("%s/v1/data/%s/%s?strict-builtin-errors=true", b.baseURL, b.pkg, rule)
	if b.evalMetrics {
		url += "&metrics=true"
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("OPA request to %s: %w", rule, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading OPA response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Distinguishable operational failure (policy_evaluation_failed) — not a
		// decision. The handler maps this to 5xx, never allow/deny.
		return fmt.Errorf("policy_evaluation_failed: OPA %s returned %d: %s", rule, resp.StatusCode, string(respBody))
	}

	// OPA wraps results in {"result": ...}; ?metrics=true adds a `metrics`
	// object whose timer_rego_query_eval_ns is OPA's own evaluation time
	// (isolated from network + OPA HTTP framing).
	var wrapper struct {
		Result  json.RawMessage  `json:"result"`
		Metrics map[string]int64 `json:"metrics"`
	}
	if err := json.Unmarshal(respBody, &wrapper); err != nil {
		return fmt.Errorf("unmarshaling OPA response: %w", err)
	}
	if ns, ok := wrapper.Metrics["timer_rego_query_eval_ns"]; ok {
		metrics.OPARegoEvalDuration.Observe(float64(ns) / 1e9)
	}

	if wrapper.Result == nil {
		// OPA returns no result field when the rule is undefined
		return nil
	}

	if err := json.Unmarshal(wrapper.Result, dest); err != nil {
		return fmt.Errorf("unmarshaling OPA result for %s: %w", rule, err)
	}
	return nil
}

// pageInput builds the OPA `page` object. limit is +1 so the policy returns one
// extra row for has-more detection. after (keyset cursor) is included only when
// set, so the policy's offset rules still fire for first/legacy pages.
func pageInput(page *authz.PageRequest) map[string]any {
	p := map[string]any{
		"limit":  page.Limit + 1,
		"offset": page.Offset,
	}
	if page.After != "" {
		p["after"] = page.After
	}
	return p
}

func buildPage(ids []string, limit int) ([]string, *authz.PageResponse, error) {
	hasMore := len(ids) > limit
	if hasMore {
		ids = ids[:limit]
	}

	var pageResp *authz.PageResponse
	if hasMore {
		// Keyset cursor: the next page starts after the last id we return.
		pageResp = &authz.PageResponse{
			HasMore:   true,
			NextToken: api.EncodePageAfter(ids[len(ids)-1]),
		}
	}

	if ids == nil {
		ids = []string{}
	}

	return ids, pageResp, nil
}
