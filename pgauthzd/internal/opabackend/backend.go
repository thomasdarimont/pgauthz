package opabackend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"thomasdarimont.de/authz/pgauthzd/internal/api"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

// Backend implements authz.Backend by calling OPA HTTP endpoints.
type Backend struct {
	baseURL      string
	pkg          string // e.g. "authz"
	client       *http.Client
	forwardToken bool // add the verified bearer token to OPA input as input.token
}

func New(baseURL, pkg string, forwardToken bool) *Backend {
	return &Backend{
		baseURL:      strings.TrimRight(baseURL, "/"),
		pkg:          pkg,
		client:       &http.Client{},
		forwardToken: forwardToken,
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

	var results []struct {
		Decision bool `json:"decision"`
	}
	if err := b.query(ctx, "evaluations", input, &results); err != nil {
		return nil, err
	}

	out := make([]authz.EvalResult, len(results))
	for i, r := range results {
		out[i] = authz.EvalResult{Decision: r.Decision}
	}
	return out, nil
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

		var ids []string
		if err := b.query(ctx, "accessible_objects_page", input, &ids); err != nil {
			return nil, nil, err
		}

		return buildPage(ids, page.Limit)
	}

	// Unpaginated — returns a set from OPA
	var ids []string
	if err := b.query(ctx, "accessible_objects", input, &ids); err != nil {
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

		var ids []string
		if err := b.query(ctx, "accessible_subjects_page", input, &ids); err != nil {
			return nil, nil, err
		}

		return buildPage(ids, page.Limit)
	}

	var ids []string
	if err := b.query(ctx, "accessible_subjects", input, &ids); err != nil {
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
	return nil
}

// query calls OPA's /v1/data/{pkg}/{rule} and unwraps the result.
func (b *Backend) query(ctx context.Context, rule string, input any, dest any) error {
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
	// callback as X-Authz-Role, which pgauthzd validates + SET LOCAL ROLEs to
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
	body, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		return fmt.Errorf("marshaling OPA input: %w", err)
	}

	url := fmt.Sprintf("%s/v1/data/%s/%s", b.baseURL, b.pkg, rule)
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
		return fmt.Errorf("OPA %s returned %d: %s", rule, resp.StatusCode, string(respBody))
	}

	// OPA wraps results in {"result": ...}
	var wrapper struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(respBody, &wrapper); err != nil {
		return fmt.Errorf("unmarshaling OPA response: %w", err)
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
