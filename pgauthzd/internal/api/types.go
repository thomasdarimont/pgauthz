package api

// AuthZEN 1.0 request/response types.
// See https://openid.net/specs/authorization-api-1_0.html

// --- Evaluation ---

type EvalRequestBody struct {
	Subject  Subject        `json:"subject"`
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

type EvalResponseBody struct {
	Decision bool `json:"decision"`
	// Context carries the optional rich decision detail (AuthZEN's response
	// context field): state allow|deny|conditional, missing_context,
	// conditions, reason, model. Populated only when the caller opts in via
	// the X-PGAuthz-Detail header and the backend supports it.
	Context map[string]any `json:"context,omitempty"`
}

// --- Batch Evaluations ---

type EvalsBatchRequest struct {
	Subject     *Subject          `json:"subject,omitempty"`
	Action      *Action           `json:"action,omitempty"`
	Resource    *Resource         `json:"resource,omitempty"`
	Evaluations []EvalRequestBody `json:"evaluations"`
	Context     map[string]any    `json:"context,omitempty"`
	// Options carries the AuthZEN 1.0 §7.1.2 request options
	// (options.evaluations_semantic).
	Options *EvalsOptions `json:"options,omitempty"`
	// Semantic is the pre-1.0 top-level spelling of the evaluations semantic,
	// still accepted; options.evaluations_semantic wins when both are sent.
	Semantic string `json:"semantic,omitempty"`
}

// EvalsOptions is the AuthZEN 1.0 `options` object of a batch request.
type EvalsOptions struct {
	EvaluationsSemantic string `json:"evaluations_semantic,omitempty"`
}

// semantic is the effective evaluations semantic: options.evaluations_semantic,
// else the legacy top-level `semantic`, else execute_all.
func (r *EvalsBatchRequest) semantic() string {
	if r.Options != nil && r.Options.EvaluationsSemantic != "" {
		return r.Options.EvaluationsSemantic
	}
	if r.Semantic != "" {
		return r.Semantic
	}
	return "execute_all"
}

type EvalsBatchResponse struct {
	Evaluations []EvalResponseBody `json:"evaluations"`
}

// --- Search ---

type SearchSubjectRequest struct {
	Subject  Subject        `json:"subject"`
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
	Page     *PageToken     `json:"page,omitempty"`
}

type SearchResourceRequest struct {
	Subject  Subject        `json:"subject"`
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
	Page     *PageToken     `json:"page,omitempty"`
}

type SearchActionRequest struct {
	Subject  Subject        `json:"subject"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// The search responses carry the entities THEMSELVES in `results` — subject
// objects {type, id}, resource objects {type, id}, action objects {name}
// (AuthZEN 1.0 §8.4.2, §8.5.2, §8.6.2) — not the pre-1.0 draft's wrapped
// {"subject": {…}} items, and put `page` before `results` on the wire, as
// §8.3 recommends (so a streaming reader sees the cursor first).

type SearchSubjectResponse struct {
	Page    *PageResult `json:"page,omitempty"`
	Results []Subject   `json:"results"`
}

type SearchResourceResponse struct {
	Page    *PageResult `json:"page,omitempty"`
	Results []Resource  `json:"results"`
}

type SearchActionResponse struct {
	Results []Action `json:"results"`
}

// --- Shared types ---

type Subject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Action struct {
	Name string `json:"name"`
}

type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

type PageToken struct {
	Token string `json:"token,omitempty"`
	// Limit is the AuthZEN 1.0 §8.2 page size; Size is the pre-1.0 spelling,
	// still accepted (limit wins when both are sent).
	Limit int `json:"limit,omitempty"`
	Size  int `json:"size,omitempty"`
}

// size is the requested page size: limit, else the legacy size, else 0
// (the caller applies the default).
func (p *PageToken) size() int {
	if p.Limit > 0 {
		return p.Limit
	}
	return p.Size
}

type PageResult struct {
	NextToken string `json:"next_token"`
}

// --- Well-Known ---

// WellKnownResponse is the AuthZEN 1.0 PDP metadata document (§9.1). Field
// names match the spec exactly; PolicyDecisionPoint (the PDP identifier) is
// REQUIRED. For a store-scoped (tenant) PDP the identifier and endpoints carry
// the /stores/{store} path, so each store presents as its own PDP.
type WellKnownResponse struct {
	PolicyDecisionPoint    string   `json:"policy_decision_point"`
	AccessEvaluationEndpt  string   `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpt string   `json:"access_evaluations_endpoint"`
	SearchSubjectEndpoint  string   `json:"search_subject_endpoint"`
	SearchResourceEndpoint string   `json:"search_resource_endpoint"`
	SearchActionEndpoint   string   `json:"search_action_endpoint"`
	Capabilities           []string `json:"capabilities,omitempty"`
}
