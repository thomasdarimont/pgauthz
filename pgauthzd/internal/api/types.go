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
	// the X-Authz-Detail header and the backend supports it.
	Context map[string]any `json:"context,omitempty"`
}

// --- Batch Evaluations ---

type EvalsBatchRequest struct {
	Subject     *Subject          `json:"subject,omitempty"`
	Action      *Action           `json:"action,omitempty"`
	Resource    *Resource         `json:"resource,omitempty"`
	Evaluations []EvalRequestBody `json:"evaluations"`
	Context     map[string]any    `json:"context,omitempty"`
	Semantic    string            `json:"semantic,omitempty"`
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

type SearchSubjectResponse struct {
	Results []SubjectResult `json:"results"`
	Page    *PageResult     `json:"page,omitempty"`
}

type SearchResourceResponse struct {
	Results []ResourceResult `json:"results"`
	Page    *PageResult      `json:"page,omitempty"`
}

type SearchActionResponse struct {
	Results []ActionResult `json:"results"`
}

type SubjectResult struct {
	Subject Subject `json:"subject"`
}

type ResourceResult struct {
	Resource Resource `json:"resource"`
}

type ActionResult struct {
	Action Action `json:"action"`
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
	Size  int    `json:"size,omitempty"`
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
