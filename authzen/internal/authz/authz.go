package authz

import "context"

// PageRequest holds pagination parameters. After is a keyset cursor (the last
// id of the previous page); when set it takes precedence over Offset, so paging
// never re-runs the per-candidate access check on earlier pages. Offset is kept
// for back-compat with legacy offset-encoded continuation tokens.
type PageRequest struct {
	Limit  int
	Offset int
	After  string
}

// PageResponse holds pagination state for the response.
type PageResponse struct {
	NextToken string
	HasMore   bool
}

// EvalRequest represents a single access evaluation.
type EvalRequest struct {
	Store       string
	SubjectType string
	SubjectID   string
	Action      string
	ObjectType  string
	ObjectID    string
	Context     map[string]any
}

// EvalResult holds the result of a single evaluation in a batch.
type EvalResult struct {
	Decision bool
}

// Backend is the authorization evaluation interface.
// Both pgbackend and opabackend implement this.
type Backend interface {
	CheckAccess(ctx context.Context, req EvalRequest) (bool, error)
	CheckAccessBatch(ctx context.Context, store string, reqs []EvalRequest,
		globalContext map[string]any, semantic string) ([]EvalResult, error)
	ListResources(ctx context.Context, store string,
		subjectType, subjectID, action, objectType string,
		reqContext map[string]any, page *PageRequest) ([]string, *PageResponse, error)
	ListSubjects(ctx context.Context, store string,
		subjectType, action, objectType, objectID string,
		reqContext map[string]any, page *PageRequest) ([]string, *PageResponse, error)
	ListActions(ctx context.Context, store string,
		subjectType, subjectID, objectType, objectID string,
		reqContext map[string]any) ([]string, error)
	Healthz(ctx context.Context) error
}
