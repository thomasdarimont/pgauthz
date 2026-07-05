package authz

import (
	"context"
	"encoding/json"
)

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

// NativeReader is an optional backend capability exposing pgauthz-native
// READ operations beyond the AuthZEN standard surface — the "why" (explain)
// and the changefeed (watch). Implemented by the direct pgx backend; the
// OPA-compat backend does not implement it (those routes return 501). Returns
// raw JSON straight from the engine so the HTTP layer stays a thin passthrough.
type NativeReader interface {
	// Explain returns explain_access's structured decision + trace.
	Explain(ctx context.Context, req EvalRequest) (json.RawMessage, error)
	// WatchChanges returns a page of the audit changefeed for a store
	// (cursored by after_at/after_seq, lag-gated, filterable).
	WatchChanges(ctx context.Context, req WatchRequest) (json.RawMessage, error)
}

// WatchRequest is a cursored changefeed page request.
type WatchRequest struct {
	Store       string
	AfterAt     string // RFC3339; "" = from the beginning
	AfterSeq    int64
	Limit       int
	Lag         string   // interval, e.g. "1 second"; "" = default
	ObjectTypes []string // nil = all
	Namespaces  []string // nil = all
	Relations   []string // nil = all
}

// DetailedChecker is an optional backend capability: a check that also
// reports WHY (state allow|deny|conditional, missing condition-context keys,
// the managed model version). detail carries everything except the boolean.
// Backends that cannot provide it simply don't implement the interface and
// the handler falls back to the plain boolean check.
type DetailedChecker interface {
	CheckAccessDetailed(ctx context.Context, req EvalRequest) (decision bool, detail map[string]any, err error)
}
