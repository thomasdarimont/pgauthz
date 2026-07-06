package authz

import (
	"context"
	"encoding/json"
	"errors"
)

// ErrForbiddenRole signals that a caller's per-app DB role is not authorized
// for the attempted operation (e.g. a reader-only role reached a write). It is
// a caller/authorization error, not a server fault — handlers map it to 403,
// not 500. Backends wrap it with %w so errors.Is recognizes it.
var ErrForbiddenRole = errors.New("db role not authorized for this operation")

// ErrInvalidConsistency is returned when a write requests an unrecognized
// consistency mode. Fails closed (rejects the write) rather than silently
// downgrading the durability guarantee — maps to 400 Bad Request.
var ErrInvalidConsistency = errors.New("unknown consistency mode")

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

// NativeWriter is an optional backend capability: pgauthz tuple WRITES over
// the direct pgx connection (the `full` profile). Each op runs in a
// transaction that SET LOCAL ROLEs to a writer-capable role (the per-app role
// from the token when present, validated writer + not admin; else the default
// writer), applies the per-write consistency mode, and records performed_by =
// the authenticated subject. Implemented only by the direct backend on a
// writable connection; a decision-only (read-only) instance does not (403/501).
type NativeWriter interface {
	// WriteTuples upserts a batch; returns the count affected.
	WriteTuples(ctx context.Context, req WriteRequest) (int, error)
	// DeleteTuples removes a batch; returns the count affected.
	DeleteTuples(ctx context.Context, req WriteRequest) (int, error)
	// DeleteUserTuples removes every tuple for a subject (offboarding); returns
	// the count affected.
	DeleteUserTuples(ctx context.Context, req DeleteUserRequest) (int, error)
	// WriteTuplesChecked applies preconditions + deletes + writes atomically
	// (optimistic concurrency); returns the engine's JSONB result verbatim.
	WriteTuplesChecked(ctx context.Context, req CheckedWriteRequest) (json.RawMessage, error)
}

// WriteRequest is a batch tuple write/delete. Tuples is the JSONB array in the
// write_tuples_jsonb/delete_tuples_jsonb shape. PerformedBy is the audit author
// (the authenticated subject). Consistency maps to synchronous_commit
// (applied|durable|eventual); "" = the connection default. The per-app DB role
// to assume is taken from the request context (the verified token), same as the
// read path — the backend reads it there, not from this struct.
type WriteRequest struct {
	Store       string
	Tuples      json.RawMessage
	PerformedBy string
	Consistency string
}

// DeleteUserRequest is an offboarding delete: every tuple for (UserType,UserID).
type DeleteUserRequest struct {
	Store       string
	UserType    string
	UserID      string
	PerformedBy string
	Consistency string
}

// CheckedWriteRequest is a conditional/atomic write: preconditions gate the
// deletes+writes, all in one transaction. Each field is a JSONB array.
type CheckedWriteRequest struct {
	Store         string
	Preconditions json.RawMessage
	Deletes       json.RawMessage
	Writes        json.RawMessage
	PerformedBy   string
	Consistency   string
}

// DetailedChecker is an optional backend capability: a check that also
// reports WHY (state allow|deny|conditional, missing condition-context keys,
// the managed model version). detail carries everything except the boolean.
// Backends that cannot provide it simply don't implement the interface and
// the handler falls back to the plain boolean check.
type DetailedChecker interface {
	CheckAccessDetailed(ctx context.Context, req EvalRequest) (decision bool, detail map[string]any, err error)
}

// ContextualChecker is an optional backend capability: a check that also
// evaluates ephemeral "contextual" tuples (a JSONB array in the
// write_tuples_jsonb element shape) alongside the stored graph, without
// persisting them. Implemented by the direct pgx backend.
type ContextualChecker interface {
	CheckWithContextualTuples(ctx context.Context, req EvalRequest, contextualTuples json.RawMessage) (bool, error)
}
