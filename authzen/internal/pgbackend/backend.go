package pgbackend

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"thomasdarimont.de/authz/authzen/internal/api"
	"thomasdarimont.de/authz/authzen/internal/authz"
)

// Backend implements authz.Backend using direct PostgreSQL calls.
type Backend struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Backend {
	return &Backend{pool: pool}
}

func (b *Backend) CheckAccess(ctx context.Context, req authz.EvalRequest) (bool, error) {
	var decision bool
	var err error

	if req.Context != nil {
		ctxJSON, jerr := json.Marshal(req.Context)
		if jerr != nil {
			return false, fmt.Errorf("marshaling context: %w", jerr)
		}
		err = b.pool.QueryRow(ctx,
			"SELECT authz.check_access_with_context($1, $2, $3, $4, $5, $6, $7)",
			req.Store, req.SubjectType, req.SubjectID, req.Action,
			req.ObjectType, req.ObjectID, ctxJSON,
		).Scan(&decision)
	} else {
		err = b.pool.QueryRow(ctx,
			"SELECT authz.check_access($1, $2, $3, $4, $5, $6)",
			req.Store, req.SubjectType, req.SubjectID, req.Action,
			req.ObjectType, req.ObjectID,
		).Scan(&decision)
	}

	if err != nil {
		return false, fmt.Errorf("check_access: %w", err)
	}
	return decision, nil
}

func (b *Backend) CheckAccessBatch(ctx context.Context, store string, reqs []authz.EvalRequest,
	globalContext map[string]any, semantic string) ([]authz.EvalResult, error) {

	// Build JSONB checks array matching the SQL function's expected format
	checks := make([]map[string]string, len(reqs))
	for i, req := range reqs {
		checks[i] = map[string]string{
			"user_type":   req.SubjectType,
			"user_id":     req.SubjectID,
			"relation":    req.Action,
			"object_type": req.ObjectType,
			"object_id":   req.ObjectID,
		}
	}

	checksJSON, err := json.Marshal(checks)
	if err != nil {
		return nil, fmt.Errorf("marshaling checks: %w", err)
	}

	var ctxJSON []byte
	if globalContext != nil {
		ctxJSON, err = json.Marshal(globalContext)
		if err != nil {
			return nil, fmt.Errorf("marshaling context: %w", err)
		}
	}

	var resultJSON []byte
	err = b.pool.QueryRow(ctx,
		"SELECT authz.check_access_batch($1, $2, $3, $4)",
		store, checksJSON, ctxJSON, semantic,
	).Scan(&resultJSON)
	if err != nil {
		return nil, fmt.Errorf("check_access_batch: %w", err)
	}

	var rawResults []struct {
		Decision *bool `json:"decision"`
	}
	if err := json.Unmarshal(resultJSON, &rawResults); err != nil {
		return nil, fmt.Errorf("unmarshaling batch results: %w", err)
	}

	results := make([]authz.EvalResult, len(rawResults))
	for i, r := range rawResults {
		if r.Decision != nil {
			results[i].Decision = *r.Decision
		}
	}
	return results, nil
}

func (b *Backend) ListResources(ctx context.Context, store string,
	subjectType, subjectID, action, objectType string,
	reqContext map[string]any, page *authz.PageRequest) ([]string, *authz.PageResponse, error) {

	limit, offset := pageParams(page)

	var ctxJSON []byte
	if reqContext != nil {
		var err error
		ctxJSON, err = json.Marshal(reqContext)
		if err != nil {
			return nil, nil, fmt.Errorf("marshaling context: %w", err)
		}
	}

	// Request limit+1 to detect if more pages exist
	queryLimit := limit + 1

	rows, err := b.pool.Query(ctx,
		"SELECT object_id FROM authz.list_objects($1, $2, $3, $4, $5, $6, $7, $8)",
		store, subjectType, subjectID, action, objectType, ctxJSON, queryLimit, offset,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("list_objects: %w", err)
	}
	defer rows.Close()

	ids, err := collectStrings(rows, queryLimit)
	if err != nil {
		return nil, nil, err
	}

	return buildPage(ids, limit, offset)
}

func (b *Backend) ListSubjects(ctx context.Context, store string,
	subjectType, action, objectType, objectID string,
	reqContext map[string]any, page *authz.PageRequest) ([]string, *authz.PageResponse, error) {

	limit, offset := pageParams(page)

	var ctxJSON []byte
	if reqContext != nil {
		var err error
		ctxJSON, err = json.Marshal(reqContext)
		if err != nil {
			return nil, nil, fmt.Errorf("marshaling context: %w", err)
		}
	}

	queryLimit := limit + 1

	rows, err := b.pool.Query(ctx,
		"SELECT subject_id FROM authz.list_subjects($1, $2, $3, $4, $5, $6, $7, $8)",
		store, subjectType, action, objectType, objectID, ctxJSON, queryLimit, offset,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("list_subjects: %w", err)
	}
	defer rows.Close()

	ids, err := collectStrings(rows, queryLimit)
	if err != nil {
		return nil, nil, err
	}

	return buildPage(ids, limit, offset)
}

func (b *Backend) ListActions(ctx context.Context, store string,
	subjectType, subjectID, objectType, objectID string,
	reqContext map[string]any) ([]string, error) {

	var ctxJSON []byte
	if reqContext != nil {
		var err error
		ctxJSON, err = json.Marshal(reqContext)
		if err != nil {
			return nil, fmt.Errorf("marshaling context: %w", err)
		}
	}

	rows, err := b.pool.Query(ctx,
		"SELECT action FROM authz.list_actions($1, $2, $3, $4, $5, $6)",
		store, subjectType, subjectID, objectType, objectID, ctxJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("list_actions: %w", err)
	}
	defer rows.Close()

	return collectStrings(rows, 0)
}

func (b *Backend) Healthz(ctx context.Context) error {
	return b.pool.Ping(ctx)
}

// --- helpers ---

func pageParams(page *authz.PageRequest) (limit, offset int) {
	if page == nil {
		return 100, 0
	}
	limit = page.Limit
	if limit <= 0 {
		limit = 100
	}
	return limit, page.Offset
}

func collectStrings(rows pgx.Rows, _ int) ([]string, error) {
	var result []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func buildPage(ids []string, limit, offset int) ([]string, *authz.PageResponse, error) {
	hasMore := len(ids) > limit
	if hasMore {
		ids = ids[:limit]
	}

	var pageResp *authz.PageResponse
	if hasMore {
		pageResp = &authz.PageResponse{
			HasMore:   true,
			NextToken: api.EncodePage(offset + limit),
		}
	}

	if ids == nil {
		ids = []string{}
	}

	return ids, pageResp, nil
}
