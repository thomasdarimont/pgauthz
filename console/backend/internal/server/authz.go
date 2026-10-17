package server

// The console's authorization gate. Every handler resolves the principal from
// the session, derives the person's directory memberships from the token
// (realm roles, groups, organizations → team:<prefix>_<value>), and asks the
// console store with those memberships as CONTEXTUAL tuples:
//
//   check_access_with_contextual_tuples_jsonb('console', 'user', 'alice',
//       'can_edit_model', 'store', 'demo', NULL,
//       '[{"user_type":"user","user_id":"alice","relation":"member",
//          "object_type":"team","object_id":"role_console_admin"}]')
//
// So a store shared with team:role_console_admin#member works for whoever
// carries that realm role, without the console ever writing membership
// tuples. Explicit tuples (owner, tester, …) come from the Access tab.

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/jackc/pgx/v5"
)

type principal struct {
	typ       string   // console subject type (config.SubjectType)
	id        string   // preferred_username
	name      string   // display name from the token
	teams     []string // team object ids derived from claims
	ctxTuples string   // JSON array of contextual membership tuples
}

// principal returns the logged-in person, or nil.
func (s *Server) principal(r *http.Request) *principal {
	se := s.sessionFromReq(r)
	if se == nil || se.username == "" {
		return nil
	}
	claims := claimMap(se.accessToken)
	p := &principal{typ: s.cfg.SubjectType, id: se.username}
	if n, ok := claims["name"].(string); ok {
		p.name = n
	}
	seen := map[string]bool{}
	for _, tc := range s.cfg.TeamClaims {
		for _, v := range claimValues(claimPath(claims, tc.Path)) {
			id := teamID(tc.Prefix, v)
			if !seen[id] {
				seen[id] = true
				p.teams = append(p.teams, id)
			}
		}
	}
	sort.Strings(p.teams)
	tuples := make([]map[string]string, 0, len(p.teams))
	for _, t := range p.teams {
		tuples = append(tuples, map[string]string{
			"user_type": p.typ, "user_id": p.id, "relation": "member", "object_type": "team", "object_id": t,
		})
	}
	raw, _ := json.Marshal(tuples)
	p.ctxTuples = string(raw)
	return p
}

// can asks the console store one question.
func (s *Server) can(ctx context.Context, p *principal, relation, objectType, objectID string) (bool, error) {
	var ok bool
	err := s.engine.QueryRow(ctx,
		`SELECT authz.check_access_with_contextual_tuples_jsonb($1, $2, $3, $4, $5, $6, NULL, $7::jsonb)`,
		s.cfg.ConsoleStore, p.typ, p.id, relation, objectType, objectID, p.ctxTuples).Scan(&ok)
	return ok, err
}

// capabilities answers objects × relations in ONE round trip: for every
// object id of the type, every relation — the home screen's badges and a
// store's tab gating.
func (s *Server) capabilities(ctx context.Context, p *principal, objectType string, ids, relations []string) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	for _, id := range ids {
		out[id] = map[string]bool{}
	}
	if len(ids) == 0 || len(relations) == 0 {
		return out, nil
	}
	// One engine call for the whole objects × relations grid: the contextual
	// membership tuples are loaded once, every check reuses them.
	checks := make([]map[string]string, 0, len(ids)*len(relations))
	for _, id := range ids {
		for _, rel := range relations {
			checks = append(checks, map[string]string{"user_type": p.typ, "user_id": p.id, "relation": rel, "object_type": objectType, "object_id": id})
		}
	}
	raw, _ := json.Marshal(checks)
	rows, err := s.engine.Query(ctx, `
		SELECT object_id, relation, decision
		  FROM authz.check_access_batch_with_contextual_tuples_jsonb($1, $2::jsonb, NULL, $3::jsonb)`,
		s.cfg.ConsoleStore, string(raw), nullable(p.ctxTuples))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rel string
		var ok bool
		if err := rows.Scan(&id, &rel, &ok); err != nil {
			return nil, err
		}
		out[id][rel] = ok
	}
	return out, rows.Err()
}

// require resolves the principal and demands one console capability on the
// object; it writes the 401/403 itself and returns nil when the caller must
// stop. The 403 names the capability so the UI can say what is missing.
func (s *Server) require(w http.ResponseWriter, r *http.Request, relation, objectType, objectID string) *principal {
	p := s.principal(r)
	if p == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return nil
	}
	ok, err := s.can(r.Context(), p, relation, objectType, objectID)
	if err != nil {
		writeEngineError(w, err)
		return nil
	}
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":    "you are not allowed to do this: " + relation + " on " + objectType + ":" + objectID,
			"required": relation, "object": objectType + ":" + objectID,
		})
		return nil
	}
	return p
}

// requireStore is require() for the managed store named in the path.
func (s *Server) requireStore(w http.ResponseWriter, r *http.Request, relation string) (*principal, string) {
	store := r.PathValue("store")
	if !validName.MatchString(store) {
		writeError(w, http.StatusBadRequest, "invalid store name")
		return nil, ""
	}
	p := s.require(w, r, relation, "store", store)
	return p, store
}

// asPerson runs fn in one engine transaction attributed to the principal: the
// audit trail's performed_by is the person (authz.performed_by GUC, read by
// the audit triggers), and the console store's action log gets one event
// naming what they did to which object — before the managed-store work, so a
// failure rolls both back together.
func (s *Server) asPerson(ctx context.Context, p *principal, action, objectType, objectID string, payload any, fn func(tx pgx.Tx) error) error {
	tx, err := s.engine.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('authz.performed_by', $1, true)`, p.typ+":"+p.id); err != nil {
		return err
	}
	if payload == nil {
		payload = map[string]any{}
	}
	pl, _ := json.Marshal(payload)
	if _, err := tx.Exec(ctx,
		`SELECT authz.record_event($1, $2, $3, $4, $5, $6, 'request', $7::jsonb, NULL, NULL, $8)`,
		s.cfg.ConsoleStore, p.typ, p.id, action, objectType, objectID, string(pl), p.typ+":"+p.id); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// storeCapabilities are the console relations a store screen is gated by.
var storeCapabilities = []string{
	"can_view", "can_run_tests", "can_edit_model", "can_publish", "can_rollout",
	"can_grant", "can_view_audit", "can_view_decisions", "can_manage_access",
	// the test policy (see test.go): what a tester may ask beyond their own access
	"can_test_others", "can_test_explain_full", "can_test_search", "can_test_history",
}

// homeCapabilities are what the stores home needs per store: the chips it
// shows and the visibility gate. The test-policy capabilities only matter on
// a store's own page, so the home skips them — the capability grid is one
// engine call, but every cell is a graph walk, and stores × capabilities
// adds up.
var homeCapabilities = []string{
	"can_view", "can_run_tests", "can_edit_model", "can_publish", "can_rollout",
	"can_grant", "can_view_audit", "can_view_decisions", "can_manage_access",
}
