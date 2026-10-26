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
	"slices"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

type principal struct {
	typ       string   // console subject type (config.SubjectType)
	id        string   // preferred_username
	name      string   // display name from the token
	email     string   // email claim, when the token carries one
	teams     []string // team object ids derived from claims
	ctxTuples string   // JSON array of contextual membership tuples
	// storeRole: the local admin's contextual role on every store it is asked
	// about (config.LocalAdminStoreRole); pathStore is the store of the current
	// request, so checks on a store's namespaces reach it too. Empty otherwise.
	storeRole string
	pathStore string
	// noTesting: the session's token carries pgauthz:* scopes but not
	// pgauthz:test — the identity provider did not issue it for testing, so
	// the test pages stay closed whatever the console store grants (the
	// local admin has no token and is never masked).
	noTesting bool
}

// scopeLacksTesting: a token issued with pgauthz:* scopes but without
// pgauthz:test was not issued for testing; a token without any pgauthz
// scope (an identity provider that does not use them) is not masked.
func scopeLacksTesting(scope string) bool {
	fields := strings.Fields(scope)
	hasPgauthz := false
	for _, f := range fields {
		if strings.HasPrefix(f, "pgauthz:") {
			hasPgauthz = true
		}
	}
	return hasPgauthz && !slices.Contains(fields, "pgauthz:test")
}

// testingRelations are the console capabilities pgauthz:test guards.
var testingRelations = map[string]bool{"can_run_tests": true, "can_test_others": true, "can_test_explain_full": true, "can_test_search": true, "can_test_history": true}

// tuplesFor returns the contextual tuples for a check on objectType/ids: the
// membership tuples, plus — for the local admin — its store role on every
// store among the ids and on the request's store. Nothing is written.
func (p *principal) tuplesFor(objectType string, ids []string) string {
	if p.storeRole == "" {
		return p.ctxTuples
	}
	var tuples []map[string]string
	_ = json.Unmarshal([]byte(p.ctxTuples), &tuples)
	add := func(store string) {
		tuples = append(tuples, map[string]string{
			"user_type": p.typ, "user_id": p.id, "relation": p.storeRole, "object_type": "store", "object_id": store,
		})
	}
	seen := map[string]bool{}
	if objectType == "store" {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				add(id)
			}
		}
	}
	if p.pathStore != "" && !seen[p.pathStore] {
		add(p.pathStore)
	}
	raw, _ := json.Marshal(tuples)
	return string(raw)
}

// principal returns the logged-in person, or nil.
func (s *Server) principal(r *http.Request) *principal {
	se := s.sessionFromReq(r)
	if se == nil || se.username == "" {
		return nil
	}
	p := &principal{typ: s.cfg.SubjectType, id: se.username}
	if se.local {
		// The local admin sign-in: memberships come from the configuration,
		// not a token (getSession already rejected it if deactivated).
		p.name = se.username
		p.teams = append(p.teams, s.cfg.LocalAdminTeams...)
		p.storeRole = s.cfg.LocalAdminStoreRole
		p.pathStore = r.PathValue("store")
	} else {
		// Identity and memberships: the ID token (what OpenID Connect tells
		// the relying party about the person); the access token only says
		// what it may be used for (its scope) and is forwarded to pgauthzd.
		claims := claimMap(se.idToken)
		if n, ok := claims["name"].(string); ok {
			p.name = n
		}
		if e, ok := claims["email"].(string); ok {
			p.email = e
		}
		if sc, ok := claimMap(se.accessToken)["scope"].(string); ok {
			p.noTesting = scopeLacksTesting(sc)
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

// querier is what a console-store question needs: the pool, or the
// transaction a change runs in (so the check sees the same snapshot and
// waits on the same lock as a competing access change).
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// can asks the console store one question.
func (s *Server) can(ctx context.Context, p *principal, relation, objectType, objectID string) (bool, error) {
	return s.canQ(ctx, s.engine, p, relation, objectType, objectID)
}

func (s *Server) canQ(ctx context.Context, q querier, p *principal, relation, objectType, objectID string) (bool, error) {
	if p.noTesting && testingRelations[relation] {
		return false, nil
	}
	var ok bool
	err := q.QueryRow(ctx,
		`SELECT authz.check_access_with_contextual_tuples_jsonb($1, $2, $3, $4, $5, $6, NULL, $7::jsonb)`,
		s.cfg.ConsoleStore, p.typ, p.id, relation, objectType, objectID, p.tuplesFor(objectType, []string{objectID})).Scan(&ok)
	return ok, err
}

// accessLock serializes, per console object (store:X, platform:default),
// every change that is authorized by or changes that object's roles: role
// grants and removals, model and data changes, tests being recorded. The
// transaction-scoped advisory lock is taken before the capability is
// re-checked inside the transaction, so a removal committed by another
// session is seen (it released the lock after committing) and a competing
// removal waits — the last-owner count and the "may this person still do
// this" question are answered under the same lock.
//
// Store capabilities can be inherited from the platform (`admin from
// platform`), so a change about a store also takes the platform lock in
// SHARED mode first, and a change about the platform (an admin granted or
// revoked) takes it exclusively: a platform-admin revocation waits for the
// store changes that admin already started, and the store changes that start
// after it see the revocation. Independent stores still run in parallel. The
// order is always platform, then object — no path takes them the other way.
// Keys are 64-bit (hashtextextended) so unrelated objects do not share a
// lock by collision; the bigint advisory-lock overloads take them.
func (s *Server) accessLock(ctx context.Context, tx pgx.Tx, objectType, objectID string) error {
	if objectType != "platform" {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`, lockKey("platform", s.cfg.PlatformID)); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey(objectType, objectID))
	return err
}

func lockKey(objectType, objectID string) string {
	return "pgauthz-console:" + objectType + ":" + objectID
}

// storeGate is an in-transaction authorization (see asPersonAuthorized) for
// one or more capabilities on a store — all of them are required.
func (s *Server) storeGate(ctx context.Context, p *principal, store string, caps ...string) func(tx pgx.Tx) error {
	return func(tx pgx.Tx) error {
		for _, c := range caps {
			ok, err := s.canQ(ctx, tx, p, c, "store", store)
			if err != nil {
				return err
			}
			if !ok {
				return scopeError{c, "store:" + store}
			}
		}
		return nil
	}
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
		s.cfg.ConsoleStore, string(raw), nullable(p.tuplesFor(objectType, ids)))
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
		out[id][rel] = ok && !(p.noTesting && testingRelations[rel])
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
//
// The capability named by action on the object is re-checked INSIDE the
// transaction, after the per-object access lock: the handler's earlier
// check decided whether to start at all, this one decides whether to
// commit, so a role revoked in between denies the change (the review's
// check/use race). Handlers whose authorization is namespace-scoped use
// asPersonScoped with the namespaces they touch.
func (s *Server) asPerson(ctx context.Context, p *principal, action, objectType, objectID string, payload any, fn func(tx pgx.Tx) error) error {
	return s.asPersonScoped(ctx, p, action, objectType, objectID, nil, payload, fn)
}

// asPersonScoped — asPerson for a change scoped by namespaces (see
// authorizeScoped): a store capability allows everything, otherwise every
// touched namespace must grant it. namespaces == nil means store-level.
func (s *Server) asPersonScoped(ctx context.Context, p *principal, action, objectType, objectID string, namespaces []string, payload any, fn func(tx pgx.Tx) error) error {
	authorize := func(tx pgx.Tx) error {
		if namespaces != nil {
			return s.authorizeScopedQ(ctx, tx, p, action, objectID, namespaces)
		}
		ok, err := s.canQ(ctx, tx, p, action, objectType, objectID)
		if err != nil {
			return err
		}
		if !ok {
			return scopeError{action, objectType + ":" + objectID}
		}
		return nil
	}
	return s.asPersonAuthorized(ctx, p, authorize, action, objectType, objectID, payload, fn)
}

// asPersonAuthorized is the general form: authorize runs inside the
// transaction, after the access lock on (objectType, objectID), and decides
// whether the change may commit — for the handlers whose gate is not simply
// "action on that object" (creating, adopting or deleting a store is decided
// on the platform object). It returns a scopeError to deny (→ 403).
func (s *Server) asPersonAuthorized(ctx context.Context, p *principal, authorize func(tx pgx.Tx) error, action, objectType, objectID string, payload any, fn func(tx pgx.Tx) error) error {
	tx, err := s.engine.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.accessLock(ctx, tx, objectType, objectID); err != nil {
		return err
	}
	if err := authorize(tx); err != nil {
		return err
	}
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
	"can_grant", "can_view_audit", "can_export", "can_view_decisions", "can_manage_access",
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
	"can_grant", "can_view_audit", "can_export", "can_view_decisions", "can_manage_access",
}
