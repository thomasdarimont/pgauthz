package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"thomasdarimont.de/authz/pgauthzadm"
)

// handleMeta — names for the Test tab's autocompletion: types, relations,
// and the subjects/objects that appear in tuples.
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view")
	if p == nil {
		return
	}
	ctx := r.Context()
	names := func(sql string) []string {
		out := []string{}
		rows, err := s.engine.Query(ctx, sql, store)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if rows.Scan(&v) == nil {
				out = append(out, v)
			}
		}
		return out
	}
	// Relations per object type with their kind: what a subject IS (relation,
	// assignable; "derived" when it is also inherited) versus what it CAN DO
	// (permission). The Test tab groups its action picker by this.
	type relInfo struct {
		Name    string `json:"name"`
		Kind    string `json:"kind"`
		Direct  bool   `json:"direct"`
		Derived bool   `json:"derived"`
	}
	byType := map[string][]relInfo{}
	if rows, err := s.engine.Query(ctx, `
		SELECT v.object_type, v.relation, COALESCE(r.metadata->>'kind', 'relation'),
		       bool_or(v.rule_type = 'direct'), bool_or(v.rule_type <> 'direct')
		  FROM authz.models_view v
		  JOIN authz.stores s ON s.name = v.store
		  JOIN authz.relations r ON r.store_id = s.id AND r.name = v.relation
		 WHERE v.store = $1
		 GROUP BY v.object_type, v.relation, r.metadata
		 ORDER BY v.object_type, (r.metadata->>'ui_order')::numeric NULLS LAST, v.relation`, store); err == nil {
		defer rows.Close()
		for rows.Next() {
			var typ string
			var ri relInfo
			if rows.Scan(&typ, &ri.Name, &ri.Kind, &ri.Direct, &ri.Derived) == nil {
				byType[typ] = append(byType[typ], ri)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"relations_by_type": byType,
		"types":             names(`SELECT t.name FROM authz.types t JOIN authz.stores s ON s.id=t.store_id WHERE s.name=$1 ORDER BY t.name`),
		"relations":         names(`SELECT r.name FROM authz.relations r JOIN authz.stores s ON s.id=r.store_id WHERE s.name=$1 ORDER BY (r.metadata->>'ui_order')::numeric NULLS LAST, r.name`),
		// Samples per type (up to 100 each), so a store whose subjects are mostly
		// orgs and teams still offers a few users — the pickers' completion
		// lists and the placeholders both draw on these.
		"subjects": names(`SELECT ut.name || ':' || x.user_id
		                     FROM authz.types ut JOIN authz.stores s ON s.id = ut.store_id
		                     JOIN LATERAL (SELECT DISTINCT t.user_id FROM authz.tuples t
		                                    WHERE t.store_id = ut.store_id AND t.user_type = ut.id ORDER BY 1 LIMIT 100) x ON true
		                    WHERE s.name = $1 ORDER BY 1`),
		"objects": names(`SELECT ot.name || ':' || x.object_id
		                    FROM authz.types ot JOIN authz.stores s ON s.id = ot.store_id
		                    JOIN LATERAL (SELECT DISTINCT t.object_id FROM authz.tuples t
		                                   WHERE t.store_id = ot.store_id AND t.object_type = ot.id ORDER BY 1 LIMIT 100) x ON true
		                   WHERE s.name = $1 ORDER BY 1`),
	})
}

type checkReq struct {
	Subject  string          `json:"subject"`  // type:id
	Action   string          `json:"action"`   // relation
	Resource string          `json:"resource"` // type:id
	Context  json.RawMessage `json:"context"`
	// Contextual tuples (OpenFGA notation, the fixture's shape): ephemeral
	// relationships that take part in this question only — "would bob be
	// allowed if he were a member of team X?". Nothing is written.
	ContextualTuples []pgauthzadm.FixtureTuple `json:"contextual_tuples"`
	// explain only: keep just the steps that contributed to the decision
	// (p_successful_only), and strip identifiers and free text (p_redact).
	SuccessfulOnly bool `json:"successful_only"`
	Redact         bool `json:"redact"`
	// At (RFC 3339, optional): decide as of this instant instead of now —
	// the audit trail replayed to it (tuples and model as they were, or as
	// they are for a future instant) with expiries applied against it.
	At string `json:"at"`
}

func splitRef(s string) (typ, id string, ok bool) {
	typ, id, ok = strings.Cut(s, ":")
	return typ, id, ok && typ != "" && id != ""
}

// ── The test policy ────────────────────────────────────────────────────────
//
// can_run_tests opens the Test tab; four further permissions of the console
// store say what a tester may ask beyond their own access, and the console
// enforces them here, server-side, whatever the UI sends:
//
//	can_test_others        subjects other than the person (by id, any type)
//	can_test_explain_full  unredacted resolution trees (else p_redact is forced)
//	can_test_search        list_objects / list_subjects (enumeration)
//	can_test_history       point-in-time checks (audit replay)
//
// Every test is recorded in the console's action log as the person, with
// the question but never the answer.
type testPolicy struct {
	Others, ExplainFull, Search, History bool
}

var testPolicyCaps = []string{"can_test_others", "can_test_explain_full", "can_test_search", "can_test_history"}

func (s *Server) testPolicyFor(ctx context.Context, p *principal, store string) (testPolicy, error) {
	caps, err := s.capabilities(ctx, p, "store", []string{store}, testPolicyCaps)
	if err != nil {
		return testPolicy{}, err
	}
	c := caps[store]
	return testPolicy{Others: c["can_test_others"], ExplainFull: c["can_test_explain_full"], Search: c["can_test_search"], History: c["can_test_history"]}, nil
}

// isSelf: the subject is the person — the person's id under one of the
// subject types that denote people (the console's own type plus
// CONSOLE_SELF_SUBJECT_TYPES). Another type with the same id (agent:alice,
// service_account:alice) is another principal and needs can_test_others.
func (s *Server) isSelf(p *principal, subjectType, subjectID string) bool {
	if subjectID != p.id {
		return false
	}
	if subjectType == p.typ {
		return true
	}
	for _, t := range s.cfg.SelfSubjectTypes {
		if t == subjectType {
			return true
		}
	}
	return false
}

func writePolicyDenied(w http.ResponseWriter, required, why string) {
	writeJSON(w, http.StatusForbidden, map[string]any{"error": why, "required": required, "policy": true})
}

func (s *Server) checkInput(w http.ResponseWriter, r *http.Request) (*principal, string, checkReq, [4]string, bool) {
	var q checkReq
	var parts [4]string
	p, store := s.requireStore(w, r, "can_run_tests")
	if p == nil {
		return nil, "", q, parts, false
	}
	if !decodeJSON(w, r, &q) {
		return nil, "", q, parts, false
	}
	st, sid, ok1 := splitRef(q.Subject)
	ot, oid, ok2 := splitRef(q.Resource)
	if !ok1 || !ok2 || q.Action == "" {
		writeError(w, http.StatusBadRequest, "subject (type:id), action and resource (type:id) are required")
		return nil, "", q, parts, false
	}
	pol, err := s.testPolicyFor(r.Context(), p, store)
	if err != nil {
		writeEngineError(w, err)
		return nil, "", q, parts, false
	}
	if !pol.Others && !s.isSelf(p, st, sid) {
		writePolicyDenied(w, "can_test_others", "the test policy limits you to your own access: the subject must be you ("+p.typ+":"+p.id+" or a configured person type with that id)")
		return nil, "", q, parts, false
	}
	if q.At != "" && !pol.History {
		writePolicyDenied(w, "can_test_history", "the test policy does not let you decide at another point in time")
		return nil, "", q, parts, false
	}
	if !pol.ExplainFull {
		q.Redact = true // forced, whatever the UI sent
	}
	if _, err := pgauthzadm.ContextualTuplesJSON(q.ContextualTuples); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return nil, "", q, parts, false
	}
	parts = [4]string{st, sid, ot, oid}
	return p, store, q, parts, true
}

// contextualTuplesArg renders contextual tuples for a `$n::jsonb` argument
// (NULL for none). Validated already by the caller (checkInput, or an
// explicit check) — a malformed tuple here is a programming error.
func contextualTuplesArg(ts []pgauthzadm.FixtureTuple) any {
	raw, err := pgauthzadm.ContextualTuplesJSON(ts)
	if err != nil || raw == nil {
		return nil
	}
	return string(raw)
}

// recordTest — the question (never the answer) in the console's action log,
// as the person; the query runs in the same transaction.
func (s *Server) recordTest(ctx context.Context, p *principal, store string, payload map[string]any, fn func(tx pgx.Tx) error) error {
	return s.asPerson(ctx, p, "can_run_tests", "store", store, payload, fn)
}

// handleCheck — a decision for ANY subject in the managed store (the tester's
// question "would bob be allowed?"), with optional request context.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	p, store, q, x, ok := s.checkInput(w, r)
	if !ok {
		return
	}
	var allowed bool
	var at time.Time
	if q.At != "" {
		var perr error
		if at, perr = time.Parse(time.RFC3339, q.At); perr != nil {
			writeError(w, http.StatusBadRequest, "at must be an RFC 3339 timestamp")
			return
		}
	}
	if q.At != "" && len(q.ContextualTuples) > 0 {
		writeError(w, http.StatusBadRequest, "contextual tuples are live only: a check at another point in time replays the audit trail")
		return
	}
	err := s.recordTest(r.Context(), p, store, map[string]any{"op": "check", "subject": q.Subject, "action": q.Action, "resource": q.Resource, "at": q.At, "contextual_tuples": len(q.ContextualTuples)}, func(tx pgx.Tx) error {
		if q.At != "" {
			return tx.QueryRow(r.Context(), `SELECT authz.audit_check_access($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
				store, x[0], x[1], q.Action, x[2], x[3], at, nullableJSON(q.Context)).Scan(&allowed)
		}
		if len(q.ContextualTuples) > 0 {
			return tx.QueryRow(r.Context(), `SELECT authz.check_access_with_contextual_tuples_jsonb($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)`,
				store, x[0], x[1], q.Action, x[2], x[3], nullableJSON(q.Context), contextualTuplesArg(q.ContextualTuples)).Scan(&allowed)
		}
		return tx.QueryRow(r.Context(), `SELECT authz.check_access_with_context($1,$2,$3,$4,$5,$6,$7::jsonb)`,
			store, x[0], x[1], q.Action, x[2], x[3], nullableJSON(q.Context)).Scan(&allowed)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowed": allowed, "at": nullable(q.At)})
}

type actionsReq struct {
	Subject          string                    `json:"subject"`  // type:id
	Resource         string                    `json:"resource"` // type:id
	Context          json.RawMessage           `json:"context"`
	ContextualTuples []pgauthzadm.FixtureTuple `json:"contextual_tuples"`
}

// handleActions — POST .../actions: everything the subject holds and may
// do on the object (authz.list_actions: the relations held and the
// permissions they imply), for the Test tab's "What may they do?" mode.
// Bound by the test policy like a check: another subject needs
// can_test_others. Recorded as the person.
func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_run_tests")
	if p == nil {
		return
	}
	var q actionsReq
	if !decodeJSON(w, r, &q) {
		return
	}
	st, sid, ok1 := splitRef(q.Subject)
	ot, oid, ok2 := splitRef(q.Resource)
	if !ok1 || !ok2 {
		writeError(w, http.StatusBadRequest, "subject (type:id) and resource (type:id) are required")
		return
	}
	pol, err := s.testPolicyFor(r.Context(), p, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if !pol.Others && !s.isSelf(p, st, sid) {
		writePolicyDenied(w, "can_test_others", "the test policy limits you to your own access: the subject must be you ("+p.typ+":"+p.id+" or a configured person type with that id)")
		return
	}
	if _, err := pgauthzadm.ContextualTuplesJSON(q.ContextualTuples); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actions := []string{}
	err = s.recordTest(r.Context(), p, store, map[string]any{"op": "actions", "subject": q.Subject, "resource": q.Resource, "contextual_tuples": len(q.ContextualTuples)}, func(tx pgx.Tx) error {
		var rows pgx.Rows
		var err error
		if len(q.ContextualTuples) > 0 {
			rows, err = tx.Query(r.Context(), `SELECT action FROM authz.list_actions_with_contextual_tuples_jsonb($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb) ORDER BY 1`,
				store, st, sid, ot, oid, nullableJSON(q.Context), contextualTuplesArg(q.ContextualTuples))
		} else {
			rows, err = tx.Query(r.Context(), `SELECT action FROM authz.list_actions($1,$2,$3,$4,$5,$6::jsonb) ORDER BY 1`,
				store, st, sid, ot, oid, nullableJSON(q.Context))
		}
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				return err
			}
			actions = append(actions, a)
		}
		return rows.Err()
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

// handleExplain — the resolution tree behind a decision.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	p, store, q, x, ok := s.checkInput(w, r)
	if !ok {
		return
	}
	if q.At != "" {
		writeError(w, http.StatusBadRequest, "the resolution tree is live only; a check at another point in time returns the decision alone")
		return
	}
	var raw []byte
	err := s.recordTest(r.Context(), p, store, map[string]any{"op": "explain", "subject": q.Subject, "action": q.Action, "resource": q.Resource, "redact": q.Redact, "contextual_tuples": len(q.ContextualTuples)}, func(tx pgx.Tx) error {
		if len(q.ContextualTuples) > 0 {
			return tx.QueryRow(r.Context(), `SELECT authz.explain_access_with_contextual_tuples_jsonb($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10)`,
				store, x[0], x[1], q.Action, x[2], x[3], nullableJSON(q.Context), contextualTuplesArg(q.ContextualTuples), q.SuccessfulOnly, q.Redact).Scan(&raw)
		}
		return tx.QueryRow(r.Context(), `SELECT authz.explain_access($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`,
			store, x[0], x[1], q.Action, x[2], x[3], nullableJSON(q.Context), q.SuccessfulOnly, q.Redact).Scan(&raw)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

// ── Matrix: many subjects × actions × resources in one engine round trip ────

type batchReq struct {
	Subjects         []string                  `json:"subjects"`  // type:id
	Actions          []string                  `json:"actions"`   // relations
	Resources        []string                  `json:"resources"` // type:id
	Context          json.RawMessage           `json:"context"`
	ContextualTuples []pgauthzadm.FixtureTuple `json:"contextual_tuples"` // shared by every cell
}

type batchCell struct {
	Subject  string `json:"subject"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Allowed  bool   `json:"allowed"`
}

// handleCheckBatch — the cross product of the three lists, decided by
// check_access_batch_typed_jsonb (one call, one snapshot, shared context).
func (s *Server) handleCheckBatch(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_run_tests")
	if p == nil {
		return
	}
	var q batchReq
	if !decodeJSON(w, r, &q) {
		return
	}
	n := len(q.Subjects) * len(q.Actions) * len(q.Resources)
	if n == 0 || n > 2000 {
		writeError(w, http.StatusBadRequest, "subjects × actions × resources must be between 1 and 2000 checks")
		return
	}
	pol, err := s.testPolicyFor(r.Context(), p, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	checks := make([]map[string]string, 0, n)
	for _, sub := range q.Subjects {
		st, sid, ok := splitRef(sub)
		if !ok {
			writeError(w, http.StatusBadRequest, "subject must be type:id: "+sub)
			return
		}
		if !pol.Others && !s.isSelf(p, st, sid) {
			writePolicyDenied(w, "can_test_others", "the test policy limits you to your own access: every subject must be you ("+p.typ+":"+p.id+" or a configured person type with that id)")
			return
		}
		for _, act := range q.Actions {
			for _, res := range q.Resources {
				ot, oid, ok := splitRef(res)
				if !ok {
					writeError(w, http.StatusBadRequest, "resource must be type:id: "+res)
					return
				}
				checks = append(checks, map[string]string{"user_type": st, "user_id": sid, "relation": act, "object_type": ot, "object_id": oid})
			}
		}
	}
	if _, err := pgauthzadm.ContextualTuplesJSON(q.ContextualTuples); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, _ := json.Marshal(checks)
	cells := make([]batchCell, 0, n)
	err = s.recordTest(r.Context(), p, store, map[string]any{"op": "matrix", "subjects": q.Subjects, "actions": q.Actions, "resources": q.Resources, "checks": n, "contextual_tuples": len(q.ContextualTuples)}, func(tx pgx.Tx) error {
		var rows pgx.Rows
		var err error
		if len(q.ContextualTuples) > 0 {
			rows, err = tx.Query(r.Context(), `
			SELECT user_type, user_id, relation, object_type, object_id, decision
			  FROM authz.check_access_batch_with_contextual_tuples_jsonb($1, $2::jsonb, $3::jsonb, $4::jsonb)`, store, string(raw), nullableJSON(q.Context), contextualTuplesArg(q.ContextualTuples))
		} else {
			rows, err = tx.Query(r.Context(), `
			SELECT user_type, user_id, relation, object_type, object_id, decision
			  FROM authz.check_access_batch_typed_jsonb($1, $2::jsonb, $3::jsonb)`, store, string(raw), nullableJSON(q.Context))
		}
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var st, sid, rel, ot, oid string
			var allowed bool
			if err := rows.Scan(&st, &sid, &rel, &ot, &oid, &allowed); err != nil {
				return err
			}
			cells = append(cells, batchCell{Subject: st + ":" + sid, Action: rel, Resource: ot + ":" + oid, Allowed: allowed})
		}
		return rows.Err()
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cells": cells})
}

// ── Reverse search: the candidates you do not know ─────────────────────────

type searchReq struct {
	Mode             string                    `json:"mode"`     // objects | subjects
	Subject          string                    `json:"subject"`  // objects: type:id; subjects: the subject TYPE to list
	Action           string                    `json:"action"`   // relation
	Resource         string                    `json:"resource"` // objects: the object TYPE to list; subjects: type:id
	Context          json.RawMessage           `json:"context"`
	ContextualTuples []pgauthzadm.FixtureTuple `json:"contextual_tuples"` // walked like stored tuples
	Limit            int                       `json:"limit"`
	After            string                    `json:"after"` // keyset cursor from the previous page
}

// handleSearch — "which <type> can this subject <action>?" (list_objects) and
// "which <type> can <action> this object?" (list_subjects), paged by keyset.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_run_tests")
	if p == nil {
		return
	}
	var q searchReq
	if !decodeJSON(w, r, &q) {
		return
	}
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	pol, err := s.testPolicyFor(r.Context(), p, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if !pol.Search {
		writePolicyDenied(w, "can_test_search", "the test policy does not let you enumerate objects or subjects")
		return
	}
	if _, err := pgauthzadm.ContextualTuplesJSON(q.ContextualTuples); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := len(q.ContextualTuples) > 0
	var sql string
	var args []any
	switch q.Mode {
	case "objects":
		st, sid, ok := splitRef(q.Subject)
		if !ok || q.Action == "" || q.Resource == "" {
			writeError(w, http.StatusBadRequest, "objects mode needs subject (type:id), action and the resource type")
			return
		}
		if ctx {
			sql = `SELECT object_id, is_wildcard FROM authz.list_objects_with_contextual_tuples_jsonb($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, 0, $9)`
			args = []any{store, st, sid, q.Action, q.Resource, nullableJSON(q.Context), contextualTuplesArg(q.ContextualTuples), q.Limit, nullable(q.After)}
		} else {
			sql = `SELECT object_id, is_wildcard FROM authz.list_objects($1, $2, $3, $4, $5, $6::jsonb, $7, 0, $8)`
			args = []any{store, st, sid, q.Action, q.Resource, nullableJSON(q.Context), q.Limit, nullable(q.After)}
		}
	case "subjects":
		ot, oid, ok := splitRef(q.Resource)
		if !ok || q.Action == "" || q.Subject == "" {
			writeError(w, http.StatusBadRequest, "subjects mode needs the subject type, action and resource (type:id)")
			return
		}
		if ctx {
			sql = `SELECT subject_id, is_wildcard FROM authz.list_subjects_with_contextual_tuples_jsonb($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, 0, $9)`
			args = []any{store, q.Subject, q.Action, ot, oid, nullableJSON(q.Context), contextualTuplesArg(q.ContextualTuples), q.Limit, nullable(q.After)}
		} else {
			sql = `SELECT subject_id, is_wildcard FROM authz.list_subjects($1, $2, $3, $4, $5, $6::jsonb, $7, 0, $8)`
			args = []any{store, q.Subject, q.Action, ot, oid, nullableJSON(q.Context), q.Limit, nullable(q.After)}
		}
	default:
		writeError(w, http.StatusBadRequest, "mode must be objects or subjects")
		return
	}
	type hit struct {
		ID       string `json:"id"`
		Wildcard bool   `json:"wildcard"`
	}
	hits := []hit{}
	err = s.recordTest(r.Context(), p, store, map[string]any{"op": "search", "mode": q.Mode, "subject": q.Subject, "action": q.Action, "resource": q.Resource, "contextual_tuples": len(q.ContextualTuples)}, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h hit
			if err := rows.Scan(&h.ID, &h.Wildcard); err != nil {
				return err
			}
			hits = append(hits, h)
		}
		return rows.Err()
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	next := ""
	if len(hits) == q.Limit {
		next = hits[len(hits)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": q.Mode, "hits": hits, "next": next, "limit": q.Limit})
}

// ── As me, through pgauthzd: the real PEP path, OPA included ───────────────

type decideReq struct {
	Action   string          `json:"action"`
	Resource string          `json:"resource"`
	Context  json.RawMessage `json:"context"`
}

// handleDecide — the same question asked the way an application asks it: the
// person's own token to the decision instance (PGAUTHZD_DECISION_URL) with
// X-PGAuthz-Detail, so the answer carries the detail envelope — state,
// reason, and, when OPA fronts the instance, the policy hooks consulted and
// any veto. Self-subject by construction: pgauthzd takes the subject from
// the token (and OPA from the forwarded token), which is also why this mode
// cannot ask about other people — the engine-direct check does that.
func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_run_tests")
	if p == nil {
		return
	}
	if s.cfg.DecisionURL == "" {
		writeError(w, http.StatusServiceUnavailable, "PGAUTHZD_DECISION_URL is not configured")
		return
	}
	se := s.sessionFromReq(r)
	if se == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var q decideReq
	if !decodeJSON(w, r, &q) {
		return
	}
	ot, oid, ok := splitRef(q.Resource)
	if !ok || q.Action == "" {
		writeError(w, http.StatusBadRequest, "action and resource (type:id) are required")
		return
	}
	body := map[string]any{
		"action":   map[string]any{"name": q.Action},
		"resource": map[string]any{"type": ot, "id": oid},
	}
	if c := nullableJSON(q.Context); c != nil {
		body["context"] = json.RawMessage(c.(string))
	}
	raw, _ := json.Marshal(body)
	url := strings.TrimRight(s.cfg.DecisionURL, "/") + "/stores/" + store + "/access/v1/evaluation"
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, url, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+se.accessToken)
	req.Header.Set("X-PGAuthz-Detail", "true")
	resp, err := s.http.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "pgauthzd: "+err.Error())
		return
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		msg := "pgauthzd answered " + resp.Status
		if m, ok := out["message"].(string); ok {
			msg += ": " + m
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": msg, "upstream": out})
		return
	}
	// Who the decision was about, as pgauthzd resolved it from the token.
	subject := map[string]any{"type": claimString(se.accessToken, "subject_type"), "id": p.id}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": out["decision"],
		"detail":   out["context"],
		"subject":  subject,
		"url":      url,
	})
}

// ── Conditions: try one against mocked contexts ────────────────────────────

type evalConditionReq struct {
	Request json.RawMessage `json:"request"` // the request context ($1)
	Stored  json.RawMessage `json:"stored"`  // the tuple's stored context ($2)
}

// handleEvaluateCondition — POST /api/stores/{store}/conditions/{name}/evaluate:
// the condition's expression against a request context and a mocked stored
// context (authz.evaluate_condition), without any tuple. Missing required
// keys and expression errors come back as the engine's message with a 400.
// A test like any other: can_run_tests, recorded in the console's action log.
func (s *Server) handleEvaluateCondition(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_run_tests")
	if p == nil {
		return
	}
	name := r.PathValue("name")
	if !validName.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid condition name")
		return
	}
	var q evalConditionReq
	if !decodeJSON(w, r, &q) {
		return
	}
	req, stored := nullableJSON(q.Request), nullableJSON(q.Stored)
	if req == nil {
		req = "{}"
	}
	if stored == nil {
		stored = "{}"
	}
	var result bool
	err := s.recordTest(r.Context(), p, store, map[string]any{"op": "evaluate_condition", "condition": name}, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT authz.evaluate_condition($1, $2, $3::jsonb, $4::jsonb)`, store, name, req, stored).Scan(&result)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"condition": name, "result": result})
}
