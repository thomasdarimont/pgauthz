package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"thomasdarimont.de/authz/pgauthzadm"
)

type ruleRow struct {
	ID                  int     `json:"id"`
	ObjectType          string  `json:"object_type"`
	Relation            string  `json:"relation"`
	RuleType            string  `json:"rule_type"`
	ComputedRelation    *string `json:"computed_relation"`
	TuplesetRelation    *string `json:"tupleset_relation"`
	TuplesetComputed    *string `json:"tupleset_computed"`
	GroupID             int     `json:"group_id"`
	GroupOp             string  `json:"group_op"`
	Negated             bool    `json:"negated"`
	AllowObjectWildcard bool    `json:"allow_object_wildcard"`
}

type restrictionRow struct {
	ID                  int     `json:"id"`
	ObjectType          string  `json:"object_type"`
	Relation            string  `json:"relation"`
	AllowedUserType     string  `json:"allowed_user_type"`
	AllowedUserRelation *string `json:"allowed_user_relation"`
	AllowWildcard       bool    `json:"allow_wildcard"`
	Condition           *string `json:"condition"`
}

// handleModel — the three read views of a store's model (DSL, JSON, SQL) plus
// the structured parts with ids, which the editor needs to remove things.
func (s *Server) handleModel(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view")
	if p == nil {
		return
	}
	ctx := r.Context()
	m, err := pgauthzadm.ExportModel(ctx, s.engine, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	dsl, err := pgauthzadm.DescribeModel(ctx, s.engine, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	rules, err := s.rules(ctx, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	restrictions, err := s.restrictions(ctx, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	times, err := s.conditionTimes(ctx, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dsl":             dsl,
		"json":            m,
		"sql":             pgauthzadm.RenderSQL(store, m),
		"rules":           rules,
		"restrictions":    restrictions,
		"condition_times": times, // name → {created_at, updated_at}; not part of the model definition
	})
}

func (s *Server) rules(ctx context.Context, store string) ([]ruleRow, error) {
	rows, err := s.engine.Query(ctx, `
		SELECT id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed,
		       group_id, group_op, negated, allow_object_wildcard
		  FROM authz.models_view WHERE store = $1 ORDER BY object_type, relation, group_id, id`, store)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ruleRow{}
	for rows.Next() {
		var x ruleRow
		if err := rows.Scan(&x.ID, &x.ObjectType, &x.Relation, &x.RuleType, &x.ComputedRelation, &x.TuplesetRelation,
			&x.TuplesetComputed, &x.GroupID, &x.GroupOp, &x.Negated, &x.AllowObjectWildcard); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Server) restrictions(ctx context.Context, store string) ([]restrictionRow, error) {
	rows, err := s.engine.Query(ctx, `
		SELECT id, object_type, relation, allowed_user_type, allowed_user_relation, allow_wildcard, condition
		  FROM authz.type_restrictions_view WHERE store = $1 ORDER BY object_type, relation, allowed_user_type, id`, store)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []restrictionRow{}
	for rows.Next() {
		var x restrictionRow
		if err := rows.Scan(&x.ID, &x.ObjectType, &x.Relation, &x.AllowedUserType, &x.AllowedUserRelation, &x.AllowWildcard, &x.Condition); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// modelEdit is the union of the structured editor's operations; each op uses
// the fields it needs (the engine validates the rest).
type modelEdit struct {
	Name                string          `json:"name"`        // type / relation / condition name
	Description         string          `json:"description"` //
	Namespace           string          `json:"namespace"`   // add_type: the namespace the type belongs to (optional)
	Kind                string          `json:"kind"`        // add_relation / set_relation_kind: relation | permission
	Metadata            json.RawMessage `json:"metadata"`    // set_relation_metadata: keys to merge (ui_order, label, …)
	ObjectType          string          `json:"object_type"` //
	Relation            string          `json:"relation"`    //
	RuleType            string          `json:"rule_type"`   // direct | computed | ttu
	ComputedRelation    string          `json:"computed_relation"`
	TuplesetRelation    string          `json:"tupleset_relation"`
	TuplesetComputed    string          `json:"tupleset_computed"`
	GroupID             int             `json:"group_id"`
	GroupOp             string          `json:"group_op"` // or | intersection | exclusion
	Negated             bool            `json:"negated"`
	AllowObjectWildcard bool            `json:"allow_object_wildcard"`
	AllowedUserType     string          `json:"allowed_user_type"`
	AllowedUserRelation string          `json:"allowed_user_relation"`
	AllowWildcard       bool            `json:"allow_wildcard"`
	Condition           string          `json:"condition"`
	Expression          string          `json:"expression"`
	Lang                string          `json:"lang"`
	RequiredContext     json.RawMessage `json:"required_context"`
	Spec                json.RawMessage `json:"spec"` // add_gate: the gate object (all_of, description, mode)
	ID                  int             `json:"id"`   // rule / restriction id to remove
	Force               bool            `json:"force"`
}

// modelEditSQL maps one editor operation onto the engine call that performs
// it. The engine's model_* functions are the editor's only vocabulary, so
// what the console can express is exactly what the SQL API can (no new DSL).
func modelEditSQL(store, op string, e modelEdit) (sql string, args []any, ok bool) {
	switch op {
	case "add_type":
		sql, args = `SELECT authz.model_register_type($1, $2, p_namespace => $3, p_description => $4)`, []any{store, e.Name, nullable(e.Namespace), nullable(e.Description)}
	case "remove_type":
		sql, args = `SELECT authz.model_remove_type($1, $2, $3)`, []any{store, e.Name, e.Force}
	case "set_type_namespace": // move a type into / out of a namespace; store-wide (see modelOpNamespace)
		sql, args = `SELECT authz.model_set_type_namespace($1, $2, $3)`, []any{store, e.Name, e.Namespace}
	case "add_relation":
		var md any
		if e.Kind != "" {
			md = `{"kind": "` + e.Kind + `"}` // the engine validates the value
		}
		sql, args = `SELECT authz.model_register_relation($1, $2, $3, $4::jsonb)`, []any{store, e.Name, nullable(e.Description), md}
	case "set_relation_metadata":
		md := nullableJSON(e.Metadata)
		if md == nil {
			return "", nil, false
		}
		sql, args = `SELECT authz.model_set_relation_metadata($1, $2, $3::jsonb)`, []any{store, e.Name, md}
	case "set_relation_kind":
		if e.Kind != "relation" && e.Kind != "permission" {
			return "", nil, false
		}
		sql, args = `SELECT authz.model_set_relation_metadata($1, $2, $3::jsonb)`, []any{store, e.Name, `{"kind": "` + e.Kind + `"}`}
	case "add_rule":
		if e.GroupOp == "" {
			e.GroupOp = "or"
		}
		sql = `SELECT authz.model_add_rule($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
		args = []any{store, e.ObjectType, e.Relation, e.RuleType, nullable(e.ComputedRelation), nullable(e.TuplesetRelation),
			nullable(e.TuplesetComputed), e.GroupID, e.GroupOp, e.Negated, e.AllowObjectWildcard}
	case "remove_rule":
		sql, args = `SELECT authz.model_remove_rule($1, $2)`, []any{store, e.ID}
	case "add_restriction":
		sql = `SELECT authz.model_add_type_restriction($1, $2, $3, $4, $5, $6, $7)`
		args = []any{store, e.ObjectType, e.Relation, e.AllowedUserType, nullable(e.AllowedUserRelation), e.AllowWildcard, nullable(e.Condition)}
	case "remove_restriction":
		sql, args = `SELECT authz.model_remove_type_restriction($1, $2)`, []any{store, e.ID}
	case "add_condition":
		if e.Lang == "" {
			e.Lang = "sql"
		}
		sql = `SELECT authz.create_condition($1, $2, $3, $4, $5::jsonb, p_description => $6)`
		args = []any{store, e.Name, strings.TrimSpace(e.Expression), e.Lang, nullableJSON(e.RequiredContext), e.Description}
	case "remove_condition":
		sql, args = `SELECT authz.delete_condition($1, $2)`, []any{store, e.Name}
	case "add_gate": // create or replace (add_gate upserts by name; an identical spec is a no-op)
		sql = `SELECT authz.add_gate($1, $2, $3, $4, $5::jsonb)`
		args = []any{store, e.ObjectType, e.Relation, e.Name, nullableJSON(e.Spec)}
	case "remove_gate":
		sql, args = `SELECT authz.drop_gate($1, $2, $3, $4)`, []any{store, e.ObjectType, e.Relation, e.Name}
	default:
		return "", nil, false
	}
	return sql, args, true
}

// handleModelEdit — one structured change to the live model, as the person.
func (s *Server) handleModelEdit(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view") // the scope check below decides
	if p == nil {
		return
	}
	var e modelEdit
	if !decodeJSON(w, r, &e) {
		return
	}
	op := r.PathValue("op")
	ctx := r.Context()
	sql, args, ok := modelEditSQL(store, op, e)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown model operation: "+op)
		return
	}
	ns, err := s.modelOpNamespace(ctx, store, op, e)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if err := s.authorizeScoped(ctx, p, "can_edit_model", store, []string{ns}); err != nil {
		if !writeScopeError(w, err) {
			writeEngineError(w, err)
		}
		return
	}
	err = s.asPerson(ctx, p, "can_edit_model", "store", store, map[string]any{"op": op, "edit": e}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "op": op})
}

type modelBatchReq struct {
	Ops []modelBatchOp `json:"ops"`
}

type modelBatchOp struct {
	Op string `json:"op"`
	modelEdit
}

// handleModelBatch — several editor operations in ONE transaction (the
// selection's "remove selected"): all or nothing, one console event naming
// every operation, so a bulk removal is as attributable as a single one.
func (s *Server) handleModelBatch(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view") // the scope check below decides
	if p == nil {
		return
	}
	var req modelBatchReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Ops) == 0 || len(req.Ops) > 500 {
		writeError(w, http.StatusBadRequest, "ops must hold 1 to 500 operations")
		return
	}
	ctx := r.Context()
	type planned struct {
		sql  string
		args []any
	}
	plan := make([]planned, 0, len(req.Ops))
	touched := make([]string, 0, len(req.Ops))
	for i, op := range req.Ops {
		ns, err := s.modelOpNamespace(ctx, store, op.Op, op.modelEdit)
		if err != nil {
			writeEngineError(w, err)
			return
		}
		touched = append(touched, ns)
		sql, args, ok := modelEditSQL(store, op.Op, op.modelEdit)
		if !ok {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("ops[%d]: unknown model operation: %s", i, op.Op))
			return
		}
		plan = append(plan, planned{sql, args})
	}
	if err := s.authorizeScoped(ctx, p, "can_edit_model", store, touched); err != nil {
		if !writeScopeError(w, err) {
			writeEngineError(w, err)
		}
		return
	}
	err := s.asPerson(ctx, p, "can_edit_model", "store", store, map[string]any{"op": "batch", "ops": req.Ops}, func(tx pgx.Tx) error {
		for i, pl := range plan {
			if _, err := tx.Exec(ctx, pl.sql, pl.args...); err != nil {
				return fmt.Errorf("ops[%d] (%s): %w", i, req.Ops[i].Op, err)
			}
		}
		return nil
	})
	if err != nil {
		// Name the failing operation: the engine message alone ("Unknown
		// relation: member") does not say which of many ops raised it.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": pgErr.Code})
			return
		}
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": len(plan)})
}

type modelDSLReq struct {
	DSL string `json:"dsl"`
}

// handleModelDSL — the whole model from DSL text (the console's "Edit as
// DSL"): parsed by pgauthzadm.ParseDSL, loaded by authz.import_openfga_model
// in one transaction as the person. Types and relations are added, rules and
// type restrictions replaced; conditions, gates and grant rules are untouched.
func (s *Server) handleModelDSL(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_edit_model")
	if p == nil {
		return
	}
	var req modelDSLReq
	if !decodeJSON(w, r, &req) {
		return
	}
	modelJSON, warnings, err := pgauthzadm.ParseDSL(req.DSL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var report *pgauthzadm.ImportReport
	err = s.asPerson(r.Context(), p, "can_edit_model", "store", store, map[string]any{"op": "dsl", "bytes": len(req.DSL)}, func(tx pgx.Tx) error {
		var err error
		report, err = pgauthzadm.ImportModel(r.Context(), tx, store, modelJSON)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	report.Warnings = append(report.Warnings, warnings...)
	writeJSON(w, http.StatusOK, report)
}

// conditionTimes — when each condition of the store was created and last
// changed (migration 0021), keyed by name.
func (s *Server) conditionTimes(ctx context.Context, store string) (map[string]map[string]time.Time, error) {
	rows, err := s.engine.Query(ctx, `
		SELECT c.name, c.created_at, c.updated_at
		  FROM authz.conditions c JOIN authz.stores st ON st.id = c.store_id
		 WHERE st.name = $1`, store)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]time.Time{}
	for rows.Next() {
		var name string
		var created, updated time.Time
		if err := rows.Scan(&name, &created, &updated); err != nil {
			return nil, err
		}
		out[name] = map[string]time.Time{"created_at": created, "updated_at": updated}
	}
	return out, rows.Err()
}
