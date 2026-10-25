package server

// Batch work on a store's tuples: export (JSON, CSV, OpenFGA), import
// (the same three shapes, detected from the text; preview, then one
// transaction as the person, scoped by the namespaces of the object types
// touched like every Data-tab write), and offboarding (every tuple of one
// subject, delete_user_tuples).

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const importMax = 10000

// exportRows reads every tuple of the store in a stable order, on q.
func (s *Server) exportRows(ctx context.Context, q querier, store string) ([]tupleRow, error) {
	rows, err := q.Query(ctx, `
		SELECT ut.name, t.user_id, coalesce(ur.name,''), rl.name, ot.name, t.object_id,
		       coalesce(c.name,''), coalesce(t.condition_context, 'null'::jsonb), t.expires_at::text
		  FROM authz.tuples t
		  JOIN authz.stores s ON s.id = t.store_id
		  JOIN authz.types ut ON ut.id = t.user_type
		  JOIN authz.types ot ON ot.id = t.object_type
		  JOIN authz.relations rl ON rl.id = t.relation
		  LEFT JOIN authz.relations ur ON ur.id = t.user_relation
		  LEFT JOIN authz.conditions c ON c.id = t.condition_id
		 WHERE s.name = $1
		 ORDER BY ot.name, t.object_id, rl.name, ut.name, t.user_id, ur.name`, store)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []tupleRow{}
	for rows.Next() {
		var t tupleRow
		if err := rows.Scan(&t.UserType, &t.UserID, &t.UserRelation, &t.Relation, &t.ObjectType, &t.ObjectID,
			&t.ConditionName, &t.ConditionContext, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

var csvHeader = []string{"user_type", "user_id", "user_relation", "relation", "object_type", "object_id", "condition", "condition_context", "expires_at"}

// handleTuplesExport — GET .../tuples/export?format=json|csv|openfga: the
// store's tuples as a file. json is the native shape (what import and
// write_tuples_jsonb take: conditions, context and expiry included), csv
// the same columns for a spreadsheet, openfga the ReadTuples shape.
//
// Authorization data leaving the system is sensitive: the export needs its
// own capability (can_export: the exporter role, owners) and is recorded
// in the console's action log like a change — who, when, which store,
// which format, how many rows — before the rows are read.
func (s *Server) handleTuplesExport(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_export")
	if p == nil {
		return
	}
	ctx := r.Context()
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "openfga" {
		format = "json"
	}
	var count int
	if err := s.engine.QueryRow(ctx, `SELECT count(*) FROM authz.tuples t JOIN authz.stores s ON s.id = t.store_id WHERE s.name = $1`, store).Scan(&count); err != nil {
		writeEngineError(w, err)
		return
	}
	var rows []tupleRow
	err := s.asPerson(ctx, p, "can_export", "store", store, map[string]any{"op": "export", "format": format, "count": count}, func(tx pgx.Tx) error {
		var err error
		rows, err = s.exportRows(ctx, tx, store)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	switch format {
	case "csv":
		var buf bytes.Buffer
		cw := csv.NewWriter(&buf)
		_ = cw.Write(csvHeader)
		for _, t := range rows {
			ctxText := ""
			if len(t.ConditionContext) > 0 && string(t.ConditionContext) != "null" {
				ctxText = string(t.ConditionContext)
			}
			exp := ""
			if t.ExpiresAt != nil {
				exp = *t.ExpiresAt
			}
			_ = cw.Write([]string{t.UserType, t.UserID, t.UserRelation, t.Relation, t.ObjectType, t.ObjectID, t.ConditionName, ctxText, exp})
		}
		cw.Flush()
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-tuples-%s.csv"`, store, stamp))
		_, _ = w.Write(buf.Bytes())
	case "openfga":
		type key struct {
			User     string `json:"user"`
			Relation string `json:"relation"`
			Object   string `json:"object"`
		}
		type entry struct {
			Key key `json:"key"`
		}
		list := make([]entry, 0, len(rows))
		for _, t := range rows {
			user := t.UserType + ":" + t.UserID
			if t.UserRelation != "" {
				user += "#" + t.UserRelation
			}
			list = append(list, entry{key{user, t.Relation, t.ObjectType + ":" + t.ObjectID}})
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-tuples-openfga-%s.json"`, store, stamp))
		_ = json.NewEncoder(w).Encode(map[string]any{"tuples": list})
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-tuples-%s.json"`, store, stamp))
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
	}
}

// parseTuples turns pasted or uploaded text into tuples, detecting the
// shape: a JSON array of native tuples, an OpenFGA ReadTuples object
// ({"tuples": [{"key": {user, relation, object}}]}), or CSV with the
// export's header. Returns the tuples and the shape name.
func parseTuples(text string) ([]tupleReq, string, error) {
	text = strings.TrimSpace(strings.TrimPrefix(text, "\uFEFF"))
	if text == "" {
		return nil, "", errors.New("nothing to import")
	}
	switch text[0] {
	case '[':
		var list []tupleReq
		if err := json.Unmarshal([]byte(text), &list); err != nil {
			return nil, "", fmt.Errorf("JSON array: %w", err)
		}
		return list, "json", nil
	case '{':
		var doc struct {
			Tuples []struct {
				Key struct {
					User     string `json:"user"`
					Relation string `json:"relation"`
					Object   string `json:"object"`
				} `json:"key"`
			} `json:"tuples"`
		}
		if err := json.Unmarshal([]byte(text), &doc); err != nil {
			return nil, "", fmt.Errorf("OpenFGA JSON: %w", err)
		}
		out := make([]tupleReq, 0, len(doc.Tuples))
		for i, e := range doc.Tuples {
			ut, uid, urel, ok := splitSubject(e.Key.User)
			ot, oid, _, ok2 := splitSubject(e.Key.Object)
			if !ok || !ok2 || e.Key.Relation == "" {
				return nil, "", fmt.Errorf("tuples[%d]: user and object must be type:id (user may be type:id#relation or type:*)", i)
			}
			out = append(out, tupleReq{UserType: ut, UserID: uid, UserRelation: urel, Relation: e.Key.Relation, ObjectType: ot, ObjectID: oid})
		}
		return out, "openfga", nil
	default:
		cr := csv.NewReader(strings.NewReader(text))
		cr.FieldsPerRecord = -1
		cr.TrimLeadingSpace = true
		head, err := cr.Read()
		if err != nil {
			return nil, "", fmt.Errorf("CSV: %w", err)
		}
		col := map[string]int{}
		for i, h := range head {
			col[strings.ToLower(strings.TrimSpace(h))] = i
		}
		for _, need := range []string{"user_type", "user_id", "relation", "object_type", "object_id"} {
			if _, ok := col[need]; !ok {
				return nil, "", fmt.Errorf("CSV: the header must name %s (and may name user_relation, condition, condition_context, expires_at)", need)
			}
		}
		get := func(rec []string, name string) string {
			if i, ok := col[name]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		out := []tupleReq{}
		for line := 2; ; line++ {
			rec, err := cr.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, "", fmt.Errorf("CSV line %d: %w", line, err)
			}
			if len(rec) == 0 || (len(rec) == 1 && strings.TrimSpace(rec[0]) == "") {
				continue
			}
			t := tupleReq{UserType: get(rec, "user_type"), UserID: get(rec, "user_id"), UserRelation: get(rec, "user_relation"), Relation: get(rec, "relation"),
				ObjectType: get(rec, "object_type"), ObjectID: get(rec, "object_id"), Condition: get(rec, "condition"), ExpiresAt: get(rec, "expires_at")}
			if c := get(rec, "condition_context"); c != "" {
				if !json.Valid([]byte(c)) {
					return nil, "", fmt.Errorf("CSV line %d: condition_context is not JSON", line)
				}
				t.ConditionContext = json.RawMessage(c)
			}
			out = append(out, t)
		}
		return out, "csv", nil
	}
}

// splitSubject parses OpenFGA notation: "type:id", "type:id#relation",
// "type:*". Returns type, id, relation.
func splitSubject(s string) (typ, id, rel string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", "", false
	}
	typ, rest := s[:i], s[i+1:]
	if j := strings.IndexByte(rest, '#'); j >= 0 {
		return typ, rest[:j], rest[j+1:], rest[:j] != "" && rest[j+1:] != ""
	}
	return typ, rest, "", true
}

type importReq struct {
	Text  string `json:"text"`
	Apply bool   `json:"apply"` // false: parse and report; true: write in one transaction
}

// handleTuplesImport — POST .../tuples/import: parse the text (JSON, OpenFGA
// or CSV); apply=false returns what was understood (count, shape, the first
// rows, the namespaces touched), apply=true writes everything with
// write_tuples_jsonb in one transaction as the person, which the namespace
// scope of every object type touched must allow (can_grant).
func (s *Server) handleTuplesImport(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view") // the scope check below decides
	if p == nil {
		return
	}
	var req importReq
	if !decodeJSON(w, r, &req) {
		return
	}
	tuples, shape, err := parseTuples(req.Text)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(tuples) == 0 || len(tuples) > importMax {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("1 to %d tuples per import", importMax))
		return
	}
	for i, t := range tuples {
		if !t.valid() {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("tuple %d: user_type, user_id, relation, object_type, object_id are required", i+1))
			return
		}
	}
	ctx := r.Context()
	// the namespaces of the object types touched (each once)
	nsOf := map[string]string{}
	touched := []string{}
	for _, t := range tuples {
		if _, seen := nsOf[t.ObjectType]; seen {
			continue
		}
		ns, err := s.typeNamespace(ctx, store, t.ObjectType)
		if err != nil {
			writeEngineError(w, err)
			return
		}
		nsOf[t.ObjectType] = ns
		touched = append(touched, ns)
	}
	if err := s.authorizeScoped(ctx, p, "can_grant", store, touched); err != nil {
		if !writeScopeError(w, err) {
			writeEngineError(w, err)
		}
		return
	}
	types := make([]string, 0, len(nsOf))
	for ty := range nsOf {
		types = append(types, ty)
	}
	if !req.Apply {
		preview := tuples
		if len(preview) > 50 {
			preview = preview[:50]
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": len(tuples), "shape": shape, "object_types": types, "preview": preview, "applied": false})
		return
	}
	raw, _ := json.Marshal(tuples)
	var n int
	err = s.asPersonScoped(ctx, p, "can_grant", "store", store, touched, map[string]any{"op": "import", "shape": shape, "count": len(tuples), "object_types": types}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT authz.write_tuples_jsonb($1, $2::jsonb, $3)`, store, raw, p.typ+":"+p.id).Scan(&n)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(tuples), "shape": shape, "written": n, "applied": true})
}

type offboardReq struct {
	UserType string `json:"user_type"`
	UserID   string `json:"user_id"`
	Apply    bool   `json:"apply"`
}

// handleOffboard — POST .../tuples/offboard: every tuple whose subject is
// this one (as a direct subject or through a userset), counted first
// (apply=false), then removed with delete_user_tuples as the person
// (apply=true). Store-wide, so it needs the store-level can_grant.
func (s *Server) handleOffboard(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_grant")
	if p == nil {
		return
	}
	var req offboardReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.UserType == "" || req.UserID == "" {
		writeError(w, http.StatusBadRequest, "user_type and user_id are required")
		return
	}
	ctx := r.Context()
	var count int
	if err := s.engine.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuples t
		  JOIN authz.stores s ON s.id = t.store_id
		  JOIN authz.types ut ON ut.id = t.user_type
		 WHERE s.name = $1 AND ut.name = $2 AND t.user_id = $3`, store, req.UserType, req.UserID).Scan(&count); err != nil {
		writeEngineError(w, err)
		return
	}
	if !req.Apply {
		writeJSON(w, http.StatusOK, map[string]any{"count": count, "applied": false})
		return
	}
	var n int
	err := s.asPerson(ctx, p, "can_grant", "store", store, map[string]any{"op": "offboard", "subject_type": req.UserType, "subject_id": req.UserID, "count": count}, func(tx pgx.Tx) error {
		// p_force: offboarding is the explicit intent here — the subject
		// leaves even where a relation floor (min_direct) would refuse the
		// revocation of a last owner; relation_usage shows the gap afterwards.
		return tx.QueryRow(ctx, `SELECT authz.delete_user_tuples($1, $2, $3, $4, p_force => true)`, store, req.UserType, req.UserID, p.typ+":"+p.id).Scan(&n)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": count, "removed": n, "applied": true})
}
