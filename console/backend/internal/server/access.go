package server

// The Access tab: who may do what with a store IN THE CONSOLE. These are
// plain tuples of the console store (user:alice owner store:demo,
// team:role_x#member tester store:demo), written with the engine's tuple API
// under a can_manage_access gate. The one invariant the console adds: a store
// never ends up without an owner (the platform admin can still step in
// through the platform tuple, so nothing is ever orphaned).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// storeRoles are the assignable console roles on a store, in display order.
var storeRoles = []string{"owner", "author", "publisher", "sharer", "tester", "supporter", "auditor", "exporter", "viewer"}

var platformRoles = []string{"admin", "issuer_admin"}

type accessRow struct {
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	SubjectRelation string `json:"subject_relation"` // "member" for team#member
	Role            string `json:"role"`
	Subject         string `json:"subject"` // rendered: user:alice or team:x#member
}

type accessReq struct {
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	SubjectRelation string `json:"subject_relation"`
	Role            string `json:"role"`
}

func (s *Server) accessList(ctx context.Context, objectType, objectID string, roles []string) ([]accessRow, error) {
	rows, err := s.engine.Query(ctx, `
		SELECT ut.name, t.user_id, coalesce(ur.name,''), rl.name
		  FROM authz.tuples t
		  JOIN authz.stores s ON s.id = t.store_id
		  JOIN authz.types ot ON ot.id = t.object_type
		  JOIN authz.relations rl ON rl.id = t.relation
		  JOIN authz.types ut ON ut.id = t.user_type
		  LEFT JOIN authz.relations ur ON ur.id = t.user_relation
		 WHERE s.name = $1 AND ot.name = $2 AND t.object_id = $3 AND rl.name = ANY($4::text[])
		 ORDER BY array_position($4::text[], rl.name), ut.name, t.user_id`, s.cfg.ConsoleStore, objectType, objectID, roles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []accessRow{}
	for rows.Next() {
		var a accessRow
		if err := rows.Scan(&a.SubjectType, &a.SubjectID, &a.SubjectRelation, &a.Role); err != nil {
			return nil, err
		}
		a.Subject = a.SubjectType + ":" + a.SubjectID
		if a.SubjectRelation != "" {
			a.Subject += "#" + a.SubjectRelation
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view")
	if p == nil {
		return
	}
	list, err := s.accessList(r.Context(), "store", store, storeRoles)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	manage, err := s.can(r.Context(), p, "can_manage_access", "store", store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access": list, "roles": storeRoles, "can_manage": manage, "teams": p.teams})
}

func (s *Server) accessInput(w http.ResponseWriter, r *http.Request, roles []string) (accessReq, bool) {
	var req accessReq
	if !decodeJSON(w, r, &req) {
		return req, false
	}
	okRole := false
	for _, x := range roles {
		okRole = okRole || x == req.Role
	}
	if req.SubjectType == "" || req.SubjectID == "" || !okRole {
		writeError(w, http.StatusBadRequest, "subject_type, subject_id and a valid role are required")
		return req, false
	}
	return req, true
}

func (s *Server) handleAccessAdd(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_manage_access")
	if p == nil {
		return
	}
	req, ok := s.accessInput(w, r, storeRoles)
	if !ok {
		return
	}
	err := s.asPerson(r.Context(), p, "can_manage_access", "store", store, map[string]any{"op": "add", "access": req}, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `SELECT authz.write_tuple($1, $2, $3, $4, 'store', $5, $6)`,
			s.cfg.ConsoleStore, req.SubjectType, req.SubjectID, req.Role, store, nullable(req.SubjectRelation))
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// accessRemoveInput accepts one role assignment or {items: [...]}.
func (s *Server) accessRemoveInput(w http.ResponseWriter, r *http.Request, roles []string) ([]accessReq, bool) {
	var raw map[string]json.RawMessage
	if !decodeJSON(w, r, &raw) {
		return nil, false
	}
	var items []accessReq
	if list, ok := raw["items"]; ok {
		if err := json.Unmarshal(list, &items); err != nil {
			writeError(w, http.StatusBadRequest, "items must be a list")
			return nil, false
		}
	} else {
		body, _ := json.Marshal(raw)
		var one accessReq
		if err := json.Unmarshal(body, &one); err != nil {
			writeError(w, http.StatusBadRequest, "bad role assignment")
			return nil, false
		}
		items = []accessReq{one}
	}
	if len(items) == 0 || len(items) > 200 {
		writeError(w, http.StatusBadRequest, "1 to 200 assignments per request")
		return nil, false
	}
	for _, it := range items {
		okRole := false
		for _, x := range roles {
			okRole = okRole || x == it.Role
		}
		if it.SubjectType == "" || it.SubjectID == "" || !okRole {
			writeError(w, http.StatusBadRequest, "subject_type, subject_id and a valid role are required")
			return nil, false
		}
	}
	return items, true
}

func (s *Server) handleAccessRemove(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_manage_access")
	if p == nil {
		return
	}
	items, ok := s.accessRemoveInput(w, r, storeRoles)
	if !ok {
		return
	}
	ctx := r.Context()
	err := s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"op": "remove", "items": items}, func(tx pgx.Tx) error {
		for _, req := range items {
			if _, err := tx.Exec(ctx, `SELECT authz.delete_tuple($1, $2, $3, $4, 'store', $5, $6)`,
				s.cfg.ConsoleStore, req.SubjectType, req.SubjectID, req.Role, store, nullable(req.SubjectRelation)); err != nil {
				return err
			}
		}
		return s.ensureOwner(ctx, tx, "store", store)
	})
	if err != nil {
		if isLastOwner(err) {
			writeError(w, http.StatusConflict, "a store needs at least one owner — add another owner first")
			return
		}
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type ownerError string

func (e ownerError) Error() string { return string(e) }

const errLastOwner = ownerError("last owner")

// isLastOwner: the removal would leave the object without an owner — either
// the console's own check (ensureOwner) or the engine's relation floor
// (min_direct on store.owner / platform.admin in the console model, SQLSTATE
// ZA002), which refuses the delete itself when the model declares it.
func isLastOwner(err error) bool {
	if err == errLastOwner {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "ZA002"
}

// ensureOwner fails the transaction when the object would be left with no
// owner (store) / admin (platform) tuple.
func (s *Server) ensureOwner(ctx context.Context, tx pgx.Tx, objectType, objectID string) error {
	role := "owner"
	if objectType == "platform" {
		role = "admin"
	}
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuples t
		  JOIN authz.stores s ON s.id = t.store_id
		  JOIN authz.types ot ON ot.id = t.object_type
		  JOIN authz.relations rl ON rl.id = t.relation
		 WHERE s.name = $1 AND ot.name = $2 AND t.object_id = $3 AND rl.name = $4`,
		s.cfg.ConsoleStore, objectType, objectID, role).Scan(&n)
	if err != nil {
		return err
	}
	if n == 0 {
		return errLastOwner
	}
	return nil
}
