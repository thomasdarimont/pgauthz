package server

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/jackc/pgx/v5"
)

// Namespaces: an application team's slice of a shared store. Types carry a
// namespace (authz.types.namespace); the console store has one object per
// namespace — namespace:<store>/<name> — with roles author and viewer. The
// console checks a model or data change against the namespace of the type it
// touches: a store role allows everything, a namespace role allows what is
// inside that namespace, and store-wide changes (relations, conditions, the
// DSL apply, types without a namespace) need the store role.

var namespaceRoles = []string{"author", "viewer"}
var namespaceCapabilities = []string{"can_view", "can_edit_model", "can_grant"}
var validNamespace = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

func nsObject(store, ns string) string { return store + "/" + ns }

// storeNamespaces — the distinct namespaces the store's types declare.
func (s *Server) storeNamespaces(ctx context.Context, store string) ([]string, error) {
	rows, err := s.engine.Query(ctx, `
		SELECT DISTINCT t.namespace FROM authz.types t JOIN authz.stores st ON st.id = t.store_id
		 WHERE st.name = $1 AND t.namespace IS NOT NULL ORDER BY 1`, store)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			return nil, err
		}
		out = append(out, ns)
	}
	return out, rows.Err()
}

// typeNamespace — the namespace of a type ("" when none or unknown).
func (s *Server) typeNamespace(ctx context.Context, store, typ string) (string, error) {
	var ns *string
	err := s.engine.QueryRow(ctx, `
		SELECT t.namespace FROM authz.types t JOIN authz.stores st ON st.id = t.store_id
		 WHERE st.name = $1 AND t.name = $2`, store, typ).Scan(&ns)
	if err == pgx.ErrNoRows || ns == nil {
		return "", nil
	}
	return *ns, err
}

// namespaceCaps — what the person may do in each namespace of the store, for
// the store screen (the backend decides per operation regardless).
func (s *Server) namespaceCaps(ctx context.Context, p *principal, store string) (map[string]map[string]bool, error) {
	names, err := s.storeNamespaces(ctx, store)
	if err != nil || len(names) == 0 {
		return map[string]map[string]bool{}, err
	}
	ids := make([]string, len(names))
	for i, n := range names {
		ids[i] = nsObject(store, n)
	}
	caps, err := s.capabilities(ctx, p, "namespace", ids, namespaceCapabilities)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{}
	for i, n := range names {
		out[n] = caps[ids[i]]
	}
	return out, nil
}

// scopeError names what the person lacks for a change.
type scopeError struct{ required, object string }

func (e scopeError) Error() string {
	return fmt.Sprintf("you need %s on %s", e.required, e.object)
}

// authorizeScoped — allow when the person holds `cap` on the store, else when
// every touched namespace grants it; a store-wide change (ns == "") needs
// the store role.
func (s *Server) authorizeScoped(ctx context.Context, p *principal, cap, store string, namespaces []string) error {
	return s.authorizeScopedQ(ctx, s.engine, p, cap, store, namespaces)
}

func (s *Server) authorizeScopedQ(ctx context.Context, q querier, p *principal, cap, store string, namespaces []string) error {
	ok, err := s.canQ(ctx, q, p, cap, "store", store)
	if err != nil || ok {
		return err
	}
	if len(namespaces) == 0 {
		return scopeError{cap, "store:" + store}
	}
	seen := map[string]bool{}
	for _, ns := range namespaces {
		if ns == "" {
			return scopeError{cap, "store:" + store + " (a store-wide change)"}
		}
		if seen[ns] {
			continue
		}
		seen[ns] = true
		ok, err := s.canQ(ctx, q, p, cap, "namespace", nsObject(store, ns))
		if err != nil {
			return err
		}
		if !ok {
			return scopeError{cap, "namespace:" + nsObject(store, ns)}
		}
	}
	return nil
}

func writeScopeError(w http.ResponseWriter, err error) bool {
	if se, ok := err.(scopeError); ok {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": se.Error(), "required": se.required, "object": se.object})
		return true
	}
	return false
}

// modelOpNamespace — the namespace a model operation touches ("" = store-wide).
func (s *Server) modelOpNamespace(ctx context.Context, store, op string, e modelEdit) (string, error) {
	switch op {
	case "add_type":
		return e.Namespace, nil
	case "remove_type", "set_type_labels":
		return s.typeNamespace(ctx, store, e.Name)
	case "add_rule", "add_restriction", "add_gate", "remove_gate", "add_grant_rule", "remove_grant_rule":
		return s.typeNamespace(ctx, store, e.ObjectType)
	case "remove_rule":
		var typ string
		err := s.engine.QueryRow(ctx, `SELECT object_type FROM authz.models_view WHERE store = $1 AND id = $2`, store, e.ID).Scan(&typ)
		if err != nil {
			return "", nil // unknown id: the engine will say so; treat as store-wide
		}
		return s.typeNamespace(ctx, store, typ)
	case "remove_restriction":
		var typ string
		err := s.engine.QueryRow(ctx, `SELECT object_type FROM authz.type_restrictions_view WHERE store = $1 AND id = $2`, store, e.ID).Scan(&typ)
		if err != nil {
			return "", nil
		}
		return s.typeNamespace(ctx, store, typ)
	}
	return "", nil // relations, conditions, metadata, payload schemas: store-wide
}

// ── Access to namespaces (Access tab) ──────────────────────────────────────

// handleNamespaces — GET /api/stores/{store}/namespaces: each namespace with
// its role assignments; needs can_view, changing needs can_manage_access.
func (s *Server) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view")
	if p == nil {
		return
	}
	ctx := r.Context()
	names, err := s.storeNamespaces(ctx, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	type nsRow struct {
		Name   string      `json:"name"`
		Access []accessRow `json:"access"`
	}
	out := []nsRow{}
	for _, n := range names {
		list, err := s.accessList(ctx, "namespace", nsObject(store, n), namespaceRoles)
		if err != nil {
			writeEngineError(w, err)
			return
		}
		out = append(out, nsRow{Name: n, Access: list})
	}
	manage, err := s.can(ctx, p, "can_manage_access", "store", store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"namespaces": out, "roles": namespaceRoles, "can_manage": manage})
}

func (s *Server) namespaceTarget(w http.ResponseWriter, r *http.Request) (*principal, string, string) {
	p, store := s.requireStore(w, r, "can_manage_access")
	if p == nil {
		return nil, "", ""
	}
	ns := r.PathValue("ns")
	if !validNamespace.MatchString(ns) {
		writeError(w, http.StatusBadRequest, "invalid namespace")
		return nil, "", ""
	}
	return p, store, ns
}

// handleNamespaceAccessAdd — POST /api/stores/{store}/namespaces/{ns}/access.
// Also writes the two link tuples that let the namespace role open the store.
func (s *Server) handleNamespaceAccessAdd(w http.ResponseWriter, r *http.Request) {
	p, store, ns := s.namespaceTarget(w, r)
	if p == nil {
		return
	}
	req, ok := s.accessInput(w, r, namespaceRoles)
	if !ok {
		return
	}
	ctx := r.Context()
	obj := nsObject(store, ns)
	err := s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"op": "add", "namespace": ns, "access": req}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT authz.write_tuple($1, 'store', $2, 'store', 'namespace', $3)`, s.cfg.ConsoleStore, store, obj); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT authz.write_tuple($1, 'namespace', $2, 'namespace', 'store', $3)`, s.cfg.ConsoleStore, obj, store); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT authz.write_tuple($1, $2, $3, $4, 'namespace', $5, $6)`,
			s.cfg.ConsoleStore, req.SubjectType, req.SubjectID, req.Role, obj, nullable(req.SubjectRelation))
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleNamespaceAccessRemove — POST /api/stores/{store}/namespaces/{ns}/access/remove.
func (s *Server) handleNamespaceAccessRemove(w http.ResponseWriter, r *http.Request) {
	p, store, ns := s.namespaceTarget(w, r)
	if p == nil {
		return
	}
	items, ok := s.accessRemoveInput(w, r, namespaceRoles)
	if !ok {
		return
	}
	ctx := r.Context()
	obj := nsObject(store, ns)
	err := s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"op": "remove", "namespace": ns, "items": items}, func(tx pgx.Tx) error {
		for _, req := range items {
			if _, err := tx.Exec(ctx, `SELECT authz.delete_tuple($1, $2, $3, $4, 'namespace', $5, $6)`,
				s.cfg.ConsoleStore, req.SubjectType, req.SubjectID, req.Role, obj, nullable(req.SubjectRelation)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleNamespaceRename — POST /api/stores/{store}/namespaces/{ns}/rename
// {to}: moves every type of the namespace and the console's role tuples on
// it, in one transaction. A namespace is the set of types naming it, so this
// is the rename. Needs can_edit_model (the types) and can_manage_access (the
// roles) on the store.
func (s *Server) handleNamespaceRename(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_edit_model")
	if p == nil {
		return
	}
	ns := r.PathValue("ns")
	var req struct {
		To string `json:"to"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validNamespace.MatchString(ns) || !validNamespace.MatchString(req.To) || ns == req.To {
		writeError(w, http.StatusBadRequest, "namespace names must be identifiers (letters, digits, _ . -) and differ")
		return
	}
	ctx := r.Context()
	if ok, err := s.can(ctx, p, "can_manage_access", "store", store); err != nil || !ok {
		if err != nil {
			writeEngineError(w, err)
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "renaming a namespace moves its role assignments too", "required": "can_manage_access", "object": "store:" + store})
		return
	}
	var moved int
	// a rename changes the model (the types' namespace) AND moves the
	// namespace's role assignments: both capabilities, re-checked in the tx
	err := s.asPersonAuthorized(ctx, p, s.storeGate(ctx, p, store, "can_edit_model", "can_manage_access"), "can_edit_model", "store", store, map[string]any{"op": "rename_namespace", "from": ns, "to": req.To}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT t.name FROM authz.types t JOIN authz.stores st ON st.id = t.store_id
			 WHERE st.name = $1 AND t.namespace = $2`, store, ns)
		if err != nil {
			return err
		}
		var types []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				return err
			}
			types = append(types, n)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, typ := range types {
			if _, err := tx.Exec(ctx, `SELECT authz.model_set_type_namespace($1, $2, $3)`, store, typ, req.To); err != nil {
				return err
			}
		}
		moved = len(types)
		// console roles and link tuples follow the name
		from, to := nsObject(store, ns), nsObject(store, req.To)
		arows, err := tx.Query(ctx, `
			SELECT ut.name, t.user_id, coalesce(ur.name,''), rl.name
			  FROM authz.tuples t
			  JOIN authz.stores s ON s.id = t.store_id
			  JOIN authz.types ot ON ot.id = t.object_type
			  JOIN authz.relations rl ON rl.id = t.relation
			  JOIN authz.types ut ON ut.id = t.user_type
			  LEFT JOIN authz.relations ur ON ur.id = t.user_relation
			 WHERE s.name = $1 AND ot.name = 'namespace' AND t.object_id = $2`, s.cfg.ConsoleStore, from)
		if err != nil {
			return err
		}
		var roles [][4]string
		for arows.Next() {
			var x [4]string
			if err := arows.Scan(&x[0], &x[1], &x[2], &x[3]); err != nil {
				arows.Close()
				return err
			}
			roles = append(roles, x)
		}
		arows.Close()
		if err := arows.Err(); err != nil {
			return err
		}
		for _, x := range roles {
			if _, err := tx.Exec(ctx, `SELECT authz.delete_tuple($1, $2, $3, $4, 'namespace', $5, $6)`, s.cfg.ConsoleStore, x[0], x[1], x[3], from, nullable(x[2])); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT authz.write_tuple($1, $2, $3, $4, 'namespace', $5, $6)`, s.cfg.ConsoleStore, x[0], x[1], x[3], to, nullable(x[2])); err != nil {
				return err
			}
		}
		if len(roles) > 0 {
			_, _ = tx.Exec(ctx, `SELECT authz.delete_tuple($1, 'store', $2, 'store', 'namespace', $3)`, s.cfg.ConsoleStore, store, from)
			if _, err := tx.Exec(ctx, `SELECT authz.write_tuple($1, 'store', $2, 'store', 'namespace', $3)`, s.cfg.ConsoleStore, store, to); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT authz.write_tuple($1, 'namespace', $2, 'namespace', 'store', $3)`, s.cfg.ConsoleStore, to, store); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "from": ns, "to": req.To, "types_moved": moved})
}
