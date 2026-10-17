package server

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"thomasdarimont.de/authz/pgauthzadm"
)

type storeRow struct {
	Name         string                     `json:"name"`
	Description  string                     `json:"description"`
	DocsURL      string                     `json:"docs_url"`
	Namespaces   map[string]map[string]bool `json:"namespaces,omitempty"` // what you may do in each namespace (store screen)
	CreatedAt    *time.Time                 `json:"created_at"`
	LastChangeAt *time.Time                 `json:"last_change_at"` // latest model, condition or tuple change in the audit trail
	Capabilities map[string]bool            `json:"capabilities"`
	Status       *pgauthzadm.Status         `json:"status,omitempty"`
	Counts       map[string]int             `json:"counts,omitempty"`
	Claimed      bool                       `json:"claimed"` // has a platform tuple in the console store
}

// allStores lists the engine's live stores with descriptions.
func (s *Server) allStores(ctx context.Context) ([]storeRow, error) {
	rows, err := s.engine.Query(ctx, `
		SELECT s.name, coalesce(s.description,''), coalesce(s.docs_url,''), s.created_at,
		       GREATEST((SELECT max(a.performed_at) FROM authz.tuples_audit a WHERE a.store_id = s.id),
		                (SELECT max(a.performed_at) FROM authz.models_audit a WHERE a.store_id = s.id),
		                (SELECT max(a.performed_at) FROM authz.conditions_audit a WHERE a.store_id = s.id))
		  FROM authz.stores s ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storeRow
	for rows.Next() {
		var r storeRow
		if err := rows.Scan(&r.Name, &r.Description, &r.DocsURL, &r.CreatedAt, &r.LastChangeAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// claimedStores are the store ids that report to the platform in the console
// store (store:X platform platform:default).
func (s *Server) claimedStores(ctx context.Context) (map[string]bool, error) {
	rows, err := s.engine.Query(ctx, `
		SELECT t.object_id FROM authz.tuples t
		  JOIN authz.stores s ON s.id = t.store_id
		  JOIN authz.types ot ON ot.id = t.object_type
		  JOIN authz.relations r ON r.id = t.relation
		  JOIN authz.types ut ON ut.id = t.user_type
		 WHERE s.name = $1 AND ot.name = 'store' AND r.name = 'platform' AND ut.name = 'platform' AND t.user_id = $2`,
		s.cfg.ConsoleStore, s.cfg.PlatformID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// handleStores — the home screen: every store the person can see, with their
// capabilities on it; for a platform admin also the stores no one has claimed
// yet (so they can adopt them).
func (s *Server) handleStores(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	if p == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	ctx := r.Context()
	all, err := s.allStores(ctx)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	ids := make([]string, len(all))
	for i, st := range all {
		ids[i] = st.Name
	}
	caps, err := s.capabilities(ctx, p, "store", ids, homeCapabilities)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	claimed, err := s.claimedStores(ctx)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	admin, err := s.can(ctx, p, "can_view_all_stores", "platform", s.cfg.PlatformID)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	visible, unclaimed := []storeRow{}, []storeRow{}
	for _, st := range all {
		st.Capabilities = caps[st.Name]
		st.Claimed = claimed[st.Name]
		switch {
		case st.Capabilities["can_view"]:
			if status, err := pgauthzadm.ModelStatus(ctx, s.engine, st.Name); err == nil {
				st.Status = status
			}
			visible = append(visible, st)
		case admin && !st.Claimed:
			unclaimed = append(unclaimed, st)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"stores": visible, "unclaimed": unclaimed, "can_create": admin})
}

// handleStore — one store's header: capabilities, managed-model status, sizes.
func (s *Server) handleStore(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view")
	if p == nil {
		return
	}
	ctx := r.Context()
	caps, err := s.capabilities(ctx, p, "store", []string{store}, storeCapabilities)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	nsCaps, err := s.namespaceCaps(ctx, p, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	row := storeRow{Name: store, Capabilities: caps[store], Namespaces: nsCaps, Counts: map[string]int{}}
	_ = s.engine.QueryRow(ctx, `SELECT coalesce(description,''), coalesce(docs_url,'') FROM authz.stores WHERE name=$1`, store).Scan(&row.Description, &row.DocsURL)
	if st, err := pgauthzadm.ModelStatus(ctx, s.engine, store); err == nil {
		row.Status = st
	}
	var types, rels, tuples, conds int
	_ = s.engine.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM authz.types t JOIN authz.stores s ON s.id=t.store_id WHERE s.name=$1),
		       (SELECT count(*) FROM authz.relations r JOIN authz.stores s ON s.id=r.store_id WHERE s.name=$1),
		       (SELECT count(*) FROM authz.tuples t JOIN authz.stores s ON s.id=t.store_id WHERE s.name=$1),
		       (SELECT count(*) FROM authz.conditions c JOIN authz.stores s ON s.id=c.store_id WHERE s.name=$1)`, store).
		Scan(&types, &rels, &tuples, &conds)
	row.Counts = map[string]int{"types": types, "relations": rels, "tuples": tuples, "conditions": conds}
	claimed, _ := s.claimedStores(ctx)
	row.Claimed = claimed[store]
	writeJSON(w, http.StatusOK, row)
}

type createStoreReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// handleCreateStore — platform admins create stores; the creator becomes the
// owner (transferable in the Access tab) and the store reports to the platform.
func (s *Server) handleCreateStore(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_create_store", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	var req createStoreReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validName.MatchString(req.Name) || len(req.Name) > 63 {
		writeError(w, http.StatusBadRequest, "store name must match ^[a-zA-Z_][a-zA-Z0-9_]*$")
		return
	}
	err := s.asPerson(r.Context(), p, "can_create_store", "store", req.Name, map[string]any{"description": req.Description}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `SELECT authz.create_store($1, $2)`, req.Name, nullable(req.Description)); err != nil {
			return err
		}
		return s.claimStore(r.Context(), tx, p, req.Name)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"name": req.Name})
}

// claimStore writes the console tuples that put a store under the platform
// with the principal as its first owner.
func (s *Server) claimStore(ctx context.Context, tx pgx.Tx, p *principal, store string) error {
	if _, err := tx.Exec(ctx, `SELECT authz.write_tuple($1, 'platform', $2, 'platform', 'store', $3)`,
		s.cfg.ConsoleStore, s.cfg.PlatformID, store); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT authz.write_tuple($1, $2, $3, 'owner', 'store', $4)`,
		s.cfg.ConsoleStore, p.typ, p.id, store)
	return err
}

// handleAdoptStore — a platform admin takes an unclaimed store (one created
// outside the console, e.g. by init scripts) under management.
func (s *Server) handleAdoptStore(w http.ResponseWriter, r *http.Request) {
	store := r.PathValue("store")
	if !validName.MatchString(store) {
		writeError(w, http.StatusBadRequest, "invalid store name")
		return
	}
	p := s.require(w, r, "can_view_all_stores", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	ctx := r.Context()
	var exists bool
	if err := s.engine.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM authz.stores WHERE name=$1)`, store).Scan(&exists); err != nil {
		writeEngineError(w, err)
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "no such store")
		return
	}
	claimed, err := s.claimedStores(ctx)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if claimed[store] {
		writeError(w, http.StatusConflict, "store is already managed; use its Access tab")
		return
	}
	err = s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"adopted": true}, func(tx pgx.Tx) error {
		return s.claimStore(ctx, tx, p, store)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": store, "claimed": true})
}

type storeSettingsReq struct {
	Description string `json:"description"`
	DocsURL     string `json:"docs_url"`
}

// handleStoreSettings — description and documentation link (a wiki page, a
// design doc) of a store; owners only. The engine validates the URL.
func (s *Server) handleStoreSettings(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_manage_access")
	if p == nil {
		return
	}
	var req storeSettingsReq
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.asPerson(r.Context(), p, "can_manage_access", "store", store, map[string]any{"op": "settings", "description": req.Description, "docs_url": req.DocsURL}, func(tx pgx.Tx) error {
		// empty string clears, so both values are always sent
		_, err := tx.Exec(r.Context(), `SELECT authz.update_store($1, $2, $3)`, store, req.Description, req.DocsURL)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type deleteStoreReq struct {
	Confirm    string `json:"confirm"`     // must equal the store name
	PurgeAudit bool   `json:"purge_audit"` // also drop the audit history (default: keep)
}

// handleDeleteStore — remove a store (authz.delete_store) and its console
// access tuples, as the person, after the name was typed back. Owners and
// platform admins (can_manage_access). The console store itself is refused.
func (s *Server) handleDeleteStore(w http.ResponseWriter, r *http.Request) {
	store := r.PathValue("store")
	if !validName.MatchString(store) {
		writeError(w, http.StatusBadRequest, "invalid store name")
		return
	}
	p := s.principal(r)
	if p == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	// Owners (and platform admins through the platform tuple) delete claimed
	// stores; an UNCLAIMED store has nobody to ask, so whoever may create
	// stores may remove it.
	allowed, err := s.can(r.Context(), p, "can_manage_access", "store", store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if !allowed {
		claimed, cerr := s.claimedStores(r.Context())
		if cerr != nil {
			writeEngineError(w, cerr)
			return
		}
		if !claimed[store] {
			allowed, err = s.can(r.Context(), p, "can_create_store", "platform", s.cfg.PlatformID)
			if err != nil {
				writeEngineError(w, err)
				return
			}
		}
	}
	if !allowed {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "you are not allowed to delete this store", "required": "can_manage_access", "object": "store:" + store})
		return
	}
	var req deleteStoreReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Confirm != store {
		writeError(w, http.StatusBadRequest, "type the store name to confirm")
		return
	}
	if store == s.cfg.ConsoleStore {
		writeError(w, http.StatusConflict, "the console's own store cannot be deleted from the console")
		return
	}
	ctx := r.Context()
	err = s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"op": "delete_store", "purge_audit": req.PurgeAudit}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT authz.delete_store($1, $2)`, store, req.PurgeAudit); err != nil {
			return err
		}
		// the console's own tuples about this store (platform, owner, roles)
		rows, err := tx.Query(ctx, `
			SELECT ut.name, t.user_id, coalesce(ur.name,''), rl.name
			  FROM authz.tuples t
			  JOIN authz.stores s ON s.id = t.store_id
			  JOIN authz.types ot ON ot.id = t.object_type
			  JOIN authz.relations rl ON rl.id = t.relation
			  JOIN authz.types ut ON ut.id = t.user_type
			  LEFT JOIN authz.relations ur ON ur.id = t.user_relation
			 WHERE s.name = $1 AND ot.name = 'store' AND t.object_id = $2`, s.cfg.ConsoleStore, store)
		if err != nil {
			return err
		}
		type tup struct{ ut, uid, ur, rel string }
		var tuples []tup
		for rows.Next() {
			var x tup
			if err := rows.Scan(&x.ut, &x.uid, &x.ur, &x.rel); err != nil {
				rows.Close()
				return err
			}
			tuples = append(tuples, x)
		}
		rows.Close()
		for _, x := range tuples {
			if _, err := tx.Exec(ctx, `SELECT authz.delete_tuple($1, $2, $3, $4, 'store', $5, $6)`,
				s.cfg.ConsoleStore, x.ut, x.uid, x.rel, store, nullable(x.ur)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": store})
}
