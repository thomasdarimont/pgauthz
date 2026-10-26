package server

// Store groups (ADR 0017), phase 1: a named set of stores sharing
// administration. The engine holds membership (authz.store_groups,
// stores.group_id); the console mirrors it as link tuples of its own store
// (platform:default platform group:X, group:X group store:Y) so the access
// model's ttu rules make a group admin reach the group's stores — and keeps
// those links in step with the engine on every listing (syncGroupLinks).
//
//   GET  /api/platform/groups                 the groups you may see, with their stores and your capabilities
//   POST /api/platform/groups                 {name, description} create (platform admin)
//   PUT  /api/platform/groups/{group}         {description}
//   POST /api/platform/groups/{group}/delete  an empty group (platform admin)
//   PUT  /api/stores/{store}/group            {group} attach / "" detach (platform admin: tenancy is the platform's)
//   GET/POST /api/platform/groups/{group}/access[/remove]   the group's admins (group admin or above)

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

var groupRoles = []string{"admin", "issuer_admin"}

type groupRow struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	StoreCount   int64           `json:"store_count"`
	Stores       []string        `json:"stores"`
	CreatedAt    time.Time       `json:"created_at"`
	CreatedBy    string          `json:"created_by"`
	UpdatedAt    time.Time       `json:"updated_at"`
	UpdatedBy    string          `json:"updated_by"`
	Capabilities map[string]bool `json:"capabilities"`
}

var groupCapabilities = []string{"can_view", "can_manage_access", "can_create_store", "can_manage_issuers"}

func (s *Server) allGroups(ctx context.Context) ([]groupRow, error) {
	rows, err := s.engine.Query(ctx, `SELECT name, coalesce(description, ''), store_count, created_at, created_by, updated_at, updated_by FROM authz.list_store_groups()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []groupRow{}
	for rows.Next() {
		var g groupRow
		if err := rows.Scan(&g.Name, &g.Description, &g.StoreCount, &g.CreatedAt, &g.CreatedBy, &g.UpdatedAt, &g.UpdatedBy); err != nil {
			return nil, err
		}
		g.Stores = []string{}
		out = append(out, g)
	}
	return out, rows.Err()
}

// syncGroupLinks makes the console store's link tuples say what the engine
// says: one `group` link per grouped store, none for a detached one, and
// every group under the platform. Idempotent; writes as the console.
func (s *Server) syncGroupLinks(ctx context.Context, stores []storeRow, groups []groupRow) error {
	want := map[string]string{} // store → group
	for _, st := range stores {
		if st.Group != "" {
			want[st.Name] = st.Group
		}
	}
	rows, err := s.engine.Query(ctx, `
		SELECT ot.name, t.object_id, t.user_id
		  FROM authz.tuples t
		  JOIN authz.stores s ON s.id = t.store_id AND s.name = $1
		  JOIN authz.types ot ON ot.id = t.object_type
		  JOIN authz.types ut ON ut.id = t.user_type
		  JOIN authz.relations rl ON rl.id = t.relation
		 WHERE (ot.name = 'store' AND rl.name = 'group' AND ut.name = 'group')
		    OR (ot.name = 'group' AND rl.name = 'platform' AND ut.name = 'platform')`, s.cfg.ConsoleStore)
	if err != nil {
		return err
	}
	have := map[string]string{} // store → linked group
	linked := map[string]bool{} // group → under the platform
	for rows.Next() {
		var ot, obj, subj string
		if err := rows.Scan(&ot, &obj, &subj); err != nil {
			rows.Close()
			return err
		}
		if ot == "store" {
			have[obj] = subj
		} else {
			linked[obj] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for store, g := range have {
		if want[store] != g {
			if _, err := s.engine.Exec(ctx, `SELECT authz.delete_tuple($1, 'group', $2, 'group', 'store', $3)`, s.cfg.ConsoleStore, g, store); err != nil {
				return err
			}
		}
	}
	for store, g := range want {
		if have[store] != g {
			if _, err := s.engine.Exec(ctx, `SELECT authz.write_tuple($1, 'group', $2, 'group', 'store', $3)`, s.cfg.ConsoleStore, g, store); err != nil {
				return err
			}
		}
	}
	for _, g := range groups {
		if !linked[g.Name] {
			if _, err := s.engine.Exec(ctx, `SELECT authz.write_tuple($1, 'platform', $2, 'platform', 'group', $3)`, s.cfg.ConsoleStore, s.cfg.PlatformID, g.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	if p == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	ctx := r.Context()
	groups, err := s.allGroups(ctx)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	stores, err := s.allStores(ctx)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if err := s.syncGroupLinks(ctx, stores, groups); err != nil {
		writeEngineError(w, err)
		return
	}
	byName := map[string]int{}
	ids := make([]string, len(groups))
	for i := range groups {
		byName[groups[i].Name] = i
		ids[i] = groups[i].Name
	}
	ungrouped := []string{}
	for _, st := range stores {
		if i, ok := byName[st.Group]; ok {
			groups[i].Stores = append(groups[i].Stores, st.Name)
		} else {
			ungrouped = append(ungrouped, st.Name)
		}
	}
	caps, err := s.capabilities(ctx, p, "group", ids, groupCapabilities)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	visible := []groupRow{}
	for _, g := range groups {
		g.Capabilities = caps[g.Name]
		if g.Capabilities["can_view"] {
			visible = append(visible, g)
		}
	}
	platformAdmin, err := s.can(ctx, p, "can_manage_access", "platform", s.cfg.PlatformID)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if !platformAdmin {
		ungrouped = nil // tenancy is the platform's: a group admin sees only their groups
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": visible, "ungrouped": ungrouped, "can_manage": platformAdmin, "teams": p.teams})
}

type groupReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_manage_access", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	var req groupReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validName.MatchString(req.Name) || len(req.Name) > 63 {
		writeError(w, http.StatusBadRequest, "group name must match ^[a-zA-Z_][a-zA-Z0-9_]*$")
		return
	}
	err := s.asPerson(r.Context(), p, "can_manage_access", "platform", s.cfg.PlatformID, map[string]any{"op": "group_create", "group": req.Name}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `SELECT authz.create_store_group($1, $2)`, req.Name, nullable(req.Description)); err != nil {
			return err
		}
		_, err := tx.Exec(r.Context(), `SELECT authz.write_tuple($1, 'platform', $2, 'platform', 'group', $3)`, s.cfg.ConsoleStore, s.cfg.PlatformID, req.Name)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"name": req.Name})
}

func (s *Server) handleGroupUpdate(w http.ResponseWriter, r *http.Request) {
	group := r.PathValue("group")
	p := s.require(w, r, "can_manage_access", "group", group)
	if p == nil {
		return
	}
	var req groupReq
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.asPerson(r.Context(), p, "can_manage_access", "group", group, map[string]any{"op": "group_settings", "description": req.Description}, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `SELECT authz.update_store_group($1, $2)`, group, req.Description)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": group})
}

// handleGroupDelete: an empty group; its console tuples (the platform link,
// its admins) go with it.
func (s *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	group := r.PathValue("group")
	p := s.require(w, r, "can_manage_access", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	err := s.asPerson(r.Context(), p, "can_manage_access", "platform", s.cfg.PlatformID, map[string]any{"op": "group_delete", "group": group}, func(tx pgx.Tx) error {
		var deleted bool
		if err := tx.QueryRow(r.Context(), `SELECT authz.delete_store_group($1)`, group).Scan(&deleted); err != nil {
			return err
		}
		rows, err := tx.Query(r.Context(), `
			SELECT ut.name, t.user_id, coalesce(ur.name, ''), rl.name
			  FROM authz.tuples t
			  JOIN authz.stores s ON s.id = t.store_id AND s.name = $1
			  JOIN authz.types ot ON ot.id = t.object_type AND ot.name = 'group'
			  JOIN authz.types ut ON ut.id = t.user_type
			  LEFT JOIN authz.relations ur ON ur.id = t.user_relation
			  JOIN authz.relations rl ON rl.id = t.relation
			 WHERE t.object_id = $2`, s.cfg.ConsoleStore, group)
		if err != nil {
			return err
		}
		type tup struct{ ut, uid, urel, rel string }
		var tuples []tup
		for rows.Next() {
			var x tup
			if err := rows.Scan(&x.ut, &x.uid, &x.urel, &x.rel); err != nil {
				rows.Close()
				return err
			}
			tuples = append(tuples, x)
		}
		rows.Close()
		for _, x := range tuples {
			if _, err := tx.Exec(r.Context(), `SELECT authz.delete_tuple($1, $2, $3, $4, 'group', $5, $6)`, s.cfg.ConsoleStore, x.ut, x.uid, x.rel, group, nullable(x.urel)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": group, "deleted": true})
}

type setStoreGroupReq struct {
	Group string `json:"group"`
}

// handleStoreGroupSet: moving a store between groups changes who
// administers it — the platform's call. The link tuple follows.
func (s *Server) handleStoreGroupSet(w http.ResponseWriter, r *http.Request) {
	store := r.PathValue("store")
	p := s.require(w, r, "can_manage_access", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	var req setStoreGroupReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Group != "" && (!validName.MatchString(req.Group) || len(req.Group) > 63) {
		writeError(w, http.StatusBadRequest, "group name must match ^[a-zA-Z_][a-zA-Z0-9_]*$ (empty detaches)")
		return
	}
	err := s.asPerson(r.Context(), p, "can_manage_access", "platform", s.cfg.PlatformID, map[string]any{"op": "store_group", "store": store, "group": req.Group}, func(tx pgx.Tx) error {
		var old string
		if err := tx.QueryRow(r.Context(), `SELECT coalesce(store_group, '') FROM authz.list_stores() WHERE name = $1`, store).Scan(&old); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `SELECT authz.set_store_group($1, $2)`, store, nullable(req.Group)); err != nil {
			return err
		}
		if old != "" && old != req.Group {
			if _, err := tx.Exec(r.Context(), `SELECT authz.delete_tuple($1, 'group', $2, 'group', 'store', $3)`, s.cfg.ConsoleStore, old, store); err != nil {
				return err
			}
		}
		if req.Group != "" && old != req.Group {
			if _, err := tx.Exec(r.Context(), `SELECT authz.write_tuple($1, 'group', $2, 'group', 'store', $3)`, s.cfg.ConsoleStore, req.Group, store); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "group": req.Group})
}

// the group's admins: the Access forms, one level below the platform's
func (s *Server) handleGroupAccess(w http.ResponseWriter, r *http.Request) {
	group := r.PathValue("group")
	p := s.require(w, r, "can_view", "group", group)
	if p == nil {
		return
	}
	list, err := s.accessList(r.Context(), "group", group, groupRoles)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	manage, _ := s.can(r.Context(), p, "can_manage_access", "group", group)
	writeJSON(w, http.StatusOK, map[string]any{"access": list, "roles": groupRoles, "can_manage": manage, "teams": p.teams})
}

func (s *Server) handleGroupAccessAdd(w http.ResponseWriter, r *http.Request) {
	group := r.PathValue("group")
	p := s.require(w, r, "can_manage_access", "group", group)
	if p == nil {
		return
	}
	req, ok := s.accessInput(w, r, groupRoles)
	if !ok {
		return
	}
	err := s.asPerson(r.Context(), p, "can_manage_access", "group", group, map[string]any{"op": "add", "access": req}, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `SELECT authz.write_tuple($1, $2, $3, $4, 'group', $5, $6)`,
			s.cfg.ConsoleStore, req.SubjectType, req.SubjectID, req.Role, group, nullable(req.SubjectRelation))
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleGroupAccessRemove(w http.ResponseWriter, r *http.Request) {
	group := r.PathValue("group")
	p := s.require(w, r, "can_manage_access", "group", group)
	if p == nil {
		return
	}
	items, ok := s.accessRemoveInput(w, r, groupRoles)
	if !ok {
		return
	}
	err := s.asPerson(r.Context(), p, "can_manage_access", "group", group, map[string]any{"op": "remove", "items": items}, func(tx pgx.Tx) error {
		for _, it := range items {
			if _, err := tx.Exec(r.Context(), `SELECT authz.delete_tuple($1, $2, $3, $4, 'group', $5, $6)`,
				s.cfg.ConsoleStore, it.SubjectType, it.SubjectID, it.Role, group, nullable(it.SubjectRelation)); err != nil {
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

// the group's model consumers (ADR 0017 phase 3): group:A model_consumer
// group:B, granted by A's admins — the groups that may apply A's models
func (s *Server) handleGroupConsumers(w http.ResponseWriter, r *http.Request) {
	group := r.PathValue("group")
	p := s.require(w, r, "can_view", "group", group)
	if p == nil {
		return
	}
	rows, err := s.engine.Query(r.Context(), `SELECT consumer_group, created_at, created_by FROM authz.list_model_consumers($1)`, group)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	defer rows.Close()
	type consumer struct {
		Group     string    `json:"group"`
		CreatedAt time.Time `json:"created_at"`
		CreatedBy string    `json:"created_by"`
	}
	out := []consumer{}
	for rows.Next() {
		var c consumer
		if err := rows.Scan(&c.Group, &c.CreatedAt, &c.CreatedBy); err != nil {
			writeEngineError(w, err)
			return
		}
		out = append(out, c)
	}
	manage, _ := s.can(r.Context(), p, "can_manage_access", "group", group)
	writeJSON(w, http.StatusOK, map[string]any{"group": group, "consumers": out, "can_manage": manage})
}

type consumerReq struct {
	Consumer string `json:"consumer"`
}

func (s *Server) handleGroupConsumerGrant(w http.ResponseWriter, r *http.Request) {
	group := r.PathValue("group")
	p := s.require(w, r, "can_manage_access", "group", group)
	if p == nil {
		return
	}
	var req consumerReq
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.asPerson(r.Context(), p, "can_manage_access", "group", group, map[string]any{"op": "model_consumer_grant", "consumer": req.Consumer}, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `SELECT authz.grant_model_consumer($1, $2)`, group, req.Consumer)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": group, "consumer": req.Consumer, "granted": true})
}

func (s *Server) handleGroupConsumerRevoke(w http.ResponseWriter, r *http.Request) {
	group := r.PathValue("group")
	p := s.require(w, r, "can_manage_access", "group", group)
	if p == nil {
		return
	}
	var req consumerReq
	if !decodeJSON(w, r, &req) {
		return
	}
	var revoked bool
	err := s.asPerson(r.Context(), p, "can_manage_access", "group", group, map[string]any{"op": "model_consumer_revoke", "consumer": req.Consumer}, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT authz.revoke_model_consumer($1, $2)`, group, req.Consumer).Scan(&revoked)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": group, "consumer": req.Consumer, "revoked": revoked})
}
