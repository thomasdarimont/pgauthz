package server

// Store groups (ADR 0017), phase 1: a named set of stores sharing
// administration. The engine holds membership (authz.store_groups,
// stores.group_id); the console mirrors it as link tuples of its own store
// (platform:default platform group:X, group:X group store:Y) so the access
// model's ttu rules make a group admin reach the group's stores — and keeps
// those links in step with the engine on every listing (syncGroupLinks).
//
//   GET  /api/platform/groups?q=&limit=&offset=   a page of the groups you may see (name, description or a
//                                             store name matching q), with their stores and your capabilities
//   GET  /api/platform/groups/names?q=&limit=  the names of the groups you may see, for pickers
//   POST /api/platform/groups                 {name, description} create (platform admin)
//   PUT  /api/platform/groups/{group}         {description}
//   POST /api/platform/groups/{group}/delete  an empty group (platform admin)
//   PUT  /api/stores/{store}/group            {group} attach / "" detach (platform admin: tenancy is the platform's)
//   GET/POST /api/platform/groups/{group}/access[/remove]   the group's admins (group admin or above)

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// groupRoles: a group's own two (admin, issuer_admin) and every store role,
// which on a group reaches each of its stores (ADR 0017).
var groupRoles = []string{"admin", "issuer_admin", "author", "publisher", "sharer", "tester", "supporter", "auditor", "exporter", "viewer"}

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

// groupsReaching: the groups the person holds a relation on, by the engine's
// reverse search — one call however many groups exist, instead of a check
// per group (which is what made the listing and the identity endpoint grow
// with the fleet). limit 0 = all.
func (s *Server) groupsReaching(ctx context.Context, p *principal, relation string, limit int) ([]string, error) {
	var lim any
	if limit > 0 {
		lim = limit
	}
	rows, err := s.engine.Query(ctx, `
		SELECT object_id FROM authz.list_objects_with_contextual_tuples_jsonb($1, $2, $3, $4, 'group', NULL, $5::jsonb, $6)
		 WHERE NOT is_wildcard`,
		s.cfg.ConsoleStore, p.typ, p.id, relation, nullable(p.tuplesFor("group", nil)), lim)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// visibleGroups: which groups the person may see — every one for a
// platform admin (admin of each group through the platform), else the
// reverse search on can_view. Returns (all, names).
func (s *Server) visibleGroups(ctx context.Context, p *principal) (bool, []string, error) {
	all, err := s.can(ctx, p, "can_manage_access", "platform", s.cfg.PlatformID)
	if err != nil || all {
		return all, nil, err
	}
	names, err := s.groupsReaching(ctx, p, "can_view", 0)
	return false, names, err
}

// groupQuery is the listing's filter: a substring of the name, the
// description or one of the group's store names.
const groupQuery = `($2 = '' OR g.name ILIKE '%' || $2 || '%' OR coalesce(g.description, '') ILIKE '%' || $2 || '%'
       OR EXISTS (SELECT 1 FROM authz.stores st JOIN authz.store_groups sg ON sg.id = st.group_id
                   WHERE sg.name = g.name AND st.deleted_at IS NULL AND st.name ILIKE '%' || $2 || '%'))`

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	if p == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	ctx := r.Context()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 25
	}
	if limit > 200 {
		limit = 200
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	all, names, err := s.visibleGroups(ctx, p)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if all {
		// the platform's admin is who moves stores and creates groups: keep
		// the console's link tuples in step with the engine for them
		groups, err := s.allGroups(ctx)
		if err == nil {
			var stores []storeRow
			if stores, err = s.allStores(ctx); err == nil {
				err = s.syncGroupLinks(ctx, stores, groups)
			}
		}
		if err != nil {
			writeEngineError(w, err)
			return
		}
	}
	// one page of the visible groups, with the total under the filter
	rows, err := s.engine.Query(ctx, `
		SELECT g.name, coalesce(g.description, ''), g.store_count, g.created_at, g.created_by, g.updated_at, g.updated_by, count(*) OVER ()
		  FROM authz.list_store_groups() g
		 WHERE ($1 OR g.name = ANY($3)) AND `+groupQuery+`
		 ORDER BY g.name
		 LIMIT $4 OFFSET $5`, all, q, names, limit, offset)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	page := []groupRow{}
	var total int64
	for rows.Next() {
		var g groupRow
		if err := rows.Scan(&g.Name, &g.Description, &g.StoreCount, &g.CreatedAt, &g.CreatedBy, &g.UpdatedAt, &g.UpdatedBy, &total); err != nil {
			rows.Close()
			writeEngineError(w, err)
			return
		}
		g.Stores = []string{}
		page = append(page, g)
	}
	rows.Close()
	ids := make([]string, len(page))
	byName := map[string]int{}
	for i := range page {
		ids[i] = page[i].Name
		byName[page[i].Name] = i
	}
	// the page's stores, and the person's capabilities on the page's groups only
	if len(ids) > 0 {
		srows, err := s.engine.Query(ctx, `
			SELECT st.name, sg.name FROM authz.stores st JOIN authz.store_groups sg ON sg.id = st.group_id
			 WHERE sg.name = ANY($1) AND st.deleted_at IS NULL ORDER BY st.name`, ids)
		if err != nil {
			writeEngineError(w, err)
			return
		}
		for srows.Next() {
			var st, g string
			if err := srows.Scan(&st, &g); err != nil {
				srows.Close()
				writeEngineError(w, err)
				return
			}
			page[byName[g]].Stores = append(page[byName[g]].Stores, st)
		}
		srows.Close()
	}
	caps, err := s.capabilities(ctx, p, "group", ids, groupCapabilities)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	for i := range page {
		page[i].Capabilities = caps[page[i].Name]
		if page[i].Capabilities == nil {
			page[i].Capabilities = map[string]bool{}
		}
		page[i].Capabilities["can_view"] = true // it is in the visible set
	}
	// the detached stores — tenancy is the platform's: its admins only, on the first page
	var ungrouped []string
	if all && offset == 0 {
		ungrouped = []string{}
		urows, err := s.engine.Query(ctx, `SELECT name FROM authz.stores WHERE group_id IS NULL AND deleted_at IS NULL AND ($1 = '' OR name ILIKE '%' || $1 || '%') ORDER BY name`, q)
		if err != nil {
			writeEngineError(w, err)
			return
		}
		for urows.Next() {
			var n string
			if err := urows.Scan(&n); err == nil {
				ungrouped = append(ungrouped, n)
			}
		}
		urows.Close()
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": page, "total": total, "offset": offset, "limit": limit, "q": q,
		"ungrouped": ungrouped, "can_manage": all, "teams": p.teams})
}

// handleGroupNames — GET /api/platform/groups/names?q=&limit=: the names of
// the groups the person may see that contain q, for the pickers (a select
// over every group does not scale to a tenant per group).
func (s *Server) handleGroupNames(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	if p == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	ctx := r.Context()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	all, names, err := s.visibleGroups(ctx, p)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	rows, err := s.engine.Query(ctx, `
		SELECT g.name FROM authz.list_store_groups() g
		 WHERE ($1 OR g.name = ANY($3)) AND ($2 = '' OR g.name ILIKE '%' || $2 || '%')
		 ORDER BY (g.name ILIKE $2 || '%') DESC, g.name
		 LIMIT $4`, all, q, names, limit)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil {
			out = append(out, n)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"names": out})
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
