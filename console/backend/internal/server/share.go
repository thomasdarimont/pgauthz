package server

// The share dialog: sharing under the model's grant rules, the way an
// application's share dialog does through pgauthzd — but driven from the
// console, acting as a chosen subject of the managed store. grant_options
// says which relations the actor may grant and revoke on the object and who
// may hold them; apply_grants applies the dialog's additions and removals
// in one transaction, every entry decided by the engine under the object's
// lock exactly as authz.grant / authz.revoke would. The console's own gate
// is can_grant (sharer, owner), scoped to the object type's namespace like
// every Data-tab write; the engine's grant rules decide for the actor.

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
)

type grantOption struct {
	Relation       string   `json:"relation"`
	CanGrant       bool     `json:"can_grant"`
	CanRevoke      bool     `json:"can_revoke"`
	Requires       string   `json:"requires"`
	RequiresRevoke string   `json:"requires_revoke"`
	GranteeTypes   []string `json:"grantee_types"` // user, team#member, user:* — who the relation may hold
}

type holderRow struct {
	Relation      string  `json:"relation"`
	UserType      string  `json:"user_type"`
	UserID        string  `json:"user_id"`
	UserRelation  string  `json:"user_relation"`
	ConditionName string  `json:"condition_name"`
	ExpiresAt     *string `json:"expires_at"`
}

type shareObject struct {
	ObjectType string `json:"object_type"`
	ObjectID   string `json:"object_id"`
	ActorType  string `json:"actor_type"`
	ActorID    string `json:"actor_id"`
}

func (o shareObject) valid() bool {
	return o.ObjectType != "" && o.ObjectID != "" && o.ActorType != "" && o.ActorID != ""
}

// shareGate — the console side: can_grant on the store, or on the object
// type's namespace; the engine side (the actor's grant rules) is answered by
// grant_options and enforced by apply_grants.
func (s *Server) shareGate(w http.ResponseWriter, r *http.Request, p *principal, store string, objectType string) (ns string, ok bool) {
	ns, err := s.typeNamespace(r.Context(), store, objectType)
	if err != nil {
		writeEngineError(w, err)
		return "", false
	}
	if err := s.authorizeScoped(r.Context(), p, "can_grant", store, []string{ns}); err != nil {
		if !writeScopeError(w, err) {
			writeEngineError(w, err)
		}
		return "", false
	}
	return ns, true
}

// handleShareOptions — GET .../share?object_type=&object_id=&actor_type=&actor_id=:
// what the actor may grant and revoke on the object (every relation with a
// grant rule), and who holds what on it today.
func (s *Server) handleShareOptions(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view") // the scope check below decides
	if p == nil {
		return
	}
	q := r.URL.Query()
	o := shareObject{ObjectType: q.Get("object_type"), ObjectID: q.Get("object_id"), ActorType: q.Get("actor_type"), ActorID: q.Get("actor_id")}
	if !o.valid() {
		writeError(w, http.StatusBadRequest, "object_type, object_id, actor_type and actor_id are required")
		return
	}
	if _, ok := s.shareGate(w, r, p, store, o.ObjectType); !ok {
		return
	}
	ctx := r.Context()
	rows, err := s.engine.Query(ctx, `
		SELECT relation, can_grant, can_revoke, requires, coalesce(requires_revoke, ''), coalesce(grantee_types, '{}')
		  FROM authz.grant_options($1, $2, $3, $4, $5)`, store, o.ActorType, o.ActorID, o.ObjectType, o.ObjectID)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	options := []grantOption{}
	for rows.Next() {
		var x grantOption
		if err := rows.Scan(&x.Relation, &x.CanGrant, &x.CanRevoke, &x.Requires, &x.RequiresRevoke, &x.GranteeTypes); err != nil {
			rows.Close()
			writeEngineError(w, err)
			return
		}
		options = append(options, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		writeEngineError(w, err)
		return
	}
	rows, err = s.engine.Query(ctx, `
		SELECT rl.name, ut.name, t.user_id, coalesce(ur.name, ''), coalesce(c.name, ''), t.expires_at::text
		  FROM authz.tuples t
		  JOIN authz.stores s ON s.id = t.store_id
		  JOIN authz.types ot ON ot.id = t.object_type
		  JOIN authz.relations rl ON rl.id = t.relation
		  JOIN authz.types ut ON ut.id = t.user_type
		  LEFT JOIN authz.relations ur ON ur.id = t.user_relation
		  LEFT JOIN authz.conditions c ON c.id = t.condition_id
		 WHERE s.name = $1 AND ot.name = $2 AND t.object_id = $3
		 ORDER BY rl.name, ut.name, t.user_id, ur.name`, store, o.ObjectType, o.ObjectID)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	holders := []holderRow{}
	for rows.Next() {
		var h holderRow
		if err := rows.Scan(&h.Relation, &h.UserType, &h.UserID, &h.UserRelation, &h.ConditionName, &h.ExpiresAt); err != nil {
			rows.Close()
			writeEngineError(w, err)
			return
		}
		holders = append(holders, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": o, "options": options, "holders": holders})
}

type shareReq struct {
	shareObject
	Grants  []tupleReq `json:"grants"`
	Revokes []tupleReq `json:"revokes"`
}

// handleShareApply — POST .../share: the dialog's save. Every grant and
// revoke names the object; apply_grants decides each under the actor's
// grant rules, all or nothing, and the console records the batch as the
// person.
func (s *Server) handleShareApply(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view") // the scope check below decides
	if p == nil {
		return
	}
	var req shareReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.valid() {
		writeError(w, http.StatusBadRequest, "object_type, object_id, actor_type and actor_id are required")
		return
	}
	if len(req.Grants)+len(req.Revokes) == 0 || len(req.Grants)+len(req.Revokes) > 200 {
		writeError(w, http.StatusBadRequest, "1 to 200 changes per save")
		return
	}
	for i := range req.Grants { // every entry is about this object
		req.Grants[i].ObjectType, req.Grants[i].ObjectID = req.ObjectType, req.ObjectID
		if req.Grants[i].UserType == "" || req.Grants[i].UserID == "" || req.Grants[i].Relation == "" {
			writeError(w, http.StatusBadRequest, "every grant needs user_type, user_id and relation")
			return
		}
	}
	for i := range req.Revokes {
		req.Revokes[i].ObjectType, req.Revokes[i].ObjectID = req.ObjectType, req.ObjectID
		if req.Revokes[i].UserType == "" || req.Revokes[i].UserID == "" || req.Revokes[i].Relation == "" {
			writeError(w, http.StatusBadRequest, "every revoke needs user_type, user_id and relation")
			return
		}
	}
	ns, ok := s.shareGate(w, r, p, store, req.ObjectType)
	if !ok {
		return
	}
	grants, _ := json.Marshal(req.Grants)
	revokes, _ := json.Marshal(req.Revokes)
	var result json.RawMessage
	err := s.asPersonScoped(r.Context(), p, "can_grant", "store", store, []string{ns}, map[string]any{
		"op": "share", "actor": req.ActorType + ":" + req.ActorID, "object": req.ObjectType + ":" + req.ObjectID,
		"grants": len(req.Grants), "revokes": len(req.Revokes),
	}, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT authz.apply_grants($1, $2, $3, $4::jsonb, $5::jsonb)`,
			store, req.ActorType, req.ActorID, grants, revokes).Scan(&result)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}
