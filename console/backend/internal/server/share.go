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
//
// The actor is CHOSEN, not authenticated: a console sharer may act as any
// subject of the managed store (pgauthzd derives the actor from the token;
// the console is the administrative surface where "what could alice share,
// and do it for her" is the point). That makes can_grant a highly trusted
// console role — the same trust the Data tab's direct Add/Remove already
// carries, with the difference that the engine's grant rules bound what the
// chosen actor can do. Every save is recorded as the signed-in person with
// the actor named in the event, so the trail shows who acted as whom.

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
	ExpiresAt     *string `json:"expires_at"` // set when the tuple expires; expired ones are not listed
}

// shareHoldersPerRelation caps "who holds it" per relation: a widely shared
// object (a public doc with a hundred thousand viewers) must not become a
// hundred-thousand-chip dialog or a multi-megabyte response. The response
// says how many holders each relation has, so the dialog can say "… and
// N more"; revoking beyond the cap is the Data tab's job (filter, delete).
const shareHoldersPerRelation = 200

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
	// Who holds what: only the relations the dialog offers (the ones with a
	// grant rule), only live tuples (the engine's row policy hides expired
	// ones from the console's role anyway; said here so a superuser
	// connection shows the same), at most shareHoldersPerRelation each,
	// with every relation's full count beside it. Per relation, the cap is
	// a LIMIT over the ordered (object, relation) index and the count a
	// separate aggregate — a window function over the whole holder set
	// sorted 200K rows (325 ms, 14 MB) where this takes 46 ms, and the
	// count is the only part that grows with the object's popularity. The
	// ids are resolved first as scalar subqueries so the partitioned table
	// is pruned to the object type's partition.
	relations := make([]string, len(options))
	for i, x := range options {
		relations[i] = x.Relation
	}
	rows, err = s.engine.Query(ctx, `
		WITH st AS (SELECT id FROM authz.stores WHERE name = $1),
		     ot AS (SELECT id FROM authz.types WHERE store_id = (SELECT id FROM st) AND name = $2),
		     rels AS (SELECT id, name FROM authz.relations WHERE store_id = (SELECT id FROM st) AND name = ANY($4))
		SELECT rels.name, ut.name, h.user_id, coalesce(ur.name, ''), coalesce(c.name, ''), h.expires_at::text, n.total
		  FROM rels
		  CROSS JOIN LATERAL (
		    SELECT count(*) AS total FROM authz.tuples t
		     WHERE t.store_id = (SELECT id FROM st) AND t.object_type = (SELECT id FROM ot)
		       AND t.object_id = $3 AND t.relation = rels.id
		       AND (t.expires_at IS NULL OR t.expires_at > statement_timestamp())) n
		  CROSS JOIN LATERAL (
		    SELECT t.user_type, t.user_id, t.user_relation, t.condition_id, t.expires_at
		      FROM authz.tuples t
		     WHERE t.store_id = (SELECT id FROM st) AND t.object_type = (SELECT id FROM ot)
		       AND t.object_id = $3 AND t.relation = rels.id
		       AND (t.expires_at IS NULL OR t.expires_at > statement_timestamp())
		     ORDER BY t.user_type, t.user_id, t.user_relation LIMIT $5) h
		  JOIN authz.types ut ON ut.id = h.user_type
		  LEFT JOIN authz.relations ur ON ur.id = h.user_relation
		  LEFT JOIN authz.conditions c ON c.id = h.condition_id
		 ORDER BY rels.name, ut.name, h.user_id, ur.name`,
		store, o.ObjectType, o.ObjectID, relations, shareHoldersPerRelation)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	holders := []holderRow{}
	totals := map[string]int{} // relation → holders on the object, shown or not
	for rows.Next() {
		var h holderRow
		var total int
		if err := rows.Scan(&h.Relation, &h.UserType, &h.UserID, &h.UserRelation, &h.ConditionName, &h.ExpiresAt, &total); err != nil {
			rows.Close()
			writeEngineError(w, err)
			return
		}
		holders = append(holders, h)
		totals[h.Relation] = total
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		writeEngineError(w, err)
		return
	}
	// The caps (relation constraints, migration 0025) of the object type:
	// relation → max_direct, so the dialog can say "48 / 50" next to the
	// holders and tell "full" from "forbidden" before a save is refused.
	caps := map[string]int{}
	rows, err = s.engine.Query(ctx, `
		SELECT relation, max_direct FROM authz.list_relation_constraints($1)
		 WHERE object_type = $2 AND max_direct IS NOT NULL`, store, o.ObjectType)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	for rows.Next() {
		var rel string
		var max int
		if err := rows.Scan(&rel, &max); err != nil {
			rows.Close()
			writeEngineError(w, err)
			return
		}
		caps[rel] = max
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": o, "options": options, "holders": holders,
		"holder_totals": totals, "holders_limit": shareHoldersPerRelation, "max_direct": caps,
	})
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
	if req.Grants == nil { // a save of only revokes (or only grants): the engine wants arrays, not null
		req.Grants = []tupleReq{}
	}
	if req.Revokes == nil {
		req.Revokes = []tupleReq{}
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
