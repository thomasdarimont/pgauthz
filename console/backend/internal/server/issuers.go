package server

// Platform → Issuers: the trusted identity providers' BINDINGS, managed in
// the database (migration 0023, scratch/notes/issuer-management.md option
// C). Trust itself — issuer, audience, signing keys — stays in every
// pgauthzd's environment (JWT_ISSUERS); a row here replaces what an
// environment issuer's tokens may do (stores, DB roles, client roles, PEP
// clients, enabled) and may only narrow it. Reads and writes need the
// platform's can_manage_issuers; writes are recorded in the console's action
// log AND in authz.issuer_bindings_audit with the person as performed_by.
//
// Two transports. With PGAUTHZD_ADMIN_URL the tab goes through pgauthzd's
// ADMIN API — the rows, the history, the writes and the effective set —
// presenting the signed-in person's own token (so pgauthzd's tenant scoping
// decides what they see and may change: a tenant admin its issuer only), or
// the console's client certificate for a session without a token (the
// local admin); the console still gates on platform#can_manage_issuers
// first and records every write in its action log. Without it, the engine
// functions directly (the full set, as the console's engine login), plus the
// EFFECTIVE set that a pgauthzd's internal callback listener serves
// (PGAUTHZD_INTERNAL_URL + PGAUTHZD_SERVICE_TOKEN) — every trusted issuer,
// whether its bindings come from the environment or a row, the applied
// revision — so an admin sees which issuers exist before binding one, and
// whether a row is in force (binding_source=db) or was rejected by the
// narrowing rule.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// upstreamError is pgauthzd's answer to an admin-API call, carried to the
// browser with a status of its own: the person is signed in to the console,
// so a refusal by pgauthzd is their scope there (403), an unknown row 404,
// a rejected row 400, anything else the upstream's fault (502).
type upstreamError struct {
	status int
	msg    string
}

func (e *upstreamError) Error() string { return e.msg }

// adminAPI: the tab runs over pgauthzd's admin API.
func (s *Server) adminAPI() bool { return s.cfg.PgauthzdAdminURL != "" }

// adminCredential: what this request presents to the admin API — an OIDC
// session's own token; the console's certificate for the LOCAL admin only
// (an OIDC session without a usable token fails closed: the certificate
// may carry more scope than the person's own credential would); "" when
// there is nothing to present.
func (s *Server) adminCredential(r *http.Request) (kind, token string) {
	se := s.sessionFromReq(r)
	switch {
	case se == nil:
		return "", ""
	case se.local:
		if s.adminHTTP != nil {
			return "certificate", ""
		}
		return "", ""
	case se.accessToken != "":
		return "token", se.accessToken
	default:
		return "", ""
	}
}

// adminCall is one request to pgauthzd's admin API as the person (or the
// console); out receives a 2xx body.
func (s *Server) adminCall(ctx context.Context, r *http.Request, method, path string, body, out any) error {
	kind, token := s.adminCredential(r)
	if kind == "" {
		return &upstreamError{http.StatusServiceUnavailable, "no credential for pgauthzd's admin API: sign in through the identity provider (your token is presented), or give the console a client certificate (PGAUTHZD_ADMIN_CERT/_KEY)"}
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.cfg.PgauthzdAdminURL, "/")+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := s.http
	if client == nil {
		client = http.DefaultClient
	}
	if kind == "token" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		client = s.adminHTTP
	}
	resp, err := client.Do(req)
	if err != nil {
		return &upstreamError{http.StatusBadGateway, "pgauthzd's admin API: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		msg := strings.TrimSpace(string(raw))
		if json.Unmarshal(raw, &e) == nil && e.Message != "" {
			msg = e.Message
		}
		status := http.StatusBadGateway
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			status = http.StatusForbidden
		case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict:
			status = resp.StatusCode
		}
		return &upstreamError{status, "pgauthzd: " + msg}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// writeUpstreamError answers an upstreamError; false when err is not one.
func writeUpstreamError(w http.ResponseWriter, err error) bool {
	var ue *upstreamError
	if errors.As(err, &ue) {
		writeError(w, ue.status, ue.msg)
		return true
	}
	return false
}

type issuerBinding struct {
	Issuer        string              `json:"issuer"`
	Stores        []string            `json:"stores"`
	DBRoles       []string            `json:"db_roles"`
	ClientDBRoles map[string]string   `json:"client_db_roles"`
	PEPClients    map[string][]string `json:"pep_clients"`
	Enabled       bool                `json:"enabled"`
	Description   string              `json:"description"`
	CreatedAt     *time.Time          `json:"created_at,omitempty"`
	CreatedBy     string              `json:"created_by,omitempty"`
	UpdatedAt     *time.Time          `json:"updated_at,omitempty"`
	UpdatedBy     string              `json:"updated_by,omitempty"`
}

type issuerAuditRow struct {
	Seq         int64     `json:"seq"`
	Action      string    `json:"action"`
	PerformedAt time.Time `json:"performed_at"`
	PerformedBy string    `json:"performed_by"`
	Issuer      string    `json:"issuer"`
	Stores      []string  `json:"stores"`
	Enabled     *bool     `json:"enabled"`
	Description string    `json:"description"`
}

// effectiveIssuers is pgauthzd's GET /pgauthz/v1/issuers, as the callback
// listener serves it (the whole set).
type effectiveIssuers struct {
	Available bool            `json:"available"`
	URL       string          `json:"url,omitempty"`
	Error     string          `json:"error,omitempty"`
	Source    string          `json:"source,omitempty"`
	Revision  int64           `json:"revision"`
	Issuers   json.RawMessage `json:"issuers,omitempty"`
	// Via/Credential: "admin-api" as "token" (the person's own) or
	// "certificate" (the console's), or "callback" (the service token).
	Via        string `json:"via,omitempty"`
	Credential string `json:"credential,omitempty"`
}

// handleIssuers — GET /api/platform/issuers: the rows, the revision they
// are at, and the effective set when reachable (the history is its own,
// paged, endpoint).
func (s *Server) handleIssuers(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_manage_issuers", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	ctx := r.Context()
	if s.adminAPI() {
		var list struct {
			Bindings []issuerBinding `json:"bindings"`
			Revision int64           `json:"revision"`
		}
		if err := s.adminCall(ctx, r, "GET", "/pgauthz/v1/admin/issuer-bindings", nil, &list); err != nil {
			if !writeUpstreamError(w, err) {
				writeError(w, http.StatusBadGateway, err.Error())
			}
			return
		}
		if list.Bindings == nil {
			list.Bindings = []issuerBinding{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"bindings":  list.Bindings,
			"revision":  list.Revision,
			"effective": s.effectiveIssuersAdmin(ctx, r),
			"via":       "admin-api",
		})
		return
	}
	bindings, err := s.issuerBindings(ctx)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	var revision int64
	if err := s.engine.QueryRow(ctx, `SELECT authz.issuer_bindings_revision()`).Scan(&revision); err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bindings":  bindings,
		"revision":  revision,
		"effective": s.effectiveIssuers(ctx),
		"via":       "db",
	})
}

// effectiveIssuersAdmin is the set in force as the admin API answers it
// within the caller's scope (GET /pgauthz/v1/admin/issuers).
func (s *Server) effectiveIssuersAdmin(ctx context.Context, r *http.Request) effectiveIssuers {
	kind, _ := s.adminCredential(r)
	e := effectiveIssuers{URL: s.cfg.PgauthzdAdminURL, Via: "admin-api", Credential: kind}
	var body struct {
		Source   string          `json:"source"`
		Revision int64           `json:"revision"`
		Issuers  json.RawMessage `json:"issuers"`
	}
	if err := s.adminCall(ctx, r, "GET", "/pgauthz/v1/admin/issuers", nil, &body); err != nil {
		e.Error = err.Error()
		return e
	}
	e.Available, e.Source, e.Revision, e.Issuers = true, body.Source, body.Revision, body.Issuers
	return e
}

// handleIssuersAudit — GET /api/platform/issuers/audit?issuer=&limit=&before=<seq>:
// one page of the history, newest first, keyset by seq (`before` is the
// previous page's `next`), with the total for the pager.
func (s *Server) handleIssuersAudit(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_manage_issuers", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 25
	}
	var before *int64
	if b := q.Get("before"); b != "" {
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "before must be the previous page's next (a sequence number)")
			return
		}
		before = &n
	}
	issuer := strings.TrimSpace(q.Get("issuer"))
	if s.adminAPI() {
		qs := url.Values{"limit": {strconv.Itoa(limit)}}
		if issuer != "" {
			qs.Set("issuer", issuer)
		}
		if before != nil {
			qs.Set("before", strconv.FormatInt(*before, 10))
		}
		var page json.RawMessage
		if err := s.adminCall(r.Context(), r, "GET", "/pgauthz/v1/admin/issuer-bindings/audit?"+qs.Encode(), nil, &page); err != nil {
			if !writeUpstreamError(w, err) {
				writeError(w, http.StatusBadGateway, err.Error())
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(page)
		return
	}
	rows, err := s.issuerAudit(r.Context(), issuer, limit, before)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	var total int64
	if err := s.engine.QueryRow(r.Context(), `SELECT authz.count_issuer_bindings_audit($1)`, nullable(issuer)).Scan(&total); err != nil {
		writeEngineError(w, err)
		return
	}
	next := ""
	if len(rows) == limit {
		next = strconv.FormatInt(rows[len(rows)-1].Seq, 10)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "next": next, "total": total, "limit": limit})
}

func (s *Server) issuerBindings(ctx context.Context) ([]issuerBinding, error) {
	rows, err := s.engine.Query(ctx, `
		SELECT issuer, stores, db_roles, client_db_roles, pep_clients, enabled, coalesce(description, ''),
		       created_at, coalesce(created_by, ''), updated_at, coalesce(updated_by, '')
		  FROM authz.list_issuer_bindings()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []issuerBinding{}
	for rows.Next() {
		var b issuerBinding
		if err := rows.Scan(&b.Issuer, &b.Stores, &b.DBRoles, &b.ClientDBRoles, &b.PEPClients, &b.Enabled, &b.Description,
			&b.CreatedAt, &b.CreatedBy, &b.UpdatedAt, &b.UpdatedBy); err != nil {
			return nil, err
		}
		if b.Stores == nil {
			b.Stores = []string{}
		}
		if b.DBRoles == nil {
			b.DBRoles = []string{}
		}
		if b.ClientDBRoles == nil {
			b.ClientDBRoles = map[string]string{}
		}
		if b.PEPClients == nil {
			b.PEPClients = map[string][]string{}
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Server) issuerAudit(ctx context.Context, issuer string, limit int, before *int64) ([]issuerAuditRow, error) {
	rows, err := s.engine.Query(ctx, `
		SELECT seq, action, performed_at, performed_by, issuer, stores, enabled, coalesce(description, '')
		  FROM authz.list_issuer_bindings_audit($1, $2, $3)`, nullable(issuer), limit, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []issuerAuditRow{}
	for rows.Next() {
		var a issuerAuditRow
		if err := rows.Scan(&a.Seq, &a.Action, &a.PerformedAt, &a.PerformedBy, &a.Issuer, &a.Stores, &a.Enabled, &a.Description); err != nil {
			return nil, err
		}
		if a.Stores == nil {
			a.Stores = []string{}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// effectiveIssuers asks the configured pgauthzd's callback listener for the
// set it applies. Never an error for the page: unreachable is a state.
func (s *Server) effectiveIssuers(ctx context.Context) effectiveIssuers {
	if s.cfg.PgauthzdInternalURL == "" {
		return effectiveIssuers{}
	}
	e := effectiveIssuers{URL: s.cfg.PgauthzdInternalURL, Via: "callback", Credential: "service-token"}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.cfg.PgauthzdInternalURL, "/")+"/pgauthz/v1/issuers", nil)
	if err != nil {
		e.Error = err.Error()
		return e
	}
	if s.cfg.PgauthzdServiceToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.PgauthzdServiceToken)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		e.Error = err.Error()
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.Error = "pgauthzd answered " + resp.Status
		return e
	}
	var body struct {
		Source   string          `json:"source"`
		Revision int64           `json:"revision"`
		Issuers  json.RawMessage `json:"issuers"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&body); err != nil {
		e.Error = "pgauthzd's answer did not decode: " + err.Error()
		return e
	}
	e.Available, e.Source, e.Revision, e.Issuers = true, body.Source, body.Revision, body.Issuers
	return e
}

// handleIssuerSave — PUT /api/platform/issuers: create or replace one
// binding (the whole row). The engine validates (anchored patterns, PEP
// clients within stores); pgauthzd applies it if it narrows the
// environment's binding — the effective set shows whether it did.
func (s *Server) handleIssuerSave(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_manage_issuers", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	var b issuerBinding
	if !decodeJSON(w, r, &b) {
		return
	}
	b.Issuer = strings.TrimSpace(b.Issuer)
	if b.Issuer == "" {
		writeError(w, http.StatusBadRequest, "issuer is required (the token's iss, as in JWT_ISSUERS)")
		return
	}
	cdr, _ := json.Marshal(orMap(b.ClientDBRoles))
	pep, _ := json.Marshal(orMapList(b.PEPClients))
	var revision int64
	payload := map[string]any{"op": "set", "issuer": b.Issuer, "stores": orList(b.Stores), "enabled": b.Enabled}
	var err error
	if s.adminAPI() {
		// the console's action log records the attempt as the person; the
		// row itself is written by pgauthzd as whoever the credential names
		payload["via"] = "admin-api"
		b.Stores, b.DBRoles, b.ClientDBRoles, b.PEPClients = orList(b.Stores), orList(b.DBRoles), orMap(b.ClientDBRoles), orMapList(b.PEPClients)
		err = s.asPerson(r.Context(), p, "can_manage_issuers", "platform", s.cfg.PlatformID, payload, func(pgx.Tx) error {
			var res struct {
				Revision int64 `json:"revision"`
			}
			if err := s.adminCall(r.Context(), r, "PUT", "/pgauthz/v1/admin/issuer-bindings", b, &res); err != nil {
				return err
			}
			revision = res.Revision
			return nil
		})
	} else {
		err = s.asPerson(r.Context(), p, "can_manage_issuers", "platform", s.cfg.PlatformID, payload, func(tx pgx.Tx) error {
			return tx.QueryRow(r.Context(), `SELECT authz.set_issuer_binding($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8)`,
				b.Issuer, orList(b.Stores), orList(b.DBRoles), string(cdr), string(pep), b.Enabled, nullable(b.Description), p.typ+":"+p.id).Scan(&revision)
		})
	}
	if err != nil {
		if !writeUpstreamError(w, err) {
			writeEngineError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuer": b.Issuer, "revision": revision})
}

// handleIssuerDelete — POST /api/platform/issuers/delete {issuer}: the
// issuer falls back to its environment bindings.
func (s *Server) handleIssuerDelete(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_manage_issuers", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	var req struct {
		Issuer string `json:"issuer"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Issuer = strings.TrimSpace(req.Issuer)
	if req.Issuer == "" {
		writeError(w, http.StatusBadRequest, "issuer is required")
		return
	}
	var existed bool
	var err error
	if s.adminAPI() {
		err = s.asPerson(r.Context(), p, "can_manage_issuers", "platform", s.cfg.PlatformID,
			map[string]any{"op": "delete", "issuer": req.Issuer, "via": "admin-api"}, func(pgx.Tx) error {
				return s.adminCall(r.Context(), r, "DELETE", "/pgauthz/v1/admin/issuer-bindings?issuer="+url.QueryEscape(req.Issuer), nil, nil)
			})
	} else {
		err = s.asPerson(r.Context(), p, "can_manage_issuers", "platform", s.cfg.PlatformID,
			map[string]any{"op": "delete", "issuer": req.Issuer}, func(tx pgx.Tx) error {
				if err := tx.QueryRow(r.Context(), `SELECT authz.delete_issuer_binding($1, $2)`, req.Issuer, p.typ+":"+p.id).Scan(&existed); err != nil {
					return err
				}
				if !existed {
					return errNoSuchBinding
				}
				return nil
			})
	}
	if errors.Is(err, errNoSuchBinding) {
		writeError(w, http.StatusNotFound, "no binding for issuer "+req.Issuer)
		return
	}
	if err != nil {
		if !writeUpstreamError(w, err) {
			writeEngineError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuer": req.Issuer, "deleted": true})
}

var errNoSuchBinding = errors.New("no such binding")

func orList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func orMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func orMapList(m map[string][]string) map[string][]string {
	if m == nil {
		return map[string][]string{}
	}
	return m
}
