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
	"slices"
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
	Alias         string              `json:"alias,omitempty"` // a short handle for the issuer (migration 0031)
	Stores        []string            `json:"stores"`
	DBRoles       []string            `json:"db_roles"`
	ClientDBRoles map[string]string   `json:"client_db_roles"`
	PEPClients    map[string][]string `json:"pep_clients"`
	Enabled       bool                `json:"enabled"`
	Description   string              `json:"description"`
	// group issuers (ADR 0017): the group whose stores the issuer reaches
	// (stores then come from the engine), its own anchor, delegated rules
	StoreGroup string          `json:"store_group,omitempty"`
	JWKSURL    string          `json:"jwks_url,omitempty"`
	Audience   string          `json:"audience,omitempty"`
	Audiences  []string        `json:"audiences,omitempty"`
	Admin      json.RawMessage `json:"admin,omitempty"`
	CreatedAt  *time.Time      `json:"created_at,omitempty"`
	CreatedBy  string          `json:"created_by,omitempty"`
	UpdatedAt  *time.Time      `json:"updated_at,omitempty"`
	UpdatedBy  string          `json:"updated_by,omitempty"`
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
	StoreGroup  string    `json:"store_group,omitempty"` // the group the row belonged to when written
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
// issuerManager resolves who may open Platform → Issuers: the platform's
// issuer admins, or (ADR 0017) anyone the console store grants
// can_manage_issuers on at least one store group — they see and manage
// their groups' issuers. Returns the person, whether they are the
// platform's, and the groups they manage (every group for the platform's).
func (s *Server) issuerManager(w http.ResponseWriter, r *http.Request) (*principal, bool, []string) {
	p := s.principal(r)
	if p == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return nil, false, nil
	}
	ctx := r.Context()
	platform, err := s.can(ctx, p, "can_manage_issuers", "platform", s.cfg.PlatformID)
	if err != nil {
		writeEngineError(w, err)
		return nil, false, nil
	}
	managed := []string{}
	if !platform {
		// the groups whose identity providers the person manages, by the
		// engine's reverse search (one call, however many groups there are)
		names, err := s.groupsReaching(ctx, p, "can_manage_issuers", 0)
		if err != nil {
			writeEngineError(w, err)
			return nil, false, nil
		}
		managed = names
	}
	if !platform && len(managed) == 0 {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "this needs can_manage_issuers on platform:" + s.cfg.PlatformID + " or on a store group", "required": "can_manage_issuers", "object": "platform:" + s.cfg.PlatformID})
		return nil, false, nil
	}
	return p, platform, managed
}

func (s *Server) handleIssuers(w http.ResponseWriter, r *http.Request) {
	p, platform, managed := s.issuerManager(w, r)
	if p == nil {
		return
	}
	ctx := r.Context()
	known := s.knownForBindings(ctx)
	known["groups"] = managed
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
			"known":     known,
			"platform":  platform,
			"signin":    s.signinRows(ctx, platform, managed),
		})
		return
	}
	bindings, err := s.issuerBindings(ctx)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if !platform { // a group admin sees the rows of their groups only
		mine := map[string]bool{}
		for _, g := range managed {
			mine[g] = true
		}
		kept := []issuerBinding{}
		for _, b := range bindings {
			if b.StoreGroup != "" && mine[b.StoreGroup] {
				kept = append(kept, b)
			}
		}
		bindings = kept
	}
	var revision int64
	if err := s.engine.QueryRow(ctx, `SELECT authz.issuer_bindings_revision()`).Scan(&revision); err != nil {
		writeEngineError(w, err)
		return
	}
	effective := s.effectiveIssuers(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"bindings":  bindings,
		"revision":  revision,
		"effective": effective,
		"via":       "db",
		"known":     known,
		"platform":  platform,
		"signin":    s.signinRows(ctx, platform, managed),
	})
}

// handleIssuerDiscover — GET /api/platform/issuers/discover?issuer=…: the
// provider's OpenID discovery document, so the form fills the JWKS URL
// from the issuer URL instead of asking a person to find it. Fetched by
// the console (which trusts the deployment's CA), reported as data: the
// person still saves the row.
func (s *Server) handleIssuerDiscover(w http.ResponseWriter, r *http.Request) {
	if p, _, _ := s.issuerManager(w, r); p == nil {
		return
	}
	issuer := strings.TrimRight(strings.TrimSpace(r.URL.Query().Get("issuer")), "/")
	if !strings.HasPrefix(issuer, "https://") {
		writeError(w, http.StatusBadRequest, "issuer must be an https:// URL")
		return
	}
	// the discovery document: the issuer's well-known location by default,
	// or a URL the operator names (a provider that serves it elsewhere, a
	// proxy); the document's own `issuer` is reported, and whether it is
	// the configured one — tokens carry that `iss`, so a mismatch means
	// the binding would never match a token
	disc := strings.TrimSpace(r.URL.Query().Get("url"))
	if disc == "" {
		disc = issuer + "/.well-known/openid-configuration"
	} else if !strings.HasPrefix(disc, "https://") {
		writeError(w, http.StatusBadRequest, "the discovery URL must be an https:// URL")
		return
	}
	if err := s.outboundAllowed(r.Context(), disc); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disc, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Header.Set("Accept", "application/json")
	hc := s.outbound
	if hc == nil {
		hc = noRedirects(s.http)
	}
	resp, err := hc.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "discovery failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, "discovery answered "+resp.Status)
		return
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, resp.Body, 1<<20)).Decode(&doc); err != nil {
		writeError(w, http.StatusBadGateway, "discovery document did not decode: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuer": doc.Issuer, "jwks_uri": doc.JWKSURI, "discovery_url": disc, "matches": strings.TrimRight(doc.Issuer, "/") == issuer})
}

// knownForBindings: what a binding's lists can be picked from instead of
// typed — the live stores, and the per-application DB roles (the NOLOGIN
// roles that inherit authz_reader: app_dms, …; the engine's own authz_*
// roles and the daemons' login roles are not what a token claims).
// Patterns stay typed; the form adds a picked name as one line.
func (s *Server) knownForBindings(ctx context.Context) map[string]any {
	names := func(sql string) []string {
		out := []string{}
		rows, err := s.engine.Query(ctx, sql)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				out = append(out, n)
			}
		}
		return out
	}
	return map[string]any{
		"stores": names(`SELECT name FROM authz.list_stores() WHERE retired_at IS NULL ORDER BY 1`),
		"db_roles": names(`SELECT r.rolname FROM pg_roles r
			 WHERE NOT r.rolcanlogin AND NOT r.rolsuper
			   AND r.rolname NOT LIKE 'pg\_%' AND r.rolname NOT LIKE 'authz\_%'
			   AND pg_has_role(r.oid, 'authz_reader', 'MEMBER')
			 ORDER BY 1`),
	}
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
	// the platform's issuer admins read everything; a group's issuer admins
	// (ADR 0017) the rows written while an issuer belonged to their groups
	p, platform, managed := s.issuerManager(w, r)
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
	var groups []string
	if !platform {
		groups = managed // never another group's doings with an issuer, before or after a transfer
	}
	rows, err := s.issuerAudit(r.Context(), issuer, groups, limit, before)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	var grp any
	if groups != nil {
		grp = groups
	}
	var total int64
	if err := s.engine.QueryRow(r.Context(), `SELECT authz.count_issuer_bindings_audit($1, $2)`, nullable(issuer), grp).Scan(&total); err != nil {
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
		       created_at, coalesce(created_by, ''), updated_at, coalesce(updated_by, ''),
		       coalesce(store_group, ''), coalesce(jwks_url, ''), coalesce(audience, ''), audiences, admin, coalesce(alias, '')
		  FROM authz.list_issuer_bindings()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []issuerBinding{}
	for rows.Next() {
		var b issuerBinding
		var admin []byte
		if err := rows.Scan(&b.Issuer, &b.Stores, &b.DBRoles, &b.ClientDBRoles, &b.PEPClients, &b.Enabled, &b.Description,
			&b.CreatedAt, &b.CreatedBy, &b.UpdatedAt, &b.UpdatedBy, &b.StoreGroup, &b.JWKSURL, &b.Audience, &b.Audiences, &admin, &b.Alias); err != nil {
			return nil, err
		}
		if len(admin) > 0 && string(admin) != "[]" {
			b.Admin = json.RawMessage(admin)
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

// issuerAudit: one page of the history; groups (nil = all) narrows to the
// rows written while the issuer belonged to one of them.
func (s *Server) issuerAudit(ctx context.Context, issuer string, groups []string, limit int, before *int64) ([]issuerAuditRow, error) {
	var grp any
	if groups != nil {
		grp = groups
	}
	rows, err := s.engine.Query(ctx, `
		SELECT seq, action, performed_at, performed_by, issuer, stores, enabled, coalesce(description, ''), coalesce(store_group, '')
		  FROM authz.list_issuer_bindings_audit($1, $2, $3, $4)`, nullable(issuer), limit, before, grp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []issuerAuditRow{}
	for rows.Next() {
		var a issuerAuditRow
		if err := rows.Scan(&a.Seq, &a.Action, &a.PerformedAt, &a.PerformedBy, &a.Issuer, &a.Stores, &a.Enabled, &a.Description, &a.StoreGroup); err != nil {
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
	p, platform, _ := s.issuerManager(w, r)
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
	// Ownership (review P1): an existing row is changed by whoever manages
	// it AS IT IS — the platform, or the admins of the group it belongs to;
	// moving it to another group (or binding a platform issuer to a group)
	// is the platform's alone. The group authorized against travels to the
	// engine, which refuses the write if the row changed hands meanwhile
	// (409). A new group issuer is its group's business.
	cur, exists, err := s.bindingRow(r.Context(), b.Issuer)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	expectGroup := ""
	if exists {
		expectGroup = cur.StoreGroup
	}
	objType, objID := "platform", s.cfg.PlatformID
	if !platform {
		switch {
		case exists && cur.StoreGroup == "":
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "this binding is the platform's: changing it needs can_manage_issuers on platform:" + s.cfg.PlatformID, "required": "can_manage_issuers", "object": "platform:" + s.cfg.PlatformID})
			return
		case exists && b.StoreGroup != cur.StoreGroup:
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "moving an issuer to another store group is a platform decision (can_manage_issuers on platform:" + s.cfg.PlatformID + ")", "required": "can_manage_issuers", "object": "platform:" + s.cfg.PlatformID})
			return
		case exists:
			objType, objID = "group", cur.StoreGroup
		case b.StoreGroup == "" || b.JWKSURL == "":
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "a platform issuer needs can_manage_issuers on platform:" + s.cfg.PlatformID + "; a group issuer you manage brings its own trust anchor (store group + JWKS URL)", "required": "can_manage_issuers", "object": "platform:" + s.cfg.PlatformID})
			return
		default:
			objType, objID = "group", b.StoreGroup
		}
	}
	if ok, err := s.can(r.Context(), p, "can_manage_issuers", objType, objID); err != nil || !ok {
		if err != nil {
			writeEngineError(w, err)
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "this needs can_manage_issuers on " + objType + ":" + objID, "required": "can_manage_issuers", "object": objType + ":" + objID})
		return
	}
	cdr, _ := json.Marshal(orMap(b.ClientDBRoles))
	pep, _ := json.Marshal(orMapList(b.PEPClients))
	var revision int64
	payload := map[string]any{"op": "set", "issuer": b.Issuer, "stores": orList(b.Stores), "enabled": b.Enabled}
	if s.adminAPI() {
		// the console's action log records the attempt as the person; the
		// row itself is written by pgauthzd as whoever the credential names
		payload["via"] = "admin-api"
		b.Stores, b.DBRoles, b.ClientDBRoles, b.PEPClients = orList(b.Stores), orList(b.DBRoles), orMap(b.ClientDBRoles), orMapList(b.PEPClients)
		err = s.asPerson(r.Context(), p, "can_manage_issuers", objType, objID, payload, func(pgx.Tx) error {
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
		admin := "[]"
		if len(b.Admin) > 0 {
			admin = string(b.Admin)
		}
		err = s.asPerson(r.Context(), p, "can_manage_issuers", objType, objID, payload, func(tx pgx.Tx) error {
			// what the gate found travels with the write: a create that does
			// nothing on conflict, or an update conditional on the owner (409 otherwise)
			return tx.QueryRow(r.Context(), `SELECT authz.set_issuer_binding($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15, $16)`,
				b.Issuer, orList(b.Stores), orList(b.DBRoles), string(cdr), string(pep), b.Enabled, nullable(b.Description), p.typ+":"+p.id,
				nullable(b.StoreGroup), nullable(b.JWKSURL), nullable(b.Audience), orList(b.Audiences), admin, nullable(strings.ToLower(strings.TrimSpace(b.Alias))), expectGroup, exists).Scan(&revision)
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

// bindingRow: the current row of an issuer (URL or alias), if any — the
// engine's view, which both modes decide ownership against.
func (s *Server) bindingRow(ctx context.Context, issuer string) (issuerBinding, bool, error) {
	rows, err := s.issuerBindings(ctx)
	if err != nil {
		return issuerBinding{}, false, err
	}
	var resolved string
	if err := s.engine.QueryRow(ctx, `SELECT coalesce(authz.resolve_issuer($1), $1)`, issuer).Scan(&resolved); err != nil {
		return issuerBinding{}, false, err
	}
	for _, b := range rows {
		if b.Issuer == resolved {
			return b, true, nil
		}
	}
	return issuerBinding{}, false, nil
}

// handleIssuerDelete — POST /api/platform/issuers/delete {issuer}: the
// issuer falls back to its environment bindings.
func (s *Server) handleIssuerDelete(w http.ResponseWriter, r *http.Request) {
	p, platform, managed := s.issuerManager(w, r)
	if p == nil {
		return
	}
	var req struct {
		Issuer     string `json:"issuer"`
		StoreGroup string `json:"store_group"` // the row's group: a group admin removes their group's rows
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Issuer = strings.TrimSpace(req.Issuer)
	if req.Issuer == "" {
		writeError(w, http.StatusBadRequest, "issuer is required")
		return
	}
	// the row's group as it IS decides who may remove it (not the group
	// the request names); the engine re-checks it under the row lock
	cur, exists, err := s.bindingRow(r.Context(), req.Issuer)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	expectGroup := "*"
	if exists {
		expectGroup = cur.StoreGroup
	}
	if !platform {
		if !exists || cur.StoreGroup == "" || !slices.Contains(managed, cur.StoreGroup) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "removing this binding needs can_manage_issuers on platform:" + s.cfg.PlatformID + ", or on the row's store group", "required": "can_manage_issuers", "object": "platform:" + s.cfg.PlatformID})
			return
		}
		req.StoreGroup = cur.StoreGroup
	}
	var existed bool
	if s.adminAPI() {
		err = s.asPerson(r.Context(), p, "can_manage_issuers", "platform", s.cfg.PlatformID,
			map[string]any{"op": "delete", "issuer": req.Issuer, "via": "admin-api"}, func(pgx.Tx) error {
				return s.adminCall(r.Context(), r, "DELETE", "/pgauthz/v1/admin/issuer-bindings?issuer="+url.QueryEscape(req.Issuer), nil, nil)
			})
	} else {
		err = s.asPerson(r.Context(), p, "can_manage_issuers", "platform", s.cfg.PlatformID,
			map[string]any{"op": "delete", "issuer": req.Issuer}, func(tx pgx.Tx) error {
				if err := tx.QueryRow(r.Context(), `SELECT authz.delete_issuer_binding($1, $2, $3)`, req.Issuer, p.typ+":"+p.id, expectGroup).Scan(&existed); err != nil {
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
