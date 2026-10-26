package server

// Sign-in providers (ADR 0017, phase 4): the console authenticates people
// through more than one OpenID Connect provider — the platform's (ISSUER /
// CLIENT_ID / CLIENT_SECRET from the environment) and the providers the
// console keeps in its own database, one per group issuer whose admins
// registered the console as a client there. The sign-in page offers one
// button per provider; a session remembers which one signed it in, so a
// refresh and the logout go back to the right place. Discovery runs on
// demand with a short timeout and is cached; a provider that does not
// answer is left off the sign-in page until it does. One provider may be
// the auto-login one (CONSOLE_AUTO_LOGIN for the platform's, the row's
// auto_login for a registered one): a signed-out visitor goes straight
// there; the chooser stays reachable at ?login=select and after a sign-out,
// and ?login=<issuer> is a deep link into one provider (a tenant's bookmark).
//
//   GET  /api/providers                          the sign-in buttons (public)
//   PUT  /api/platform/issuers/signin            {issuer, store_group, label, client_id, client_secret, enabled, auto_login, discovery_url}
//   POST /api/platform/issuers/signin/delete     {issuer, store_group}
//
// Who the signed-in person is comes from the ID token the way it does for
// the platform's provider (CONSOLE_SUBJECT_ID_CLAIMS / _CEL, the team
// claims), so the delegated admin rule pgauthzd holds for the same issuer
// must derive the same id.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"thomasdarimont.de/authz/console-bff/internal/oidc"
)

type signinProvider struct {
	Issuer   string `json:"issuer"`
	Label    string `json:"label"`
	Group    string `json:"store_group,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Enabled  bool   `json:"enabled"`
	// AutoLogin: a signed-out visitor is sent here without the chooser
	// (the platform's: CONSOLE_AUTO_LOGIN). At most one provider wins.
	AutoLogin bool `json:"auto_login"`
	// DiscoveryURL: where the provider's openid-configuration is, when not
	// at the issuer's well-known location (empty = derived from the issuer).
	DiscoveryURL string `json:"discovery_url,omitempty"`
	secret       string
	meta         oidc.Metadata
	client       *oidc.Client
	fetched      time.Time
	err          error
}

type providerCache struct {
	mu sync.Mutex
	m  map[string]*signinProvider
}

const providerTTL, providerErrTTL = 10 * time.Minute, time.Minute

// platformProvider is the environment's provider, the one every
// deployment starts with; nil without ISSUER.
func (s *Server) platformProvider() *signinProvider {
	if s.oidc == nil {
		return nil
	}
	auto := strings.EqualFold(s.cfg.AutoLogin, "true") || strings.TrimRight(s.cfg.AutoLogin, "/") == strings.TrimRight(s.cfg.Issuer, "/")
	return &signinProvider{Issuer: s.cfg.Issuer, Label: s.cfg.ProviderName(), ClientID: s.cfg.ClientID, Enabled: true, AutoLogin: auto, meta: s.endpoints, client: s.oidc}
}

// dbProviders reads the registered providers (secrets included: the
// callers write them to tokens, never to responses).
func (s *Server) dbProviders(ctx context.Context) ([]signinProvider, error) {
	if s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Query(ctx, `SELECT issuer, coalesce(label, ''), coalesce(store_group, ''), client_id, client_secret, enabled, auto_login, coalesce(discovery_url, '') FROM console_providers ORDER BY issuer`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []signinProvider
	for rows.Next() {
		var p signinProvider
		if err := rows.Scan(&p.Issuer, &p.Label, &p.Group, &p.ClientID, &p.secret, &p.Enabled, &p.AutoLogin, &p.DiscoveryURL); err != nil {
			return nil, err
		}
		if p.Label == "" {
			p.Label = p.Group
		}
		if p.Label == "" {
			p.Label = p.Issuer
		}
		// the environment may name a registered provider as the auto-login one
		p.AutoLogin = p.AutoLogin || strings.TrimRight(s.cfg.AutoLogin, "/") == strings.TrimRight(p.Issuer, "/")
		out = append(out, p)
	}
	return out, rows.Err()
}

// discoverOnce: one bounded discovery fetch (oidc.Discover retries for the
// startup case; a registered provider must not stall the sign-in page).
// The document is read at the issuer's well-known location, or at the URL
// the registration names; a document naming another issuer is refused —
// its tokens would carry that iss and never match.
func (s *Server) discoverOnce(ctx context.Context, issuer, discoveryURL string) (oidc.Metadata, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if discoveryURL == "" {
		discoveryURL = strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return oidc.Metadata{}, err
	}
	hc := s.http
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return oidc.Metadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidc.Metadata{}, errors.New("discovery answered " + resp.Status)
	}
	var m oidc.Metadata
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&m); err != nil {
		return oidc.Metadata{}, err
	}
	if m.AuthURL == "" || m.TokenURL == "" {
		return oidc.Metadata{}, errors.New("discovery document names no authorization or token endpoint")
	}
	if m.Issuer != "" && strings.TrimRight(m.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return oidc.Metadata{}, errors.New("discovery document names issuer " + m.Issuer + ", not " + issuer)
	}
	return m, nil
}

// providerFor resolves a sign-in provider by issuer ("" = the platform's),
// discovering and caching a registered one. Not found or not reachable
// is an error the login handler turns into a plain refusal.
func (s *Server) providerFor(ctx context.Context, issuer string) (*signinProvider, error) {
	if issuer == "" || (s.oidc != nil && issuer == s.cfg.Issuer) {
		if p := s.platformProvider(); p != nil {
			return p, nil
		}
		return nil, errors.New("no OpenID provider is configured")
	}
	rows, err := s.dbProviders(ctx)
	if err != nil {
		return nil, err
	}
	var row *signinProvider
	for i := range rows {
		if rows[i].Issuer == issuer && rows[i].Enabled {
			row = &rows[i]
		}
	}
	if row == nil {
		return nil, errors.New("unknown or disabled sign-in provider " + issuer)
	}
	s.prov.mu.Lock()
	defer s.prov.mu.Unlock()
	if s.prov.m == nil {
		s.prov.m = map[string]*signinProvider{}
	}
	c := s.prov.m[issuer]
	ttl := providerTTL
	if c != nil && c.err != nil {
		ttl = providerErrTTL
	}
	if c == nil || time.Since(c.fetched) > ttl || c.ClientID != row.ClientID || c.secret != row.secret || c.DiscoveryURL != row.DiscoveryURL {
		meta, err := s.discoverOnce(ctx, issuer, row.DiscoveryURL)
		c = &signinProvider{Issuer: issuer, Label: row.Label, Group: row.Group, ClientID: row.ClientID, Enabled: true, AutoLogin: row.AutoLogin, DiscoveryURL: row.DiscoveryURL, secret: row.secret, meta: meta, fetched: time.Now(), err: err}
		if err == nil {
			hc := s.http
			if hc == nil {
				hc = http.DefaultClient
			}
			c.client = &oidc.Client{HTTP: hc, ClientID: row.ClientID, ClientSecret: row.secret, TokenURL: meta.TokenURL}
		}
		s.prov.m[issuer] = c
	}
	if c.err != nil {
		return nil, c.err
	}
	c.AutoLogin = row.AutoLogin // the row may have changed without a rediscovery
	return c, nil
}

// signinProviders: what the sign-in page offers — the platform's provider
// and every registered, enabled, reachable one — and which of them, if
// any, signs a visitor in without the chooser (the first marked one; the
// platform's first).
func (s *Server) signinProviders(ctx context.Context) ([]map[string]any, string) {
	out := []map[string]any{}
	auto := ""
	add := func(p *signinProvider) {
		m := map[string]any{"issuer": p.Issuer, "label": p.Label}
		if p.Group != "" {
			m["store_group"] = p.Group
		}
		if p.AutoLogin && auto == "" {
			auto = p.Issuer
			m["auto_login"] = true
		}
		out = append(out, m)
	}
	if p := s.platformProvider(); p != nil {
		add(p)
	}
	rows, err := s.dbProviders(ctx)
	if err != nil {
		return out, auto
	}
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		if p, err := s.providerFor(ctx, r.Issuer); err == nil {
			add(p)
		}
	}
	return out, auto
}

// signedOutCookie marks a browser that just signed out: the next visit
// shows the chooser even with auto-login, so a sign-out does not bounce
// straight back into the provider. Cleared by the next login.
const signedOutCookie = "pgc_signed_out"

func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	providers, auto := s.signinProviders(r.Context())
	if _, err := r.Cookie(signedOutCookie); err == nil {
		auto = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": providers, "auto_login": auto})
}

// signinRows: the registered providers for the Issuers tab (no secrets),
// the platform's view or a group admin's groups.
func (s *Server) signinRows(ctx context.Context, platform bool, managed []string) map[string]signinProvider {
	out := map[string]signinProvider{}
	rows, err := s.dbProviders(ctx)
	if err != nil {
		return out
	}
	mine := map[string]bool{}
	for _, g := range managed {
		mine[g] = true
	}
	for _, r := range rows {
		if platform || (r.Group != "" && mine[r.Group]) {
			r.secret = ""
			out[r.Issuer] = r
		}
	}
	return out
}

type signinReq struct {
	Issuer       string `json:"issuer"`
	StoreGroup   string `json:"store_group"`
	Label        string `json:"label"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // empty keeps the stored one
	Enabled      bool   `json:"enabled"`
	AutoLogin    bool   `json:"auto_login"`
	DiscoveryURL string `json:"discovery_url"` // optional: where openid-configuration is
}

// handleSigninSave registers (or updates) the console as a client at an
// issuer: the platform's issuer admins for any issuer, a group's admins for
// the group's issuers.
func (s *Server) handleSigninSave(w http.ResponseWriter, r *http.Request) {
	p, platform, _ := s.issuerManager(w, r)
	if p == nil {
		return
	}
	var req signinReq
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Issuer = strings.TrimSpace(req.Issuer)
	if !strings.HasPrefix(req.Issuer, "https://") || strings.TrimSpace(req.ClientID) == "" {
		writeError(w, http.StatusBadRequest, "issuer (https) and client_id are required")
		return
	}
	req.DiscoveryURL = strings.TrimSpace(req.DiscoveryURL)
	if req.DiscoveryURL != "" && !strings.HasPrefix(req.DiscoveryURL, "https://") {
		writeError(w, http.StatusBadRequest, "discovery_url must be an https:// URL")
		return
	}
	objType, objID := "platform", s.cfg.PlatformID
	if !platform {
		if req.StoreGroup == "" {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "registering the console at a platform issuer needs can_manage_issuers on platform:" + s.cfg.PlatformID, "required": "can_manage_issuers", "object": "platform:" + s.cfg.PlatformID})
			return
		}
		objType, objID = "group", req.StoreGroup
		if ok, err := s.can(r.Context(), p, "can_manage_issuers", objType, objID); err != nil || !ok {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "this needs can_manage_issuers on " + objType + ":" + objID, "required": "can_manage_issuers", "object": objType + ":" + objID})
			return
		}
	}
	by := p.typ + ":" + p.id
	// the console store's action log records the change (asPerson); the row
	// lives in the console's own database (not the same transaction)
	err := s.asPerson(r.Context(), p, "can_manage_issuers", objType, objID, map[string]any{"op": "signin_set", "issuer": req.Issuer, "enabled": req.Enabled}, func(pgx.Tx) error {
		_, err := s.db.Exec(r.Context(), `
			INSERT INTO console_providers (issuer, label, store_group, client_id, client_secret, enabled, auto_login, discovery_url, created_by, updated_by)
			VALUES ($1, $2, nullif($3, ''), $4, $5, $6, $7, nullif($8, ''), $9, $9)
			ON CONFLICT (issuer) DO UPDATE SET label = EXCLUDED.label, store_group = EXCLUDED.store_group, client_id = EXCLUDED.client_id,
			    client_secret = CASE WHEN EXCLUDED.client_secret = '' THEN console_providers.client_secret ELSE EXCLUDED.client_secret END,
			    enabled = EXCLUDED.enabled, auto_login = EXCLUDED.auto_login, discovery_url = EXCLUDED.discovery_url, updated_at = now(), updated_by = EXCLUDED.updated_by`,
			req.Issuer, strings.TrimSpace(req.Label), req.StoreGroup, strings.TrimSpace(req.ClientID), req.ClientSecret, req.Enabled, req.AutoLogin, req.DiscoveryURL, by)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	s.prov.mu.Lock()
	delete(s.prov.m, req.Issuer)
	s.prov.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"issuer": req.Issuer, "ok": true})
}

func (s *Server) handleSigninDelete(w http.ResponseWriter, r *http.Request) {
	p, platform, managed := s.issuerManager(w, r)
	if p == nil {
		return
	}
	var req struct {
		Issuer     string `json:"issuer"`
		StoreGroup string `json:"store_group"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !platform {
		ok := false
		for _, g := range managed {
			ok = ok || (req.StoreGroup != "" && g == req.StoreGroup)
		}
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "removing this sign-in needs can_manage_issuers on platform:" + s.cfg.PlatformID + ", or on its store group", "required": "can_manage_issuers", "object": "platform:" + s.cfg.PlatformID})
			return
		}
	}
	tag, err := s.db.Exec(r.Context(), `DELETE FROM console_providers WHERE issuer = $1 AND ($2 = '' OR store_group = $2)`, req.Issuer, req.StoreGroup)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	s.prov.mu.Lock()
	delete(s.prov.m, req.Issuer)
	s.prov.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"issuer": req.Issuer, "deleted": tag.RowsAffected() > 0})
}
