package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func pkce() (verifier, challenge string) {
	verifier = randToken(48)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

// handleLogin — GET /auth/login[?issuer=…][&next=…]: the authorization code
// flow at the chosen provider (the platform's without issuer; a registered
// one otherwise, ADR 0017 phase 4). The auth cookie carries the provider so
// the callback exchanges the code at the same one.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ref := strings.TrimSpace(r.URL.Query().Get("issuer"))
	if ref != "" && !strings.HasPrefix(ref, "https://") && !strings.HasPrefix(ref, "http://") {
		if iss, ok := s.issuerAliases(r.Context())[strings.ToLower(ref)]; ok {
			ref = iss // an alias names the provider
		}
	}
	prov, err := s.providerFor(r.Context(), ref)
	if err != nil {
		// No OpenID Provider (the SPA offers the local sign-in instead), or
		// a provider that is unknown or not reachable right now.
		http.Redirect(w, r, s.cfg.BasePath+"/?login_error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	state := randToken(16)
	verifier, challenge := pkce()
	// Remember where the person wanted to go (a deep link into a store).
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, s.cfg.BasePath+"/") || strings.Contains(next, "//") {
		next = s.cfg.BasePath + "/"
	}
	s.setCookie(w, authCookie, prov.Issuer+"|"+state+"|"+verifier+"|"+next, 300)
	s.setCookie(w, signedOutCookie, "", -1)
	q := url.Values{
		"client_id":             {prov.ClientID},
		"redirect_uri":          {s.cfg.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {s.cfg.Scopes},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, prov.meta.AuthURL+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ac, err := r.Cookie(authCookie)
	if err != nil {
		http.Error(w, "missing auth cookie", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(ac.Value, "|", 4)
	if len(parts) != 4 || r.URL.Query().Get("state") != parts[1] {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	prov, err := s.providerFor(r.Context(), parts[0])
	if err != nil {
		http.Error(w, "sign-in provider: "+err.Error(), http.StatusBadGateway)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code: "+r.URL.Query().Get("error"), http.StatusBadRequest)
		return
	}
	t, err := prov.client.Exchange(r.Context(), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {s.cfg.RedirectURI},
		"code_verifier": {parts[2]},
	})
	if err != nil {
		http.Error(w, "token exchange: "+err.Error(), http.StatusBadGateway)
		return
	}
	issuer := prov.Issuer
	if p := s.platformProvider(); p != nil && p.Issuer == issuer {
		issuer = "" // the platform's: the default, as before
	}
	id, err := s.createSession(r.Context(), t, issuer)
	if err != nil {
		http.Error(w, "session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.setCookie(w, authCookie, "", -1)
	s.setCookie(w, sessionCookie, id, int((8 * time.Hour).Seconds()))
	http.Redirect(w, r, parts[3], http.StatusFound)
}

// handleLocalLogin — POST /auth/local {username, password}: the local admin
// sign-in (config.LocalAdmin). Constant-time comparison; 404 while it is not
// configured, so its mere presence tells nothing.
func (s *Server) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.LocalAdminEnabled() {
		http.NotFound(w, r)
		return
	}
	var in struct{ Username, Password string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "username and password expected")
		return
	}
	if !localCredentialsMatch(s.cfg.LocalAdminUser, s.cfg.LocalAdminPassword, in.Username, in.Password) {
		time.Sleep(500 * time.Millisecond) // one shared password: slow a guess down
		writeError(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	id, err := s.createLocalSession(r.Context(), s.cfg.LocalAdminUser)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session: "+err.Error())
		return
	}
	s.setCookie(w, sessionCookie, id, int(localSessionTTL.Seconds()))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// localCredentialsMatch compares both fields in constant time, and only
// reports a match when both match (no early exit on the username).
func localCredentialsMatch(wantUser, wantPass, user, pass string) bool {
	u := subtle.ConstantTimeCompare([]byte(wantUser), []byte(user))
	p := subtle.ConstantTimeCompare([]byte(wantPass), []byte(pass))
	return u&p == 1
}

// loginMethods tells the SPA which sign-ins this deployment offers: the
// providers (one button each) and the local admin sign-in.
func (s *Server) loginMethods(r *http.Request) map[string]any {
	providers, auto := s.signinProviders(r.Context())
	if _, err := r.Cookie(signedOutCookie); err == nil {
		auto = "" // just signed out: show the chooser once
	}
	return map[string]any{"oidc": len(providers) > 0, "local": s.cfg.LocalAdminEnabled(), "providers": providers, "auto_login": auto}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var idToken, issuer string
	local := false
	if se := s.sessionFromReq(r); se != nil {
		idToken, issuer = se.idToken, se.issuer
		local = se.local
		if c, err := r.Cookie(sessionCookie); err == nil {
			s.deleteSession(r.Context(), c.Value)
		}
	}
	s.setCookie(w, sessionCookie, "", -1)
	s.setCookie(w, signedOutCookie, "1", 300)
	prov, err := s.providerFor(r.Context(), issuer)
	if local || err != nil || prov.meta.LogoutURL == "" {
		// Nothing to end at an IdP.
		http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
		return
	}
	q := url.Values{"post_logout_redirect_uri": {s.cfg.BaseURL + s.cfg.BasePath + "/"}, "client_id": {prov.ClientID}}
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	http.Redirect(w, r, prov.meta.LogoutURL+"?"+q.Encode(), http.StatusFound)
}

// handleMe tells the SPA who is logged in and which platform-level areas are
// open to them — decided by the console store, never by the SPA.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	if p == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false, "login": s.loginMethods(r)})
		return
	}
	platform, err := s.capabilities(r.Context(), p, "platform", []string{s.cfg.PlatformID},
		[]string{"can_manage_issuers", "can_view_health", "can_create_store", "can_view_all_stores", "can_manage_access"})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	registry, err := s.capabilities(r.Context(), p, "registry", []string{s.cfg.RegistryID}, []string{"can_view", "can_publish"})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	// sees at least one store group (ADR 0017): the platform's admin, or
	// anyone the reverse search finds a group for — one call, not a check
	// per group on every page load
	groupAdmin := platform[s.cfg.PlatformID]["can_manage_access"]
	if !groupAdmin {
		if names, err := s.groupsReaching(r.Context(), p, "can_view", 1); err == nil {
			groupAdmin = len(names) > 0
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"groups":        map[string]any{"any": groupAdmin}, // sees at least one store group (ADR 0017)
		"username":      p.id,
		"name":          p.name,
		"email":         p.email,
		"subject":       p.typ + ":" + p.id,
		"teams":         p.teams,
		"platform":      platform[s.cfg.PlatformID],
		"registry":      registry[s.cfg.RegistryID],
		"console_store": s.cfg.ConsoleStore,
		"trace_url":     s.cfg.TraceURL,
		// the erasure is a deployment decision (SUBJECT_ERASURE_ENABLED) on
		// top of platform#can_manage_access; the SPA shows it only when both hold
		"subject_erasure": s.cfg.SubjectErasureEnabled,
	})
}
