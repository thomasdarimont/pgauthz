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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		// No OpenID Provider: the SPA offers the local sign-in instead.
		http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
		return
	}
	state := randToken(16)
	verifier, challenge := pkce()
	// Remember where the person wanted to go (a deep link into a store).
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, s.cfg.BasePath+"/") || strings.Contains(next, "//") {
		next = s.cfg.BasePath + "/"
	}
	s.setCookie(w, authCookie, state+"|"+verifier+"|"+next, 300)
	q := url.Values{
		"client_id":             {s.cfg.ClientID},
		"redirect_uri":          {s.cfg.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {s.cfg.Scopes},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, s.endpoints.AuthURL+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	ac, err := r.Cookie(authCookie)
	if err != nil {
		http.Error(w, "missing auth cookie", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(ac.Value, "|", 3)
	if len(parts) != 3 || r.URL.Query().Get("state") != parts[0] {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code: "+r.URL.Query().Get("error"), http.StatusBadRequest)
		return
	}
	t, err := s.oidc.Exchange(r.Context(), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {s.cfg.RedirectURI},
		"code_verifier": {parts[1]},
	})
	if err != nil {
		http.Error(w, "token exchange: "+err.Error(), http.StatusBadGateway)
		return
	}
	id, err := s.createSession(r.Context(), t)
	if err != nil {
		http.Error(w, "session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.setCookie(w, authCookie, "", -1)
	s.setCookie(w, sessionCookie, id, int((8 * time.Hour).Seconds()))
	http.Redirect(w, r, parts[2], http.StatusFound)
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

// loginMethods tells the SPA which sign-ins this deployment offers.
func (s *Server) loginMethods() map[string]any {
	return map[string]any{"oidc": s.oidc != nil, "local": s.cfg.LocalAdminEnabled()}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var idToken string
	local := false
	if se := s.sessionFromReq(r); se != nil {
		idToken = se.idToken
		local = se.local
		if c, err := r.Cookie(sessionCookie); err == nil {
			s.deleteSession(r.Context(), c.Value)
		}
	}
	s.setCookie(w, sessionCookie, "", -1)
	if local || s.oidc == nil || s.endpoints.LogoutURL == "" {
		// Nothing to end at an IdP.
		http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
		return
	}
	q := url.Values{"post_logout_redirect_uri": {s.cfg.BaseURL + s.cfg.BasePath + "/"}, "client_id": {s.cfg.ClientID}}
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	http.Redirect(w, r, s.endpoints.LogoutURL+"?"+q.Encode(), http.StatusFound)
}

// handleMe tells the SPA who is logged in and which platform-level areas are
// open to them — decided by the console store, never by the SPA.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	if p == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false, "login": s.loginMethods()})
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
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"username":      p.id,
		"name":          p.name,
		"subject":       p.typ + ":" + p.id,
		"teams":         p.teams,
		"platform":      platform[s.cfg.PlatformID],
		"registry":      registry[s.cfg.RegistryID],
		"console_store": s.cfg.ConsoleStore,
	})
}
