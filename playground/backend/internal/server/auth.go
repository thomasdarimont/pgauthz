package server

import (
	"crypto/sha256"
	"encoding/base64"
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
	state := randToken(16)
	verifier, challenge := pkce()
	s.setCookie(w, authCookie, state+"|"+verifier, 300)
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
	ac, err := r.Cookie(authCookie)
	if err != nil {
		http.Error(w, "missing auth cookie", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(ac.Value, "|", 2)
	if len(parts) != 2 || r.URL.Query().Get("state") != parts[0] {
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
	http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var idToken string
	if se := s.sessionFromReq(r); se != nil {
		idToken = se.idToken
		if c, err := r.Cookie(sessionCookie); err == nil {
			s.deleteSession(r.Context(), c.Value)
		}
	}
	s.setCookie(w, sessionCookie, "", -1)
	q := url.Values{"post_logout_redirect_uri": {s.cfg.BaseURL + s.cfg.BasePath + "/"}, "client_id": {s.cfg.ClientID}}
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	http.Redirect(w, r, s.endpoints.LogoutURL+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	se := s.sessionFromReq(r)
	if se == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"username":      se.username,
		"subject_type":  claimString(se.accessToken, "subject_type"),
		// Whether this user may use the AuthZEN reverse-search endpoints (UI hint;
		// authzen-opa is the real gate). No SearchRole configured → available to all.
		"search_enabled": s.cfg.SearchRole == "" || tokenHasRole(se.accessToken, s.cfg.SearchRole),
	})
}
