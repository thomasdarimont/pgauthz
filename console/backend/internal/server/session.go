package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"thomasdarimont.de/authz/console-bff/internal/oidc"
)

const sessionCookie = "pgc_session"
const authCookie = "pgc_auth"

// InitSchema creates the session table in the BFF's own database.
func InitSchema(ctx context.Context, db *pgxpool.Pool) error {
	_, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS sessions (
			id            text PRIMARY KEY,
			access_token  text NOT NULL,
			refresh_token text,
			id_token      text,
			username      text,
			expires_at    timestamptz NOT NULL,
			created_at    timestamptz NOT NULL DEFAULT now()
		)`)
	if err != nil {
		return err
	}
	// local: a session of the local admin sign-in (no token; memberships from
	// the configuration). Existing tables gain the column.
	if _, err = db.Exec(ctx, `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS local boolean NOT NULL DEFAULT false`); err != nil {
		return err
	}
	// issuer: the sign-in provider of the session (ADR 0017 phase 4); '' = the platform's
	if _, err = db.Exec(ctx, `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS issuer text NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	// console_providers: the sign-in providers registered besides the
	// platform's — a group issuer's admins register the console as a client
	// at their identity provider (providers.go). Secrets stay here, like the
	// sessions' tokens.
	if _, err = db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS console_providers (
			issuer        text PRIMARY KEY,
			label         text,
			store_group   text,
			client_id     text NOT NULL,
			client_secret text NOT NULL DEFAULT '',
			enabled       boolean NOT NULL DEFAULT true,
			created_at    timestamptz NOT NULL DEFAULT now(),
			created_by    text,
			updated_at    timestamptz NOT NULL DEFAULT now(),
			updated_by    text
		)`); err != nil {
		return err
	}
	if _, err = db.Exec(ctx, `ALTER TABLE console_providers ADD COLUMN IF NOT EXISTS auto_login boolean NOT NULL DEFAULT false,
		ADD COLUMN IF NOT EXISTS discovery_url text`); err != nil {
		return err
	}
	// scenarios: one tests.authz.yaml per managed store (scenarios.go).
	_, err = db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS scenarios (
			store      text PRIMARY KEY,
			yaml       text NOT NULL,
			updated_at timestamptz NOT NULL DEFAULT now(),
			updated_by text
		)`)
	return err
}

type session struct {
	id           string
	accessToken  string
	refreshToken string
	idToken      string
	username     string
	expiresAt    time.Time
	local        bool
	issuer       string // the provider that signed the session in ("" = the platform's)
}

// createLocalSession opens a session for the local admin sign-in: no token,
// a fixed lifetime, no refresh.
func (s *Server) createLocalSession(ctx context.Context, username string) (string, error) {
	id := randToken(32)
	_, err := s.db.Exec(ctx,
		`INSERT INTO sessions (id, access_token, username, expires_at, local) VALUES ($1, '', $2, $3, true)`,
		id, username, time.Now().Add(localSessionTTL))
	return id, err
}

const localSessionTTL = 8 * time.Hour

// createSession opens a session for a signed-in person. Who they are comes
// from the ID token — the claims OpenID Connect issues to the relying party
// (the console) — never from the access token, which is for the API and
// whose claims an identity provider shapes for the API's needs.
func (s *Server) createSession(ctx context.Context, t *oidc.TokenResp, issuer string) (string, error) {
	id := randToken(32)
	exp := time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	user, err := s.subjectID(claimMap(t.IDToken))
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(ctx,
		`INSERT INTO sessions (id, access_token, refresh_token, id_token, username, expires_at, issuer)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, t.AccessToken, t.RefreshToken, t.IDToken, user, exp, issuer)
	return id, err
}

func (s *Server) getSession(ctx context.Context, id string) (*session, error) {
	var se session
	err := s.db.QueryRow(ctx,
		`SELECT id, access_token, coalesce(refresh_token,''), coalesce(id_token,''), coalesce(username,''), expires_at, local, coalesce(issuer,'')
		 FROM sessions WHERE id=$1`, id).
		Scan(&se.id, &se.accessToken, &se.refreshToken, &se.idToken, &se.username, &se.expiresAt, &se.local, &se.issuer)
	if err != nil {
		return nil, err
	}
	if se.local {
		// Deactivated (the variables were unset) or run out: gone, no refresh.
		if !s.cfg.LocalAdminEnabled() || time.Now().After(se.expiresAt) {
			s.deleteSession(ctx, se.id)
			return nil, errSessionExpired
		}
		return &se, nil
	}
	// Refresh when the access token is about to expire: the memberships that
	// drive authorization come from the token, so they stay current too. An
	// expired token that cannot be renewed ends the session — the browser
	// cookie may live longer, the authorization data behind it may not.
	if time.Until(se.expiresAt) < 30*time.Second {
		if se.refreshToken == "" {
			if time.Now().After(se.expiresAt) {
				s.deleteSession(ctx, se.id)
				return nil, errSessionExpired
			}
			return &se, nil
		}
		prov, err := s.providerFor(ctx, se.issuer)
		if err != nil {
			s.deleteSession(ctx, se.id)
			return nil, err
		}
		t, err := prov.client.Refresh(ctx, se.refreshToken)
		if err != nil {
			s.deleteSession(ctx, se.id)
			return nil, err
		}
		se.accessToken = t.AccessToken
		se.expiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
		if t.RefreshToken != "" {
			se.refreshToken = t.RefreshToken
		}
		if t.IDToken != "" {
			se.idToken = t.IDToken // renewed memberships, as the access token's expiry intends
		}
		_, _ = s.db.Exec(ctx, `UPDATE sessions SET access_token=$2, refresh_token=$3, id_token=$4, expires_at=$5 WHERE id=$1`,
			se.id, se.accessToken, se.refreshToken, se.idToken, se.expiresAt)
	}
	return &se, nil
}

var errSessionExpired = errors.New("session expired")

func (s *Server) deleteSession(ctx context.Context, id string) {
	_, _ = s.db.Exec(ctx, `DELETE FROM sessions WHERE id=$1`, id)
}

func (s *Server) sessionFromReq(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	se, err := s.getSession(r.Context(), c.Value)
	if err != nil {
		return nil
	}
	return se
}

func (s *Server) setCookie(w http.ResponseWriter, name, val string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: val, Path: s.cfg.BasePath + "/", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}
