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
	return err
}

type session struct {
	id           string
	accessToken  string
	refreshToken string
	idToken      string
	username     string
	expiresAt    time.Time
}

func (s *Server) createSession(ctx context.Context, t *oidc.TokenResp) (string, error) {
	id := randToken(32)
	exp := time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	user := claimString(t.AccessToken, "preferred_username")
	if user == "" {
		user = claimString(t.AccessToken, "sub")
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO sessions (id, access_token, refresh_token, id_token, username, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`, id, t.AccessToken, t.RefreshToken, t.IDToken, user, exp)
	return id, err
}

func (s *Server) getSession(ctx context.Context, id string) (*session, error) {
	var se session
	err := s.db.QueryRow(ctx,
		`SELECT id, access_token, coalesce(refresh_token,''), coalesce(id_token,''), coalesce(username,''), expires_at
		 FROM sessions WHERE id=$1`, id).
		Scan(&se.id, &se.accessToken, &se.refreshToken, &se.idToken, &se.username, &se.expiresAt)
	if err != nil {
		return nil, err
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
		t, err := s.oidc.Refresh(ctx, se.refreshToken)
		if err != nil {
			s.deleteSession(ctx, se.id)
			return nil, err
		}
		se.accessToken = t.AccessToken
		se.expiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
		if t.RefreshToken != "" {
			se.refreshToken = t.RefreshToken
		}
		_, _ = s.db.Exec(ctx, `UPDATE sessions SET access_token=$2, refresh_token=$3, expires_at=$4 WHERE id=$1`,
			se.id, se.accessToken, se.refreshToken, se.expiresAt)
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
