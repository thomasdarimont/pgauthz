package server

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"thomasdarimont.de/authz/playground-bff/internal/oidc"
)

const sessionCookie = "pg_session"
const authCookie = "pg_auth"

// InitSchema creates the session store table if it does not exist.
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
	_, err := s.db.Exec(ctx,
		`INSERT INTO sessions (id, access_token, refresh_token, id_token, username, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		id, t.AccessToken, t.RefreshToken, t.IDToken, user, exp)
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
	// Refresh the access token if it is about to expire.
	if time.Until(se.expiresAt) < 30*time.Second && se.refreshToken != "" {
		if t, err := s.oidc.Refresh(ctx, se.refreshToken); err == nil {
			se.accessToken = t.AccessToken
			se.expiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
			if t.RefreshToken != "" {
				se.refreshToken = t.RefreshToken
			}
			s.db.Exec(ctx, `UPDATE sessions SET access_token=$2, refresh_token=$3, expires_at=$4 WHERE id=$1`,
				se.id, se.accessToken, se.refreshToken, se.expiresAt)
		}
	}
	return &se, nil
}

func (s *Server) deleteSession(ctx context.Context, id string) {
	s.db.Exec(ctx, `DELETE FROM sessions WHERE id=$1`, id)
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
