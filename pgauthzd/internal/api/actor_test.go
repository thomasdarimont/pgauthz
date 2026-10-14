package api

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// deriveSubject: a delegated token (RFC 8693 `act`, Keycloak token-exchange
// delegation) makes the ACTOR the principal and keeps the token subject as
// on_behalf_of — the agent is checked with its own authority, never the
// user's. Off by default; a plain token is unaffected either way.
func TestDeriveSubjectDelegatedActor(t *testing.T) {
	base := JWTConfig{
		SubjectIDClaim: "preferred_username", SubjectIDFallback: "sub",
		SubjectTypeClaim: "subject_type", SubjectTypeDefault: "internal_user",
	}
	delegated := jwt.MapClaims{
		"sub": "0fa1e5d4", "preferred_username": "alice", "subject_type": "user",
		"act": map[string]any{"sub": "9b8c7d6e", "client_id": "acme_assist"},
	}
	plain := jwt.MapClaims{"sub": "0fa1e5d4", "preferred_username": "alice", "subject_type": "user"}

	cases := []struct {
		name                   string
		cfg                    func(JWTConfig) JWTConfig
		claims                 jwt.MapClaims
		wantType, wantID       string
		wantOboType, wantOboID string
	}{
		{"off: delegated token is its subject", func(c JWTConfig) JWTConfig { return c }, delegated,
			"user", "alice", "", ""},
		{"on: actor becomes the principal", func(c JWTConfig) JWTConfig {
			c.ActorClaim, c.ActorSubjectType = "act.client_id", "agent"
			return c
		}, delegated, "agent", "acme_assist", "user", "alice"},
		{"on: plain token unaffected", func(c JWTConfig) JWTConfig {
			c.ActorClaim, c.ActorSubjectType = "act.client_id", "agent"
			return c
		}, plain, "user", "alice", "", ""},
		{"on: non-string actor value ignored", func(c JWTConfig) JWTConfig {
			c.ActorClaim, c.ActorSubjectType = "act", "agent"
			return c
		}, delegated, "user", "alice", "", ""},
		{"on: subject-type default applies to on_behalf_of", func(c JWTConfig) JWTConfig {
			c.ActorClaim, c.ActorSubjectType = "act.client_id", "agent"
			return c
		}, jwt.MapClaims{"sub": "bob", "act": map[string]any{"client_id": "bot"}},
			"agent", "bot", "internal_user", "bob"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewJWTMiddleware(tc.cfg(base))
			st, sid, ot, oid := m.deriveSubject(tc.claims)
			if st != tc.wantType || sid != tc.wantID || ot != tc.wantOboType || oid != tc.wantOboID {
				t.Errorf("got (%s:%s on behalf of %s:%s), want (%s:%s on behalf of %s:%s)",
					st, sid, ot, oid, tc.wantType, tc.wantID, tc.wantOboType, tc.wantOboID)
			}
		})
	}
}

func TestOnBehalfOfFromContext(t *testing.T) {
	if ot, oid := OnBehalfOfFromContext(context.Background()); ot != "" || oid != "" {
		t.Fatalf("empty context should yield nothing, got %s:%s", ot, oid)
	}
	ctx := context.WithValue(context.Background(), ctxOnBehalfOf, onBehalfOf{Type: "user", ID: "alice"})
	if ot, oid := OnBehalfOfFromContext(ctx); ot != "user" || oid != "alice" {
		t.Fatalf("got %s:%s", ot, oid)
	}
}
