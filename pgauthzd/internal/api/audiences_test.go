package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// An issuer accepts a token carrying its audience OR one of its further
// audiences (a client id for Keycloak, the API's URI for other identity
// providers), and refuses one carrying neither.
func TestIssuerAcceptsAnyListedAudience(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := NewJWTMiddleware(JWTConfig{Issuers: []IssuerConfig{{Issuer: "https://idp", Audience: "authz-api", Audiences: []string{"https://api.example"}, JWKSFile: "x"}}})
	v := m.set.current().byIssuer["https://idp"]
	v.keys.Store("k1", &key.PublicKey)
	mint := func(aud any) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": "https://idp", "sub": "alice", "aud": aud, "exp": time.Now().Add(time.Hour).Unix()})
		tok.Header["kid"] = "k1"
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, aud := range []any{"authz-api", "https://api.example", []string{"account", "https://api.example"}} {
		if _, err := m.verifyToken(mint(aud)); err != nil {
			t.Errorf("aud %v refused: %v", aud, err)
		}
	}
	if _, err := m.verifyToken(mint("https://other.example")); err == nil || !strings.Contains(err.Error(), "aud") {
		t.Fatalf("a foreign audience must be refused, got %v", err)
	}
}
