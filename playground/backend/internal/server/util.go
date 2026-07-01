package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// claimMap decodes a JWT's payload to a map WITHOUT verifying it (the token came
// from our own session store / Keycloak; OPA does the real verification).
func claimMap(jwt string) map[string]any {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// claimString reads a string claim from a JWT's payload.
func claimString(jwt, key string) string {
	if v, ok := claimMap(jwt)[key].(string); ok {
		return v
	}
	return ""
}

// tokenHasRole reports whether the JWT carries the given Keycloak role, checking
// both realm_access.roles and every resource_access.<client>.roles list.
func tokenHasRole(jwt, role string) bool {
	m := claimMap(jwt)
	if m == nil {
		return false
	}
	inList := func(v any) bool {
		roles, ok := v.([]any)
		if !ok {
			return false
		}
		for _, r := range roles {
			if s, ok := r.(string); ok && s == role {
				return true
			}
		}
		return false
	}
	if ra, ok := m["realm_access"].(map[string]any); ok && inList(ra["roles"]) {
		return true
	}
	if res, ok := m["resource_access"].(map[string]any); ok {
		for _, c := range res {
			if cm, ok := c.(map[string]any); ok && inList(cm["roles"]) {
				return true
			}
		}
	}
	return false
}
