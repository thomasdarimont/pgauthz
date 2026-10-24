package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// writeEngineError maps an engine failure to a response: the engine's own
// RAISE EXCEPTION messages (validation, unknown names, blocked operations)
// are a 400 with the message and hint; anything else is a 502.
func writeEngineError(w http.ResponseWriter, err error) {
	if writeScopeError(w, err) { // the in-transaction re-authorization said no
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		msg := pgErr.Message
		if pgErr.Hint != "" {
			msg += " — " + pgErr.Hint
		}
		status := http.StatusBadRequest
		if pgErr.Code == "42501" { // insufficient_privilege
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]any{"error": msg, "code": pgErr.Code})
		return
	}
	writeError(w, http.StatusBadGateway, err.Error())
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return false
	}
	return true
}

// claimMap decodes a JWT's payload WITHOUT verifying it: the token came from
// our own session store, straight from the IdP's token endpoint.
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

func claimString(jwt, key string) string {
	if v, ok := claimMap(jwt)[key].(string); ok {
		return v
	}
	return ""
}

// claimPath walks a dotted path ("realm_access.roles") into the payload.
func claimPath(m map[string]any, path string) any {
	var cur any = m
	for seg := range strings.SplitSeq(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[seg]
	}
	return cur
}

// claimValues flattens a claim into strings: a string, a list of strings, or
// an object's keys (Keycloak's `organization` claim is {alias: {...}}).
func claimValues(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(t))
		for k := range t {
			out = append(out, k)
		}
		return out
	}
	return nil
}

var unsafeIDChars = regexp.MustCompile(`[^A-Za-z0-9_.@-]+`)

// teamID turns a claim value into a team object id: "/eng/platform" → "group_eng_platform".
func teamID(prefix, value string) string {
	v := strings.Trim(value, "/")
	v = unsafeIDChars.ReplaceAllString(v, "_")
	return prefix + "_" + v
}

// validName is what the engine accepts for type, relation and store names
// (store names additionally must not be Rego keywords — the engine says so).
var validName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableJSON(raw json.RawMessage) any {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil
	}
	return s
}
