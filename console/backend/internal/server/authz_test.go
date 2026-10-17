package server

import (
	"encoding/json"
	"reflect"
	"testing"

	"thomasdarimont.de/authz/console-bff/internal/config"
)

func TestTeamDerivation(t *testing.T) {
	claims := map[string]any{
		"preferred_username": "alice",
		"realm_access":       map[string]any{"roles": []any{"console_admin", "offline_access", "authz_writer"}},
		"groups":             []any{"/eng/platform", "/sales"},
		"organization":       map[string]any{"acme": map[string]any{}},
	}
	cfg := config.Config{TeamClaims: []config.TeamClaim{
		{Prefix: "role", Path: "realm_access.roles"},
		{Prefix: "group", Path: "groups"},
		{Prefix: "org", Path: "organization"},
		{Prefix: "x", Path: "missing.claim"},
	}}
	var teams []string
	for _, tc := range cfg.TeamClaims {
		for _, v := range claimValues(claimPath(claims, tc.Path)) {
			teams = append(teams, teamID(tc.Prefix, v))
		}
	}
	want := []string{"role_console_admin", "role_offline_access", "role_authz_writer", "group_eng_platform", "group_sales", "org_acme"}
	if !reflect.DeepEqual(teams, want) {
		t.Fatalf("teams = %v, want %v", teams, want)
	}
}

func TestTeamIDSanitizes(t *testing.T) {
	for in, want := range map[string]string{
		"/eng/platform": "group_eng_platform",
		"Sales Team":    "group_Sales_Team",
		"a'b;c":         "group_a_b_c",
		"ok.name-1":     "group_ok.name-1",
	} {
		if got := teamID("group", in); got != want {
			t.Errorf("teamID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContextualTuplesShape(t *testing.T) {
	p := &principal{typ: "user", id: "alice", teams: []string{"role_console_admin"}}
	tuples := []map[string]string{{"user_type": p.typ, "user_id": p.id, "relation": "member", "object_type": "team", "object_id": "role_console_admin"}}
	raw, _ := json.Marshal(tuples)
	var back []map[string]string
	if err := json.Unmarshal(raw, &back); err != nil || len(back) != 1 || back[0]["object_id"] != "role_console_admin" {
		t.Fatalf("contextual tuples malformed: %s", raw)
	}
	for _, key := range []string{"user_type", "user_id", "relation", "object_type", "object_id"} {
		if back[0][key] == "" {
			t.Errorf("tuple lacks %s (the engine's _validate_tuple_jsonb requires it)", key)
		}
	}
}

func TestValidName(t *testing.T) {
	for in, ok := range map[string]bool{"demo": true, "tenant_a": true, "_x1": true, "9x": false, "a-b": false, "a b": false, "": false} {
		if validName.MatchString(in) != ok {
			t.Errorf("validName(%q) = %v, want %v", in, !ok, ok)
		}
	}
}
