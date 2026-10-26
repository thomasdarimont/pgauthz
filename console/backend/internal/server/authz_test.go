package server

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
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

// pgauthz:test on the session's token opens the Test pages: a token with
// pgauthz:* scopes but without it is masked out of every testing
// capability, single checks and the batch alike, whatever the store grants;
// a token without any pgauthz scope is not masked.
func TestScopeGuardsTesting(t *testing.T) {
	for scope, want := range map[string]bool{"openid pgauthz:admin": true, "openid pgauthz:admin pgauthz:test": false, "openid profile": false, "": false, "pgauthz:test": false} {
		if got := scopeLacksTesting(scope); got != want {
			t.Errorf("scopeLacksTesting(%q) = %v", scope, got)
		}
	}
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	if _, err := pool.Exec(ctx, `SELECT authz.write_tuple($1, 'user', 'scope_tester', 'tester', 'store', 'scope_store')`, cs); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple($1, 'user', 'scope_tester', 'tester', 'store', 'scope_store')`, cs)
	}()
	open := &principal{typ: "user", id: "scope_tester", ctxTuples: "[]"}
	masked := &principal{typ: "user", id: "scope_tester", ctxTuples: "[]", noTesting: true}
	for _, c := range []struct {
		p    *principal
		want bool
	}{{open, true}, {masked, false}} {
		if ok, err := s.can(ctx, c.p, "can_run_tests", "store", "scope_store"); err != nil || ok != c.want {
			t.Fatalf("can_run_tests masked=%v: %v %v", c.p.noTesting, ok, err)
		}
		caps, err := s.capabilities(ctx, c.p, "store", []string{"scope_store"}, []string{"can_run_tests", "can_view"})
		if err != nil || caps["scope_store"]["can_run_tests"] != c.want || !caps["scope_store"]["can_view"] {
			t.Fatalf("capabilities masked=%v: %v %v", c.p.noTesting, caps, err)
		}
	}
}

// The person's id from the ID token: the claim list in order, the first
// non-empty wins; a CEL expression shapes it when a list is not enough.
func TestSubjectIDResolution(t *testing.T) {
	claims := map[string]any{"sub": "uuid-1", "upn": "alice@corp.example", "email": "Alice@corp.example", "preferred_username": ""}
	s := &Server{cfg: config.Config{SubjectIDClaims: []string{"preferred_username", "upn", "sub"}}}
	if id, err := s.subjectID(claims); err != nil || id != "alice@corp.example" {
		t.Fatalf("list: %q %v", id, err)
	}
	s = &Server{cfg: config.Config{SubjectIDClaims: []string{"nope.deep"}}}
	if _, err := s.subjectID(claims); err == nil {
		t.Fatal("no claim present must refuse the sign-in")
	}
	// a technical claim in the list is skipped, never taken as the identity
	s = &Server{cfg: config.Config{SubjectIDClaims: []string{"iss", "iat", "upn"}}}
	if id, err := s.subjectID(map[string]any{"iss": "https://idp", "iat": "1", "upn": "bob"}); err != nil || id != "bob" {
		t.Fatalf("technical claims skipped: %q %v", id, err)
	}
	s = &Server{cfg: config.Config{SubjectIDCEL: "has(claims.upn) ? claims.upn.split('@')[0] : claims.sub"}}
	if id, err := s.subjectID(claims); err != nil || id != "alice" {
		t.Fatalf("cel: %q %v", id, err)
	}
	s = &Server{cfg: config.Config{SubjectIDCEL: "claims.email.lowerAscii()"}}
	if id, err := s.subjectID(claims); err != nil || id != "alice@corp.example" {
		t.Fatalf("cel lower: %q %v", id, err)
	}
	s = &Server{cfg: config.Config{SubjectIDCEL: "size(claims)"}}
	if _, err := s.subjectID(claims); err == nil {
		t.Fatal("a non-string result must refuse the sign-in")
	}
	s = &Server{cfg: config.Config{SubjectIDCEL: "claims.("}}
	if _, err := s.subjectID(claims); err == nil || !strings.Contains(err.Error(), "CONSOLE_SUBJECT_ID_CEL") {
		t.Fatalf("a broken expression names the setting: %v", err)
	}
}
