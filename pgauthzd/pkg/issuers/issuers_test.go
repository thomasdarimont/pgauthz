package issuers

import (
	"strings"
	"testing"
)

func TestValidateBindings(t *testing.T) {
	ok := Issuer{Issuer: "https://idp", Stores: []string{"docs", "tenant-.*"}, DBRoles: []string{"app_.*"},
		ClientDBRoles: map[string]string{"svc": "app_docs"}, PEPClients: map[string][]string{"svc": {"docs", "tenant-1", "tenant-.*"}}}
	if err := ValidateBindings(ok); err != nil {
		t.Fatalf("valid binding refused: %v", err)
	}
	for name, iss := range map[string]Issuer{
		"bad store pattern":    {Stores: []string{"tenant-("}},
		"bad role pattern":     {DBRoles: []string{"app_["}},
		"empty client role":    {ClientDBRoles: map[string]string{"svc": ""}},
		"pep without stores":   {PEPClients: map[string][]string{"svc": {}}},
		"pep outside binding":  {Stores: []string{"docs"}, PEPClients: map[string][]string{"svc": {"hr"}}},
		"pep pattern not verb": {Stores: []string{"tenant-.*"}, PEPClients: map[string][]string{"svc": {"tenant-[0-9]+"}}},
	} {
		if err := ValidateBindings(iss); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// without a stores binding, pep clients may name anything
	if err := ValidateBindings(Issuer{PEPClients: map[string][]string{"svc": {".*"}}}); err != nil {
		t.Errorf("unbound issuer with pep .*: %v", err)
	}
}

func TestMerge(t *testing.T) {
	env := []Issuer{
		{Issuer: "https://corp", Audience: "api", JWKSURL: "https://corp/jwks", Stores: []string{"docs", "tenant-.*"}, PEPClients: map[string][]string{"gw": {".*"}}},
		{Issuer: "https://open", Audience: "api", JWKSFile: "/k.json"},
	}
	rows := []Binding{
		{Issuer: "https://corp", Stores: []string{"tenant-.*"}, DBRoles: []string{"app_.*"}, PEPClients: map[string][]string{"docs-svc": {"tenant-1"}}, Enabled: true},
		{Issuer: "https://open", Stores: []string{"sandbox"}, Enabled: false},
		{Issuer: "https://rogue", Stores: []string{".*"}, Enabled: true},
	}
	merged, problems := Merge(env, rows)
	if len(merged) != 2 {
		t.Fatalf("merged %d issuers", len(merged))
	}
	corp, open := merged[0], merged[1]
	if corp.Audience != "api" || corp.JWKSURL != "https://corp/jwks" || corp.BindingSource != "db" ||
		strings.Join(corp.Stores, ",") != "tenant-.*" || strings.Join(corp.DBRoles, ",") != "app_.*" || corp.PEPClients["gw"] != nil || corp.PEPClients["docs-svc"] == nil || corp.Disabled {
		t.Errorf("corp: %+v", corp)
	}
	if open.BindingSource != "db" || strings.Join(open.Stores, ",") != "sandbox" || !open.Disabled || open.JWKSFile != "/k.json" {
		t.Errorf("open: %+v", open)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "rogue") {
		t.Errorf("problems: %v", problems)
	}
	for name, row := range map[string]Binding{
		"widen":   {Issuer: "https://corp", Stores: []string{"hr"}, Enabled: true},
		"unbind":  {Issuer: "https://corp", Stores: nil, Enabled: true},
		"bad pep": {Issuer: "https://corp", Stores: []string{"docs"}, PEPClients: map[string][]string{"x": {"tenant-.*"}}, Enabled: true},
		"bad pat": {Issuer: "https://corp", Stores: []string{"docs("}, Enabled: true},
		"pattern": {Issuer: "https://corp", Stores: []string{"tenant-[ab]"}, Enabled: true},
	} {
		m, p := Merge(env, []Binding{row})
		if len(p) != 1 || m[0].BindingSource != "env" || strings.Join(m[0].Stores, ",") != "docs,tenant-.*" {
			t.Errorf("%s: merged %+v problems %v", name, m[0], p)
		}
	}
	m, p := Merge(env, nil)
	if len(p) != 0 || m[0].BindingSource != "env" || m[1].BindingSource != "env" {
		t.Errorf("no rows: %+v %v", m, p)
	}
}

// Merge keeps the environment's stores binding next to a row's, so the
// narrowing rule can be re-checked against the environment later (the
// admin API validates a PUT against it).
func TestMergeKeepsEnvStores(t *testing.T) {
	env := []Issuer{{Issuer: "https://a", Stores: []string{"a_.*"}}}
	merged, problems := Merge(env, []Binding{{Issuer: "https://a", Stores: []string{"a_docs"}, Enabled: true}})
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	if got := merged[0]; got.BindingSource != "db" || len(got.EnvStores) != 1 || got.EnvStores[0] != "a_.*" || got.Stores[0] != "a_docs" {
		t.Fatalf("%+v", got)
	}
}

// An admin binding is the environment's business: validated with the
// issuer, never empty, scope issuer or platform.
func TestAdminBindingValidation(t *testing.T) {
	ok := Issuer{Admin: &AdminBinding{Scopes: []string{"pgauthz:admin"}}}
	if err := ValidateBindings(ok); err != nil {
		t.Fatal(err)
	}
	if (&AdminBinding{}).Empty() != true || ok.Admin.Empty() {
		t.Fatal("Empty")
	}
	for name, iss := range map[string]Issuer{
		"empty":        {Admin: &AdminBinding{}},
		"blank scope":  {Admin: &AdminBinding{Scopes: []string{" "}}},
		"claim no val": {Admin: &AdminBinding{Claims: map[string][]string{"roles": {}}}},
		"blank client": {Admin: &AdminBinding{Clients: []string{""}}},
		"bad scope":    {Admin: &AdminBinding{Clients: []string{"tf"}, Scope: "everything"}},
	} {
		if err := ValidateBindings(iss); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
