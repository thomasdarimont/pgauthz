package issuers

import (
	"encoding/json"
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
	ok := Issuer{Admin: AdminRules{{Scopes: []string{"pgauthz:admin"}}}}
	if err := ValidateBindings(ok); err != nil {
		t.Fatal(err)
	}
	if (&AdminBinding{}).Empty() != true || ok.Admin[0].Empty() {
		t.Fatal("Empty")
	}
	for name, iss := range map[string]Issuer{
		"empty":        {Admin: AdminRules{{}}},
		"blank scope":  {Admin: AdminRules{{Scopes: []string{" "}}}},
		"claim no val": {Admin: AdminRules{{Claims: map[string][]string{"roles": {}}}}},
		"blank client": {Admin: AdminRules{{Clients: []string{""}}}},
		"bad scope":    {Admin: AdminRules{{Clients: []string{"tf"}, Scope: "everything"}}},
		"bad cap":      {Admin: AdminRules{{Clients: []string{"ci"}, Capabilities: []string{"delete"}}}},
		"platform+st":  {Admin: AdminRules{{Clients: []string{"ci"}, Scope: "platform", Stores: []string{"x"}}}},
		"bad pattern":  {Admin: AdminRules{{Clients: []string{"ci"}, Stores: []string{"a("}}}},
		"second empty": {Admin: AdminRules{{Clients: []string{"tf"}}, {}}},
		"tech claim":   {Admin: AdminRules{{Decide: &AdminDecision{Store: "console", SubjectClaim: "preferred_username,iat"}}}},
	} {
		if err := ValidateBindings(iss); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The admin rules parse from the single object every deployment started
// with, or from a list; they always marshal as a list; capabilities
// default to manage.
func TestAdminRulesJSON(t *testing.T) {
	var one Issuer
	if err := json.Unmarshal([]byte(`{"issuer":"https://a","admin":{"clients":["tf"],"scope":"platform"}}`), &one); err != nil {
		t.Fatal(err)
	}
	if len(one.Admin) != 1 || one.Admin[0].Scope != AdminScopePlatform || !one.Admin[0].Can(AdminCapManage) || !one.Admin[0].Can(AdminCapTest) {
		t.Fatalf("%+v", one.Admin)
	}
	var many Issuer
	if err := json.Unmarshal([]byte(`{"issuer":"https://a","admin":[{"clients":["tf"]},{"clients":["ci"],"capabilities":["test"],"stores":["docs"]}]}`), &many); err != nil {
		t.Fatal(err)
	}
	if len(many.Admin) != 2 || many.Admin[1].Can(AdminCapManage) || !many.Admin[1].Can(AdminCapTest) || many.Admin[1].Can(AdminCapRead) || many.Admin[1].Stores[0] != "docs" {
		t.Fatalf("%+v", many.Admin)
	}
	if err := ValidateBindings(many); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(one)
	if !strings.Contains(string(out), `"admin":[{"clients":["tf"],"scope":"platform"}]`) {
		t.Fatalf("marshal: %s", out)
	}
	var none Issuer
	if err := json.Unmarshal([]byte(`{"issuer":"https://a","admin":null}`), &none); err != nil || len(none.Admin) != 0 {
		t.Fatalf("null: %v %+v", err, none.Admin)
	}
}
