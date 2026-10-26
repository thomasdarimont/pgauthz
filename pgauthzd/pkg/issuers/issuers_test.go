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

// A row for an issuer the environment does not trust is admitted only as a
// group issuer (ADR 0017): store group + its own anchor + an audience,
// delegated admin rules only; its stores are what the engine resolved.
func TestMergeGroupIssuer(t *testing.T) {
	env := []Issuer{{Issuer: "https://corp", Audience: "api", JWKSURL: "https://corp/jwks", Stores: []string{"docs"}}}
	good := Binding{Issuer: "https://tenant-a-idp", StoreGroup: "tenant_a", JWKSURL: "https://tenant-a-idp/jwks", Audience: "authz-api", Audiences: []string{"https://api.example"},
		Stores: []string{"tenant_a_docs", "tenant_a_hr"}, Enabled: true, Admin: AdminRules{{Decide: &AdminDecision{Store: "console"}}}}
	merged, problems := Merge(env, []Binding{good})
	if len(problems) != 0 || len(merged) != 2 {
		t.Fatalf("merged %d problems %v", len(merged), problems)
	}
	g := merged[1]
	if g.Issuer != "https://tenant-a-idp" || g.AnchorSource != "db" || g.BindingSource != "db" || g.JWKSURL != "https://tenant-a-idp/jwks" || g.Audience != "authz-api" ||
		strings.Join(g.Stores, ",") != "tenant_a_docs,tenant_a_hr" || g.StoreGroup != "tenant_a" || len(g.Admin) != 1 || merged[0].AnchorSource != "env" {
		t.Fatalf("group issuer: %+v", g)
	}
	for name, row := range map[string]Binding{
		"no group":   {Issuer: "https://x", JWKSURL: "https://x/jwks", Audience: "a", Enabled: true},
		"no anchor":  {Issuer: "https://x", StoreGroup: "g", Audience: "a", Enabled: true},
		"no aud":     {Issuer: "https://x", StoreGroup: "g", JWKSURL: "https://x/jwks", Enabled: true},
		"http":       {Issuer: "https://x", StoreGroup: "g", JWKSURL: "http://x/jwks", Audience: "a", Enabled: true},
		"static adm": {Issuer: "https://x", StoreGroup: "g", JWKSURL: "https://x/jwks", Audience: "a", Enabled: true, Admin: AdminRules{{Clients: []string{"tf"}, Scope: AdminScopePlatform}}},
		"caps adm":   {Issuer: "https://x", StoreGroup: "g", JWKSURL: "https://x/jwks", Audience: "a", Enabled: true, Admin: AdminRules{{Decide: &AdminDecision{Store: "console"}, Capabilities: []string{"test"}}}},
	} {
		m, p := Merge(env, []Binding{row})
		if len(p) != 1 || len(m) != 1 {
			t.Errorf("%s: merged %d problems %v", name, len(m), p)
		}
	}
	// a row for an environment issuer may name a group (the engine resolved its stores) but not carry admin rules
	m, p := Merge(env, []Binding{{Issuer: "https://corp", StoreGroup: "g", Stores: []string{"docs"}, Enabled: true, Admin: AdminRules{{Decide: &AdminDecision{Store: "console"}}}}})
	if len(p) != 1 || !strings.Contains(p[0], "admin rules are ignored") || m[0].StoreGroup != "g" || m[0].AnchorSource != "env" || len(m[0].Admin) != 0 {
		t.Errorf("env issuer with a group row: %+v %v", m[0], p)
	}
}

// Aliases: a row's alias names the issuer (a group issuer's too); a bad
// shape or a collision with another issuer's alias is reported and ignored;
// Resolve turns either form into the URL.
func TestMergeAlias(t *testing.T) {
	env := []Issuer{
		{Issuer: "https://corp", Alias: "corp", Audience: "api", JWKSURL: "https://corp/jwks", Stores: []string{"docs"}},
		{Issuer: "https://other", Audience: "api", JWKSURL: "https://other/jwks", Stores: []string{"x"}},
	}
	rows := []Binding{
		{Issuer: "https://other", Alias: "Other-IdP", Stores: []string{"x"}, Enabled: true},
		{Issuer: "https://tenant-a-idp", Alias: "corp", StoreGroup: "tenant_a", JWKSURL: "https://tenant-a-idp/jwks", Audience: "a", Enabled: true}, // collides with corp
		{Issuer: "https://tenant-b-idp", Alias: "bad alias", StoreGroup: "tenant_b", JWKSURL: "https://tenant-b-idp/jwks", Audience: "a", Enabled: true},
	}
	merged, problems := Merge(env, rows)
	got := map[string]string{}
	for _, m := range merged {
		got[m.Issuer] = m.Alias
	}
	if got["https://corp"] != "corp" || got["https://other"] != "other-idp" || got["https://tenant-a-idp"] != "" || got["https://tenant-b-idp"] != "" {
		t.Fatalf("aliases: %v (problems %v)", got, problems)
	}
	if len(problems) != 2 || !strings.Contains(problems[0], `alias "corp" already names`) || !strings.Contains(problems[1], "letters, digits") {
		t.Fatalf("problems: %v", problems)
	}
	if Resolve(merged, "OTHER-IDP") != "https://other" || Resolve(merged, "https://x") != "https://x" || Resolve(merged, "nope") != "" {
		t.Fatal("resolve")
	}
	if _, err := ValidAlias("https://x"); err == nil {
		t.Fatal("a URL is not an alias")
	}
}

// The host allow-list for group issuers: the daemon fetches a row's jwks_url,
// so under the restriction a row whose issuer or jwks_url host is not listed
// is ignored (and with no host listed, every group issuer is).
func TestMergeGroupIssuerHosts(t *testing.T) {
	for host, want := range map[string]bool{"id.acme.test": true, "a.b.acme.test": true, "acme.test": false, "ID.ACME.TEST": true, "idp.example:8443": true, "evil.example": false, "": false} {
		if got := HostAllowed([]string{"*.acme.test", "idp.example"}, host); got != want {
			t.Errorf("HostAllowed(%q) = %v", host, got)
		}
	}
	if !HostAllowed([]string{"*"}, "anything") || HostAllowed(nil, "anything") {
		t.Fatal("wildcard / empty list")
	}
	env := []Issuer{{Issuer: "https://corp", Audience: "api", JWKSURL: "https://corp/jwks", Stores: []string{"docs"}}}
	row := func(iss, jwks string) Binding {
		return Binding{Issuer: iss, StoreGroup: "t", JWKSURL: jwks, Audience: "a", Enabled: true}
	}
	rows := []Binding{row("https://id.acme.test/realms/t", "https://id.acme.test/realms/t/certs"), row("https://id.acme.test/realms/u", "https://169.254.169.254/latest"), row("https://evil.example", "https://evil.example/jwks")}
	merged, problems := MergeWith(env, rows, MergeOptions{RestrictGroupIssuerHosts: true, GroupIssuerHosts: []string{"*.acme.test"}})
	if len(merged) != 2 || merged[1].Issuer != "https://id.acme.test/realms/t" || len(problems) != 2 ||
		!strings.Contains(problems[0], `host "evil.example" is not in GROUP_ISSUER_HOSTS`) || !strings.Contains(problems[1], `host "169.254.169.254"`) { // problems come sorted by issuer
		t.Fatalf("merged %+v problems %v", merged, problems)
	}
	// no host listed: nothing is admitted; without the restriction (the library default) everything is
	if m, p := MergeWith(env, rows[:1], MergeOptions{RestrictGroupIssuerHosts: true}); len(m) != 1 || len(p) != 1 || !strings.Contains(p[0], "names no host") {
		t.Fatalf("empty list: %v %v", m, p)
	}
	if m, p := Merge(env, rows); len(m) != 4 || len(p) != 0 {
		t.Fatalf("unrestricted: %d %v", len(m), p)
	}
}
