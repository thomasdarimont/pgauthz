package pgauthzadm

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func str(s string) *string { return &s }
func intp(i int) *int      { return &i }

func TestRenderSQLHelloWorld(t *testing.T) {
	m := &Model{
		Format:    1,
		Types:     []ModelType{{Name: "user"}, {Name: "document", Description: str("a doc's 'file'")}},
		Relations: []ModelRelation{{Name: "viewer"}, {Name: "editor", Description: str("edits")}, {Name: "can_read", Metadata: json.RawMessage(`{"kind": "permission"}`)}},
		Rules: []ModelRule{
			{ObjectType: "document", Relation: "can_read", RuleType: "computed", ComputedRelation: str("viewer"), GroupOp: "or"},
			{ObjectType: "document", Relation: "viewer", RuleType: "direct", GroupOp: "or"},
			{ObjectType: "document", Relation: "can_read", RuleType: "ttu", TuplesetRelation: str("parent"), TuplesetComputed: str("can_read"), GroupOp: "or"},
			{ObjectType: "document", Relation: "can_read", RuleType: "computed", ComputedRelation: str("blocked"), GroupID: 1, GroupOp: "exclusion", Negated: true},
		},
		TypeRestrictions: []TypeRestriction{
			{ObjectType: "document", Relation: "viewer", AllowedUserType: "user"},
			{ObjectType: "document", Relation: "viewer", AllowedUserType: "team", AllowedUserRelation: str("member"), AllowWildcard: false, Condition: str("in_hours")},
		},
		Conditions: []Condition{{Name: "in_hours", Expression: "(ctx->>'hour')::int < 18", Lang: "sql"}},
		GrantRules: []GrantRule{
			{ObjectType: "document", Relation: "viewer", Requires: "owner"},
			{ObjectType: "document", Relation: "editor", Requires: "owner", RecordAs: str("share")},
		},
		RelationConstraints: []RelationConstraint{
			{ObjectType: "document", Relation: "viewer", MaxDirect: intp(50), MaxEffective: intp(200)},
			{ObjectType: "document", Relation: "can_read", MaxEffective: intp(500)},
			{ObjectType: "document", Relation: "owner", MinDirect: intp(1)},
		},
	}
	out := RenderSQL("hello", m)
	want := []string{
		"SELECT authz.model_register_type('hello', 'user');",
		"SELECT authz.model_register_type('hello', 'document', p_description => 'a doc''s ''file''');",
		"SELECT authz.model_register_relation('hello', 'viewer');",
		"SELECT authz.model_register_relation('hello', 'editor', p_description => 'edits');",
		"SELECT authz.model_register_relation('hello', 'can_read', p_metadata => '{\"kind\": \"permission\"}'::jsonb);",
		"SELECT authz.create_condition('hello', 'in_hours', '(ctx->>''hour'')::int < 18', p_lang => 'sql');",
		"SELECT authz.model_add_rule('hello', 'document', 'viewer', 'direct');",
		"SELECT authz.model_add_rule('hello', 'document', 'can_read', 'computed', 'viewer');",
		"SELECT authz.model_add_rule('hello', 'document', 'can_read', 'ttu', NULL, 'parent', 'can_read');",
		"SELECT authz.model_add_rule('hello', 'document', 'can_read', 'computed', 'blocked', p_group_id => 1, p_group_op => 'exclusion', p_negated => true);",
		"SELECT authz.model_add_type_restriction('hello', 'document', 'viewer', 'user');",
		"SELECT authz.model_add_type_restriction('hello', 'document', 'viewer', 'team', p_allowed_user_relation => 'member', p_condition => 'in_hours');",
		"SELECT authz.model_add_grant_rule('hello', 'document', 'viewer', 'owner');",
		"SELECT authz.model_add_grant_rule('hello', 'document', 'editor', 'owner', p_record_as => 'share');",
		"SELECT authz.model_set_relation_constraint('hello', 'document', 'viewer', p_max_direct => 50, p_max_effective => 200);",
		"SELECT authz.model_set_relation_constraint('hello', 'document', 'can_read', p_max_effective => 500);",
		"SELECT authz.model_set_relation_constraint('hello', 'document', 'owner', p_min_direct => 1);",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("rendered SQL lacks %q\n---\n%s", w, out)
		}
	}
	// rules are ordered by object type, relation, then group — the exclusion
	// group (1) follows the union terms (0) of the same relation
	if strings.Index(out, "'can_read', 'computed', 'viewer'") > strings.Index(out, "p_group_id => 1") {
		t.Errorf("rules not sorted by object type, relation, group:\n%s", out)
	}
}

func TestParseModelRef(t *testing.T) {
	for _, tc := range []struct {
		in      string
		name    string
		version int
		ok      bool
	}{
		{"saas_core", "saas_core", 0, true},
		{"saas_core@3", "saas_core", 3, true},
		{"saas_core@x", "", 0, false},
		{"saas_core@0", "", 0, false},
		{"", "", 0, false},
	} {
		n, v, err := ParseModelRef(tc.in)
		if (err == nil) != tc.ok || n != tc.name || v != tc.version {
			t.Errorf("ParseModelRef(%q) = %q, %d, %v; want %q, %d, ok=%v", tc.in, n, v, err, tc.name, tc.version, tc.ok)
		}
	}
}

func TestPlanRender(t *testing.T) {
	plan := Plan{
		"store": "tenant_a", "model": "saas_core", "version": 3.0,
		"current": map[string]any{"model_name": "saas_core", "model_version": 2.0, "in_sync": true},
		"changes": map[string]any{
			"relations": map[string]any{"add": []any{"can_archive"}},
			"rules":     map[string]any{"remove": []any{map[string]any{"object_type": "doc", "relation": "x"}}},
		},
		"blockers":  []any{"type removal required: legacy"},
		"can_apply": false,
	}
	if got := plan.Changes(); len(got) != 2 || got[0].Section != "relations" || got[1].Op != "remove" {
		t.Fatalf("Changes() = %+v", got)
	}
	var buf bytes.Buffer
	RenderPlan(&buf, plan)
	for _, w := range []string{"plan: store tenant_a ← saas_core@3", "current: saas_core@2 (in_sync: true)", "+ relations can_archive",
		`- rules {"object_type":"doc","relation":"x"}`, "! type removal required: legacy", "verdict: BLOCKED"} {
		if !strings.Contains(buf.String(), w) {
			t.Errorf("RenderPlan lacks %q:\n%s", w, buf.String())
		}
	}
}

func TestRelationKind(t *testing.T) {
	if k := (ModelRelation{Name: "viewer"}).Kind(); k != "relation" {
		t.Errorf("undeclared kind = %q", k)
	}
	if k := (ModelRelation{Name: "can_read", Metadata: json.RawMessage(`{"kind":"permission","label":"Read"}`)}).Kind(); k != "permission" {
		t.Errorf("declared kind = %q", k)
	}
}

// A "but not" group renders its base rule before the negated one whatever
// order the export lists them in — the engine's model validation refuses a
// negated rule whose group has no base yet.
func TestRenderSQLBaseRuleBeforeNegated(t *testing.T) {
	blocked, editor := "blocked", "editor"
	m := &Model{Rules: []ModelRule{
		{ObjectType: "folder", Relation: "can_read", RuleType: "computed", ComputedRelation: &blocked, GroupID: 1, GroupOp: "exclusion", Negated: true},
		{ObjectType: "folder", Relation: "can_read", RuleType: "computed", ComputedRelation: &editor, GroupID: 1, GroupOp: "exclusion"},
	}}
	out := RenderSQL("s", m)
	i, j := strings.Index(out, "'editor'"), strings.Index(out, "'blocked'")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("base rule must come first:\n%s", out)
	}
}
