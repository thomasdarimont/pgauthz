package pgauthzadm

import "testing"

func TestDiffModels(t *testing.T) {
	s := func(v string) *string { return &v }
	a := &Model{
		Types:     []ModelType{{Name: "doc"}, {Name: "user"}},
		Relations: []ModelRelation{{Name: "viewer"}, {Name: "can_read"}},
		Rules: []ModelRule{
			{ObjectType: "doc", Relation: "viewer", RuleType: "direct", GroupOp: "or"},
			{ObjectType: "doc", Relation: "can_read", RuleType: "computed", ComputedRelation: s("viewer"), GroupOp: "or"},
		},
	}
	b := &Model{
		Types:     []ModelType{{Name: "doc", Description: s("a document")}, {Name: "user"}},
		Relations: []ModelRelation{{Name: "viewer"}, {Name: "can_read"}, {Name: "can_download"}},
		Rules: []ModelRule{
			{ObjectType: "doc", Relation: "viewer", RuleType: "direct", GroupOp: "or"},
			{ObjectType: "doc", Relation: "can_download", RuleType: "computed", ComputedRelation: s("viewer"), GroupOp: "or"},
		},
	}
	got := DiffModels(a, b)
	want := []Change{
		{Op: "update", Section: "types", Item: "doc"},
		{Op: "add", Section: "relations", Item: "can_download"},
		{Op: "add", Section: "rules", Item: "doc.can_download ← viewer"},
		{Op: "remove", Section: "rules", Item: "doc.can_read ← viewer"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d changes: %v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("change %d: got %v, want %v", i, got[i], want[i])
		}
	}
	if len(DiffModels(a, a)) != 0 {
		t.Error("a model must not differ from itself")
	}
}
