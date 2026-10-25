package server

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func intp(i int) *int { return &i }

// The editor's vocabulary is the engine's model_* API: every operation maps
// to exactly one call, with the arguments in the engine's order.
func TestModelEditSQL(t *testing.T) {
	cases := []struct {
		op       string
		edit     modelEdit
		wantFn   string
		wantArgs []any
	}{
		{"set_type_labels", modelEdit{Name: "doc", Labels: []string{" group:docs ", "", "tier:core"}},
			"authz.model_set_type_labels", []any{"s", "doc", []string{"group:docs", "tier:core"}}},
		{"set_type_labels", modelEdit{Name: "doc"},
			"authz.model_set_type_labels", []any{"s", "doc", []string{}}},
		{"add_grant_rule", modelEdit{ObjectType: "doc", Relation: "viewer", Requires: "can_share"},
			"authz.model_add_grant_rule", []any{"s", "doc", "viewer", "can_share", nil, nil}},
		{"add_grant_rule", modelEdit{ObjectType: "doc", Relation: "editor", Requires: "can_share", RequiresRevoke: "owner", RecordAs: "share"},
			"authz.model_add_grant_rule", []any{"s", "doc", "editor", "can_share", "owner", "share"}},
		{"remove_grant_rule", modelEdit{ObjectType: "doc", Relation: "viewer"},
			"authz.model_drop_grant_rule", []any{"s", "doc", "viewer"}},
		{"set_relation_constraint", modelEdit{ObjectType: "doc", Relation: "viewer", MaxDirect: intp(50)},
			"authz.model_set_relation_constraint", []any{"s", "doc", "viewer", intp(50), (*int)(nil), (*int)(nil)}},
		{"set_relation_constraint", modelEdit{ObjectType: "doc", Relation: "can_read", MaxEffective: intp(500)},
			"authz.model_set_relation_constraint", []any{"s", "doc", "can_read", (*int)(nil), intp(500), (*int)(nil)}},
		{"set_relation_constraint", modelEdit{ObjectType: "doc", Relation: "owner", MinDirect: intp(1)},
			"authz.model_set_relation_constraint", []any{"s", "doc", "owner", (*int)(nil), (*int)(nil), intp(1)}},
		{"remove_relation_constraint", modelEdit{ObjectType: "doc", Relation: "viewer"},
			"authz.model_drop_relation_constraint", []any{"s", "doc", "viewer"}},
		{"set_payload_schema", modelEdit{Name: "transfer", PayloadSchema: json.RawMessage(`{"required": {"input.amount": "number"}}`)},
			"authz.model_set_payload_schema", []any{"s", "transfer", `{"required": {"input.amount": "number"}}`}},
		{"set_payload_schema", modelEdit{Name: "transfer", PayloadSchema: json.RawMessage(` null `)},
			"authz.model_set_payload_schema", []any{"s", "transfer", nil}},
		{"set_payload_schema", modelEdit{Name: "transfer"},
			"authz.model_set_payload_schema", []any{"s", "transfer", nil}},
	}
	for _, c := range cases {
		sql, args, ok := modelEditSQL("s", c.op, c.edit)
		if !ok {
			t.Fatalf("%s: not an operation", c.op)
		}
		if !strings.Contains(sql, c.wantFn+"(") {
			t.Errorf("%s: sql %q does not call %s", c.op, sql, c.wantFn)
		}
		if !reflect.DeepEqual(args, c.wantArgs) {
			t.Errorf("%s: args = %#v, want %#v", c.op, args, c.wantArgs)
		}
	}
	if _, _, ok := modelEditSQL("s", "drop_everything", modelEdit{}); ok {
		t.Error("unknown operation accepted")
	}
}
