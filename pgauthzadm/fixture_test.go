package pgauthzadm

import (
	"strings"
	"testing"
	"time"
)

func TestParseRef(t *testing.T) {
	for in, want := range map[string]Ref{
		"user:alice":       {Type: "user", ID: "alice"},
		"user:*":           {Type: "user", ID: "*"},
		"group:eng#member": {Type: "group", ID: "eng", Relation: "member"},
		"doc:a:b":          {Type: "doc", ID: "a:b"},
	} {
		got, err := ParseRef(in)
		if err != nil || got != want {
			t.Errorf("ParseRef(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "user", ":alice", "user:", "#member"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) accepted", bad)
		}
	}
}

func TestParseFixture(t *testing.T) {
	fix, err := ParseFixture([]byte(`
model_file: ./model.fga
tuples:
  - user: user:alice
    relation: member
    object: group:eng
tests:
  - name: alice reads
    description: "Alice should be able to read the design document"
    check:
      - user: user:alice
        object: doc:design
        description: "US-7: the designer's view"
        assertions: { can_read: true }
        notes: { can_read: "REQ-12: group members read via the folder" }
        context: { current_time: "2026-07-05T10:00:00Z" }
    list_objects:
      - user: user:bob
        type: doc
        assertions: { can_write: [doc:readme] }
    list_subjects:
      - object: doc:design
        type: user
        assertions: { can_read: [user:alice, user:*] }
    list_actions:
      - user: user:bob
        object: doc:readme
        expect: [owner, can_read]
    explain:
      - user: user:alice
        relation: can_write
        object: doc:design
        expect_reasons: [no_direct_tuple, computed]
`))
	if err != nil {
		t.Fatal(err)
	}
	if fix.ModelFile != "./model.fga" || len(fix.Tuples) != 1 || len(fix.Tests) != 1 {
		t.Fatalf("parsed %+v", fix)
	}
	tc := fix.Tests[0]
	if len(tc.Check) != 1 || tc.Check[0].Assertions["can_read"] != true || tc.Check[0].Context["current_time"] == nil {
		t.Errorf("check case %+v", tc.Check)
	}
	if tc.Check[0].Notes["can_read"] != "REQ-12: group members read via the folder" {
		t.Errorf("note not parsed: %+v", tc.Check[0].Notes)
	}
	if tc.Description != "Alice should be able to read the design document" || tc.Check[0].Description != "US-7: the designer's view" {
		t.Errorf("descriptions not parsed: test %q, case %q", tc.Description, tc.Check[0].Description)
	}
	if len(tc.ListObjects) != 1 || tc.ListObjects[0].Assertions["can_write"][0] != "doc:readme" {
		t.Errorf("list case %+v", tc.ListObjects)
	}
	if len(tc.ListSubjects) != 1 || tc.ListSubjects[0].Type != "user" || tc.ListSubjects[0].Assertions["can_read"][1] != "user:*" {
		t.Errorf("list_subjects case %+v", tc.ListSubjects)
	}
	if len(tc.ListActions) != 1 || tc.ListActions[0].Expect[1] != "can_read" {
		t.Errorf("list_actions case %+v", tc.ListActions)
	}
	if len(tc.Explain) != 1 || strings.Join(tc.Explain[0].ExpectReasons, ",") != "no_direct_tuple,computed" {
		t.Errorf("explain case %+v", tc.Explain)
	}
	// round-trips through YAML
	out, err := fix.YAML()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseFixture(out)
	if err != nil || len(again.Tests) != 1 || again.Tests[0].Name != "alice reads" {
		t.Errorf("round trip: %v %+v", err, again)
	}
}

func TestFixtureValidate(t *testing.T) {
	for name, yml := range map[string]string{
		"neither model":       "tests: []\n",
		"both models":         "model_file: m.fga\nmodel: saas_core@3\n",
		"model and store":     "model: saas_core@3\nstore: gdrive\n",
		"bad registry ref":    "model: saas_core@three\n",
		"bad tuple user":      "model: saas_core\ntuples:\n  - user: alice\n    relation: member\n    object: group:eng\n",
		"tuple sans relation": "model: saas_core\ntuples:\n  - user: user:alice\n    object: group:eng\n",
		"unnamed test":        "model: saas_core\ntests:\n  - check: []\n",
	} {
		if _, err := ParseFixture([]byte(yml)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseFixture([]byte("model: saas_core@3\ntests:\n  - name: t\n")); err != nil {
		t.Errorf("registry ref fixture rejected: %v", err)
	}
	if _, err := ParseFixture([]byte("store: gdrive\ntests:\n  - name: t\n")); err != nil {
		t.Errorf("live-store fixture rejected: %v", err)
	}
}

func TestJUnit(t *testing.T) {
	out, err := JUnit("tests.authz.yaml", &RunReport{
		Results:  []Result{{Name: "ok"}, {Name: "bad", Failed: true, Detail: "got false"}},
		Failed:   1,
		Duration: 1500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`<?xml`, `<testsuite name="tests.authz.yaml" tests="2" failures="1" time="1.5">`,
		`<testcase name="ok"></testcase>`, `<failure message="got false"></failure>`} {
		if !strings.Contains(s, want) {
			t.Errorf("JUnit output lacks %q:\n%s", want, s)
		}
	}
}

// Contextual tuples on every case kind, and their rendering for the
// engine's *_with_contextual_tuples_jsonb functions.
func TestFixtureContextualTuples(t *testing.T) {
	fix, err := ParseFixture([]byte(`
store: gdrive
tests:
  - name: with a hypothetical membership
    check:
      - user: user:frank
        object: doc:x
        assertions: { can_read: true }
        contextual_tuples:
          - user: group:eng#member
            relation: viewer
            object: doc:x
    list_objects:
      - user: user:frank
        type: doc
        assertions: { can_read: [doc:x] }
        contextual_tuples:
          - { user: user:frank, relation: viewer, object: doc:x }
    list_subjects:
      - object: doc:x
        type: user
        assertions: { can_read: [user:frank] }
        contextual_tuples:
          - { user: user:frank, relation: viewer, object: doc:x }
    list_actions:
      - user: user:frank
        object: doc:x
        expect: [viewer, can_read]
        contextual_tuples:
          - { user: user:frank, relation: viewer, object: doc:x }
`))
	if err != nil {
		t.Fatal(err)
	}
	tc := fix.Tests[0]
	if len(tc.Check[0].ContextualTuples) != 1 || len(tc.ListObjects[0].ContextualTuples) != 1 ||
		len(tc.ListSubjects[0].ContextualTuples) != 1 || len(tc.ListActions[0].ContextualTuples) != 1 {
		t.Fatalf("contextual tuples not parsed on every case kind: %+v", tc)
	}
	raw, err := ContextualTuplesJSON(tc.Check[0].ContextualTuples)
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"object_id":"x","object_type":"doc","relation":"viewer","user_id":"eng","user_relation":"member","user_type":"group"}]`
	if string(raw) != want {
		t.Errorf("rendered %s, want %s", raw, want)
	}
	if raw, err := ContextualTuplesJSON(nil); raw != nil || err != nil {
		t.Errorf("none: %s %v, want nil", raw, err)
	}
	if _, err := ContextualTuplesJSON([]FixtureTuple{{User: "frank", Relation: "viewer", Object: "doc:x"}}); err == nil {
		t.Error("a bare user id must be refused")
	}
	if _, err := ContextualTuplesJSON([]FixtureTuple{{User: "user:frank", Object: "doc:x"}}); err == nil {
		t.Error("a missing relation must be refused")
	}
}
