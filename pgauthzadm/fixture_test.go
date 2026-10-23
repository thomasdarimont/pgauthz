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
    check:
      - user: user:alice
        object: doc:design
        assertions: { can_read: true }
        context: { current_time: "2026-07-05T10:00:00Z" }
    list_objects:
      - user: user:bob
        type: doc
        assertions: { can_write: [doc:readme] }
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
	if len(tc.ListObjects) != 1 || tc.ListObjects[0].Assertions["can_write"][0] != "doc:readme" {
		t.Errorf("list case %+v", tc.ListObjects)
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
