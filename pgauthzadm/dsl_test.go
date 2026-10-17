package pgauthzadm

import (
	"encoding/json"
	"strings"
	"testing"
)

// What the console shows in its DSL view parses back: the store line and the
// permission markers go, the header comes.
func TestParseDSLAcceptsDescribeOutput(t *testing.T) {
	text := `store: gdrive
# condition in_hours (sql, caller time)

type user

type doc
  relations
    define can_read: viewer or owner  # permission
    define owner: [user]
    define viewer: [user, user:*, team#member]
    # grant requires can_share (revoke requires owner)

type team
  relations
    define member: [user]
`
	out, warnings, err := ParseDSL(text)
	if err != nil {
		t.Fatalf("ParseDSL: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	var m struct {
		SchemaVersion   string `json:"schema_version"`
		TypeDefinitions []struct {
			Type      string                     `json:"type"`
			Relations map[string]json.RawMessage `json:"relations"`
		} `json:"type_definitions"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if m.SchemaVersion != "1.1" || len(m.TypeDefinitions) != 3 {
		t.Fatalf("schema %q, %d types", m.SchemaVersion, len(m.TypeDefinitions))
	}
	for _, td := range m.TypeDefinitions {
		if td.Type == "doc" {
			if _, ok := td.Relations["can_read"]; !ok {
				t.Errorf("doc lacks can_read (permission marker broke the define?)")
			}
			if !strings.Contains(string(td.Relations["can_read"]), "union") {
				t.Errorf("can_read is not a union: %s", td.Relations["can_read"])
			}
		}
	}
}

func TestParseDSLErrors(t *testing.T) {
	if _, _, err := ParseDSL("store: x\n# nothing\n"); err == nil {
		t.Error("empty model accepted")
	}
	if _, _, err := ParseDSL("type doc\n  relations\n    define viewer: [user or"); err == nil {
		t.Error("broken DSL accepted")
	}
}
