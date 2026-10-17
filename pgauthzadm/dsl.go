package pgauthzadm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/openfga/language/pkg/go/transformer"
)

// ParseDSL turns OpenFGA-style DSL text into an OpenFGA authorization-model
// JSON document, the input of authz.import_openfga_model. It accepts what
// authz.describe_model renders: the leading "store: <name>" line and the
// "# …" comment lines (permission markers, conditions, gates, grant rules)
// are dropped, and the "model / schema 1.1" header is added when missing.
// Condition blocks are reported as warnings, not imported: OpenFGA's CEL
// vocabulary is not pgauthz's; create them natively (create_condition).
func ParseDSL(text string) (modelJSON []byte, warnings []string, err error) {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "store:") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// trailing "# …" comments (describe_model's "# permission" marker)
		if i := strings.Index(line, "  #"); i >= 0 {
			line = strings.TrimRight(line[:i], " ")
		}
		lines = append(lines, line)
	}
	body := strings.TrimSpace(strings.Join(lines, "\n"))
	if body == "" {
		return nil, nil, fmt.Errorf("the model is empty")
	}
	if !headerRe.MatchString(body) {
		body = "model\n  schema 1.1\n\n" + body
	}
	out, terr := transformer.TransformDSLToJSON(body)
	if terr != nil {
		return nil, nil, fmt.Errorf("the DSL does not parse: %w", terr)
	}
	modelJSON = []byte(out)
	var probe struct {
		Conditions map[string]struct {
			Expression string `json:"expression"`
		} `json:"conditions"`
	}
	if json.Unmarshal(modelJSON, &probe) == nil && len(probe.Conditions) > 0 {
		for name, c := range probe.Conditions {
			warnings = append(warnings, fmt.Sprintf(
				"condition %q is not imported (OpenFGA CEL vocabulary differs from pgauthz CEL) — create it natively, e.g. authz.create_condition(<store>, '%s', <translated: %s>)",
				name, name, c.Expression))
		}
	}
	return modelJSON, warnings, nil
}

var headerRe = regexp.MustCompile(`(?m)^\s*model\s*$`)

// ImportReport is what authz.import_openfga_model returns.
type ImportReport struct {
	Store                    string   `json:"store"`
	Types                    []string `json:"types"`
	Relations                []string `json:"relations"`
	RulesImported            int      `json:"rules_imported"`
	RulesReplaced            int      `json:"rules_replaced"`
	TypeRestrictionsImported int      `json:"type_restrictions_imported"`
	PlaceholderConditions    []string `json:"placeholder_conditions"`
	Warnings                 []string `json:"warnings"`
}

// ImportModel loads an OpenFGA model JSON into a store (authz.import_openfga_model):
// types and relations are added, rules and type restrictions are REPLACED,
// conditions, gates and grant rules are left as they are. The store must
// exist. Relation kinds are inferred from the result by the engine.
func ImportModel(ctx context.Context, db DB, store string, modelJSON []byte) (*ImportReport, error) {
	var r ImportReport
	if err := QueryJSON(ctx, db, &r, "SELECT authz.import_openfga_model($1, $2::jsonb)", store, string(modelJSON)); err != nil {
		return nil, err
	}
	return &r, nil
}
