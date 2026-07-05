package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openfga/language/pkg/go/transformer"
)

// loadModelJSON reads a model file and returns OpenFGA authorization-model
// JSON. .fga / .dsl files go through the official OpenFGA DSL transformer;
// .json files pass through untouched.
//
// DSL `condition` blocks are surfaced as warnings, not imported: the engine
// import consumes condition references on tuples but not the model-level
// conditions map — and OpenFGA CEL (bare parameter names) is not the same
// vocabulary as pgauthz CEL (request.* / stored.*), so a faithful automatic
// translation would be wrong more often than right. Create them natively
// with authz.create_condition_sql / create_condition_cel.
func loadModelJSON(path string) (modelJSON []byte, warnings []string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		modelJSON = raw
	case ".fga", ".dsl", ".openfga":
		out, terr := transformer.TransformDSLToJSON(string(raw))
		if terr != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", path, terr)
		}
		modelJSON = []byte(out)
	default:
		return nil, nil, fmt.Errorf("unsupported model file %s (want .fga, .dsl or .json)", path)
	}

	var probe struct {
		Conditions map[string]struct {
			Expression string `json:"expression"`
		} `json:"conditions"`
	}
	if json.Unmarshal(modelJSON, &probe) == nil && len(probe.Conditions) > 0 {
		for name, c := range probe.Conditions {
			warnings = append(warnings, fmt.Sprintf(
				"condition %q is NOT imported (OpenFGA CEL vocabulary differs from pgauthz CEL) — "+
					"create it natively, e.g.: SELECT authz.create_condition_cel('<store>', '%s', '<translated: %s>');",
				name, name, c.Expression))
		}
	}
	return modelJSON, warnings, nil
}
