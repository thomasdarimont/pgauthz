package conformance

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed suite-config/*.json
var suiteConfigs embed.FS

// PlanDefinition is an AuthZEN PDP test plan of the OpenID conformance suite. All plans run with
// the same variant — pdp_auth_type=api_key (pgauthzd always wants a bearer token, so `none` is
// impossible), pdp_server_metadata=static (the endpoints are configured, not discovered) and
// authzen_support=core (decisions from identifiers alone; the `properties` level needs request
// properties pgauthzd does not yet feed into the engine) — and the same configuration template.
type PlanDefinition struct {
	// Name is the name of the test plan in the suite.
	Name string
	// Certifiable says whether the plan is part of the (planned) certification program; the
	// comprehensive plan only exercises the optional short-circuit semantics.
	Certifiable bool
}

// The plans.
var (
	Evaluation               = PlanDefinition{"authzen-pdp-evaluation-test-plan", true}
	Evaluations              = PlanDefinition{"authzen-pdp-evaluations-test-plan", true}
	SubjectSearch            = PlanDefinition{"authzen-pdp-subject-search-test-plan", true}
	ResourceSearch           = PlanDefinition{"authzen-pdp-resource-search-test-plan", true}
	ActionSearch             = PlanDefinition{"authzen-pdp-action-search-test-plan", true}
	EvaluationsComprehensive = PlanDefinition{"authzen-pdp-evaluations-comprehensive-test-plan", false}
)

// Plans are the plans, the five certification plans first.
var Plans = []PlanDefinition{Evaluation, Evaluations, SubjectSearch, ResourceSearch, ActionSearch, EvaluationsComprehensive}

// Variant is the variant the plan is created with.
func (p PlanDefinition) Variant() map[string]string {
	return map[string]string{"pdp_auth_type": "api_key", "pdp_server_metadata": "static", "authzen_support": "core"}
}

// PDP is the PDP under test as the suite sees it.
type PDP struct {
	// BaseURL is the PDP identifier: the https front's URL plus the store path,
	// https://<host>:<port>/stores/<store>.
	BaseURL string
	// APIKey is the bearer credential the suite sends.
	APIKey string
}

// Config is the suite configuration of the plan for the PDP: the template
// suite-config/authzen-core.json with the PDP identifier, the five endpoints under it and the
// api_key filled in.
func (p PlanDefinition) Config(pdp PDP) (json.RawMessage, error) {
	data, err := suiteConfigs.ReadFile("suite-config/authzen-core.json")
	if err != nil {
		return nil, err
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("suite-config/authzen-core.json: %w", err)
	}
	config["description"] = fmt.Sprintf("pgauthzd %s against %s", p.Name, pdp.BaseURL)
	config["pdp"] = map[string]any{
		"policy_decision_point":       pdp.BaseURL,
		"access_evaluation_endpoint":  pdp.BaseURL + "/access/v1/evaluation",
		"access_evaluations_endpoint": pdp.BaseURL + "/access/v1/evaluations",
		"search_subject_endpoint":     pdp.BaseURL + "/access/v1/search/subject",
		"search_resource_endpoint":    pdp.BaseURL + "/access/v1/search/resource",
		"search_action_endpoint":      pdp.BaseURL + "/access/v1/search/action",
		"api_key":                     pdp.APIKey,
	}
	return json.Marshal(config)
}
