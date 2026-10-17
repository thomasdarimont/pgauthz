package conformance

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed suite-config/*.json
var suiteConfigs embed.FS

// PlanDefinition is an AuthZEN PDP test plan of the OpenID conformance suite with the variant it
// runs in. Every plan runs with pdp_auth_type=api_key (pgauthzd always wants a bearer token, so
// `none` is impossible). authzen_support is properties by default — the core modules plus the
// ones deciding on subject/resource/action properties (certification profile rules 5–8),
// which pgauthzd feeds into the engine's conditions — or core (CTS_SUPPORT=core).
// pdp_server_metadata is static (the five endpoints are configured) or discovery (the suite
// fetches them from the PDP's /.well-known/authzen-configuration and insists the advertised
// policy_decision_point equals the configured one).
type PlanDefinition struct {
	// Name is the name of the test plan in the suite.
	Name string
	// Certifiable says whether the plan is part of the (planned) certification program; the
	// comprehensive plan only exercises the optional short-circuit semantics.
	Certifiable bool
	// Metadata is the pdp_server_metadata variant: Static or Discovery.
	Metadata string
}

// The pdp_server_metadata variants.
const (
	Static    = "static"
	Discovery = "discovery"
)

// The authzen_support variants; Support is the one the plans run with (CTS_SUPPORT, default
// Properties — it includes every core module).
const (
	Core       = "core"
	Properties = "properties"
)

var Support = env("CTS_SUPPORT", Properties)

// The plans with static endpoints.
var (
	Evaluation               = PlanDefinition{"authzen-pdp-evaluation-test-plan", true, Static}
	Evaluations              = PlanDefinition{"authzen-pdp-evaluations-test-plan", true, Static}
	SubjectSearch            = PlanDefinition{"authzen-pdp-subject-search-test-plan", true, Static}
	ResourceSearch           = PlanDefinition{"authzen-pdp-resource-search-test-plan", true, Static}
	ActionSearch             = PlanDefinition{"authzen-pdp-action-search-test-plan", true, Static}
	EvaluationsComprehensive = PlanDefinition{"authzen-pdp-evaluations-comprehensive-test-plan", false, Static}
)

// Plans are the plans with static endpoints, the five certification plans first.
var Plans = []PlanDefinition{Evaluation, Evaluations, SubjectSearch, ResourceSearch, ActionSearch, EvaluationsComprehensive}

// DiscoveryPlans are the five certification plans with discovered endpoints.
var DiscoveryPlans = []PlanDefinition{
	Evaluation.WithMetadata(Discovery), Evaluations.WithMetadata(Discovery), SubjectSearch.WithMetadata(Discovery),
	ResourceSearch.WithMetadata(Discovery), ActionSearch.WithMetadata(Discovery),
}

// WithMetadata is the plan in the given pdp_server_metadata variant.
func (p PlanDefinition) WithMetadata(metadata string) PlanDefinition {
	p.Metadata = metadata
	return p
}

// Variant is the variant the plan is created with.
func (p PlanDefinition) Variant() map[string]string {
	metadata := p.Metadata
	if metadata == "" {
		metadata = Static
	}
	return map[string]string{"pdp_auth_type": "api_key", "pdp_server_metadata": metadata, "authzen_support": Support}
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
// suite-config/authzen-core.json with the PDP identifier and the api_key filled in, plus the
// five endpoints under the identifier in the static variant (the discovery variant takes them
// from the PDP's metadata, so none are configured).
func (p PlanDefinition) Config(pdp PDP) (json.RawMessage, error) {
	data, err := suiteConfigs.ReadFile("suite-config/authzen-core.json")
	if err != nil {
		return nil, err
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("suite-config/authzen-core.json: %w", err)
	}
	config["description"] = fmt.Sprintf("pgauthzd %s (%s) against %s", p.Name, p.Variant()["pdp_server_metadata"], pdp.BaseURL)
	section := map[string]any{
		"policy_decision_point": pdp.BaseURL,
		"api_key":               pdp.APIKey,
	}
	if p.Metadata != Discovery {
		section["access_evaluation_endpoint"] = pdp.BaseURL + "/access/v1/evaluation"
		section["access_evaluations_endpoint"] = pdp.BaseURL + "/access/v1/evaluations"
		section["search_subject_endpoint"] = pdp.BaseURL + "/access/v1/search/subject"
		section["search_resource_endpoint"] = pdp.BaseURL + "/access/v1/search/resource"
		section["search_action_endpoint"] = pdp.BaseURL + "/access/v1/search/action"
	}
	config["pdp"] = section
	return json.Marshal(config)
}
