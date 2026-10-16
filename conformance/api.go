package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIClient is the part of the suite's REST API the tests use: creating plans and modules,
// starting modules and reading their state and log. The same client as easyssf-go's.
type APIClient struct {
	baseURL *url.URL
	client  *http.Client
}

var terminalStates = map[string]bool{"FINISHED": true, "INTERRUPTED": true}

// NewAPIClient calls the suite at baseURL with client, which has to trust its certificate.
func NewAPIClient(baseURL *url.URL, client *http.Client) *APIClient {
	return &APIClient{baseURL: baseURL, client: client}
}

// BaseURL is the URL of the suite.
func (c *APIClient) BaseURL() *url.URL { return c.baseURL }

// Plan is a created plan.
type Plan struct {
	ID      string
	Name    string
	Variant map[string]string
	Modules []PlanModule
	// URL is the plan's page in the suite.
	URL string
}

// PlanModule is a module of a plan with the variant the plan assigns to it.
type PlanModule struct {
	Name    string
	Variant map[string]string
}

func (m PlanModule) String() string {
	if len(m.Variant) == 0 {
		return m.Name
	}
	return fmt.Sprintf("%s %v", m.Name, m.Variant)
}

// ModuleResult is the outcome of a module run as the suite reports it.
type ModuleResult struct {
	Plan     Plan
	Module   PlanModule
	ModuleID string
	Status   string
	Result   string
	// Logs are the log entries of the module as the suite returns them.
	Logs []map[string]any
	// URL is the module's log page in the suite.
	URL string
}

// FinishedWith reports whether the module finished with the expected result (PASSED, ...).
func (r ModuleResult) FinishedWith(expected string) bool {
	return r.Status == "FINISHED" && r.Result == expected
}

// Problems are the failures and warnings the suite logged.
func (r ModuleResult) Problems() []string {
	var problems []string
	for _, entry := range r.Logs {
		result, _ := entry["result"].(string)
		if result != "FAILURE" && result != "WARNING" {
			continue
		}
		problems = append(problems, formatLogEntry(entry))
	}
	return problems
}

// Summary is the result with the problems, for a failure message.
func (r ModuleResult) Summary() string {
	var summary strings.Builder
	fmt.Fprintf(&summary, "Conformance module %s of plan %s %v: status %s, result %s (%s)", r.Module, r.Plan.Name, r.Plan.Variant, r.Status, r.Result, r.URL)
	problems := r.Problems()
	if len(problems) == 0 {
		summary.WriteString("\n  no failures or warnings logged")
	}
	for i, problem := range problems {
		if i == 20 {
			break
		}
		summary.WriteString("\n  " + problem)
	}
	return summary.String()
}

func formatLogEntry(entry map[string]any) string {
	text := func(names ...string) string {
		for _, name := range names {
			if value, ok := entry[name].(string); ok && value != "" {
				return value
			}
		}
		return ""
	}
	formatted := fmt.Sprintf("%s %s: %s", text("result"), text("src", "condition"), text("msg", "message", "error"))
	for _, detail := range []string{"url", "match", "detail", "requirements"} {
		if value, ok := entry[detail]; ok && value != nil {
			encoded, _ := json.Marshal(value)
			formatted += " " + detail + "=" + string(encoded)
		}
	}
	return formatted
}

// WaitUntilAvailable waits until the suite answers /api/runner/available.
func (c *APIClient) WaitUntilAvailable(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		status, _, err := c.send(ctx, http.MethodGet, "/api/runner/available", nil, true)
		if err == nil && status == http.StatusOK {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("the conformance suite returned HTTP %d", status)
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("the conformance suite did not become available at %s: %w", c.baseURL, last)
}

// CreatePlan creates a plan and returns its id together with the modules it consists of.
func (c *APIClient) CreatePlan(ctx context.Context, planName string, variant map[string]string, config json.RawMessage) (Plan, error) {
	encodedVariant, _ := json.Marshal(variant)
	path := "/api/plan?planName=" + url.QueryEscape(planName) + "&variant=" + url.QueryEscape(string(encodedVariant))
	body, err := c.expectJSON(ctx, http.MethodPost, path, config, http.StatusCreated, true)
	if err != nil {
		return Plan{}, err
	}
	id, _ := body["id"].(string)
	if id == "" {
		return Plan{}, fmt.Errorf("conformance suite API response lacks 'id': %v", body)
	}
	plan := Plan{ID: id, Name: planName, Variant: variant, URL: c.baseURL.String() + "/plan-detail.html?plan=" + id}
	modules, _ := body["modules"].([]any)
	for _, element := range modules {
		module, _ := element.(map[string]any)
		name, _ := module["testModule"].(string)
		if name == "" {
			return Plan{}, fmt.Errorf("conformance suite API response lacks 'testModule': %v", module)
		}
		plan.Modules = append(plan.Modules, PlanModule{Name: name, Variant: stringMap(module["variant"])})
	}
	return plan, nil
}

// StartModule creates and starts a module of a plan and returns the id of the module. A PDP
// module needs nothing from the system under test to begin — the suite calls the PDP itself —
// so it runs to its end on its own; AwaitResult collects the outcome.
func (c *APIClient) StartModule(ctx context.Context, plan Plan, module PlanModule) (string, error) {
	encodedVariant, _ := json.Marshal(module.Variant)
	path := "/api/runner?test=" + url.QueryEscape(module.Name) + "&plan=" + url.QueryEscape(plan.ID) + "&variant=" + url.QueryEscape(string(encodedVariant))
	created, err := c.expectJSON(ctx, http.MethodPost, path, nil, http.StatusCreated, true)
	if err != nil {
		return "", err
	}
	id, _ := created["id"].(string)
	if id == "" {
		return "", fmt.Errorf("conformance suite API response lacks 'id': %v", created)
	}
	info, err := c.waitForState(ctx, id, 2*time.Minute, "CONFIGURED", "WAITING", "RUNNING")
	if err != nil {
		return "", err
	}
	if info["status"] == "CONFIGURED" {
		// not replayed, as a lost response would start the module a second time
		if _, err := c.expectJSON(ctx, http.MethodPost, "/api/runner/"+id, nil, http.StatusOK, false); err != nil {
			return "", err
		}
	}
	return id, nil
}

// AwaitResult waits until the module ended and returns its result with its log.
func (c *APIClient) AwaitResult(ctx context.Context, plan Plan, module PlanModule, moduleID string, timeout time.Duration) (ModuleResult, error) {
	info, err := c.waitForState(ctx, moduleID, timeout)
	if err != nil {
		return ModuleResult{}, err
	}
	status, body, err := c.send(ctx, http.MethodGet, "/api/log/"+moduleID, nil, true)
	var logs []map[string]any
	if err == nil && status == http.StatusOK {
		_ = json.Unmarshal(body, &logs)
	}
	result := ModuleResult{Plan: plan, Module: module, ModuleID: moduleID, Logs: logs, URL: c.baseURL.String() + "/log-detail.html?log=" + moduleID, Result: "UNKNOWN"}
	result.Status, _ = info["status"].(string)
	if r, ok := info["result"].(string); ok && r != "" {
		result.Result = r
	}
	return result, nil
}

// Info is the state of a module.
func (c *APIClient) Info(ctx context.Context, moduleID string) (map[string]any, error) {
	return c.expectJSON(ctx, http.MethodGet, "/api/info/"+moduleID, nil, http.StatusOK, true)
}

// waitForState waits until the module is in one of the states or in a terminal one.
func (c *APIClient) waitForState(ctx context.Context, moduleID string, timeout time.Duration, states ...string) (map[string]any, error) {
	deadline := time.Now().Add(timeout)
	var last map[string]any
	var lastErr error
	for time.Now().Before(deadline) {
		info, err := c.Info(ctx, moduleID)
		if err == nil {
			last = info
			status, _ := info["status"].(string)
			if terminalStates[status] {
				return info, nil
			}
			for _, state := range states {
				if state == status {
					return info, nil
				}
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("timed out waiting for module %s to reach %v; last info: %v: %w", moduleID, states, last, lastErr)
	}
	return nil, fmt.Errorf("timed out waiting for module %s to reach %v; last info: %v", moduleID, states, last)
}

func (c *APIClient) expectJSON(ctx context.Context, method, path string, body []byte, expected int, replayable bool) (map[string]any, error) {
	status, response, err := c.send(ctx, method, path, body, replayable)
	if err != nil {
		return nil, err
	}
	if status != expected {
		return nil, fmt.Errorf("conformance suite API %s %s returned HTTP %d: %s", method, path, status, response)
	}
	var parsed map[string]any
	if err := json.Unmarshal(response, &parsed); err != nil {
		return nil, fmt.Errorf("conformance suite API %s %s answered with invalid JSON: %w", method, path, err)
	}
	return parsed, nil
}

// send sends a request; the suite occasionally drops a connection, so transient failures of
// replayable requests are retried.
func (c *APIClient) send(ctx context.Context, method, path string, body []byte, replayable bool) (int, []byte, error) {
	attempts := 1
	if replayable {
		attempts = 4
	}
	target := c.baseURL.String() + path
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		requestCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		request, err := http.NewRequestWithContext(requestCtx, method, target, reader)
		if err != nil {
			cancel()
			return 0, nil, err
		}
		request.Header.Set("Accept", "application/json")
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := c.client.Do(request)
		if err == nil {
			data, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			cancel()
			if readErr == nil {
				return response.StatusCode, data, nil
			}
			err = readErr
		} else {
			cancel()
		}
		lastErr = err
		if attempt < attempts {
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
	}
	return 0, nil, fmt.Errorf("conformance suite API request failed: %s: %w", target, lastErr)
}

func stringMap(value any) map[string]string {
	object, _ := value.(map[string]any)
	result := map[string]string{}
	for name, v := range object {
		result[name] = fmt.Sprint(v)
	}
	return result
}
