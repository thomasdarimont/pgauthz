package config

import (
	"strings"
	"testing"
)

// Decision log settings (ADR 0013): sink and sample are validated at load.
func TestDecisionLogConfig(t *testing.T) {
	load := func(extra map[string]string) (*Config, error) {
		setIssuers(t, `[{"issuer":"https://a","jwks_file":"/keys/a.json","stores":["demo"]}]`)
		t.Setenv("DECISION_LOG", "")
		t.Setenv("DECISION_LOG_SAMPLE", "")
		t.Setenv("DECISION_LOG_DETAIL", "")
		t.Setenv("DECISION_LOG_REQUIRED", "")
		t.Setenv("DECISION_LOG_SEARCHES", "")
		for k, v := range extra {
			t.Setenv(k, v)
		}
		return Load()
	}
	if c, err := load(nil); err != nil {
		t.Fatalf("baseline config rejected: %v", err)
	} else if c.DecisionLog != "off" || c.DecisionLogSample != 1 || c.DecisionLogDetail {
		t.Fatalf("defaults: sink=%q sample=%v detail=%v", c.DecisionLog, c.DecisionLogSample, c.DecisionLogDetail)
	}
	if c, err := load(map[string]string{"DECISION_LOG": "file:/tmp/d.log", "DECISION_LOG_SAMPLE": "0.25", "DECISION_LOG_DETAIL": "true"}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	} else if c.DecisionLog != "file:/tmp/d.log" || c.DecisionLogSample != 0.25 || !c.DecisionLogDetail {
		t.Fatalf("values not parsed: %+v", c)
	}
	if _, err := load(map[string]string{"DECISION_LOG": "syslog"}); err == nil || !strings.Contains(err.Error(), "DECISION_LOG") {
		t.Fatalf("bad sink accepted: %v", err)
	}
	if _, err := load(map[string]string{"DECISION_LOG": "file:"}); err == nil {
		t.Fatal("empty file path accepted")
	}
	if _, err := load(map[string]string{"DECISION_LOG_SAMPLE": "2"}); err == nil || !strings.Contains(err.Error(), "DECISION_LOG_SAMPLE") {
		t.Fatalf("bad sample accepted: %v", err)
	}
	// strict delivery / search lines need a sink
	if _, err := load(map[string]string{"DECISION_LOG_REQUIRED": "true"}); err == nil || !strings.Contains(err.Error(), "DECISION_LOG_REQUIRED") {
		t.Fatalf("required without a sink accepted: %v", err)
	}
	if _, err := load(map[string]string{"DECISION_LOG_SEARCHES": "true"}); err == nil || !strings.Contains(err.Error(), "DECISION_LOG_SEARCHES") {
		t.Fatalf("searches without a sink accepted: %v", err)
	}
	if c, err := load(map[string]string{"DECISION_LOG": "stdout", "DECISION_LOG_REQUIRED": "true", "DECISION_LOG_SEARCHES": "true"}); err != nil || !c.DecisionLogRequired || !c.DecisionLogSearches {
		t.Fatalf("valid strict config: %v %+v", err, c)
	}
	// required = complete: sampling is refused
	if _, err := load(map[string]string{"DECISION_LOG": "stdout", "DECISION_LOG_REQUIRED": "true", "DECISION_LOG_SAMPLE": "0.5"}); err == nil || !strings.Contains(err.Error(), "DECISION_LOG_SAMPLE must be 1") {
		t.Fatalf("required with sampling accepted: %v", err)
	}
}
