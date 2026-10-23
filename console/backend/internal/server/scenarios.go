package server

// Saved test scenarios: one tests.authz.yaml fixture per managed store,
// kept in the console's own database, run through pgauthzadm.RunFixture —
// the same runner as `pgauthzctl model test` — in an ephemeral store, so a
// run never touches the store's data. In the console a fixture tests the
// store's CURRENT model by default (no model_file: the BFF exports the
// store's model and imports it into the ephemeral store); a registry ref
// (`model: name@version`) works as in the CLI; `model_file` is refused
// (there are no files here). The export hands the fixture plus the model
// as DSL to pgauthzctl, with model_file filled in.
//
// Gates: reading and running need can_run_tests, and a run is bound by the
// test policy like every other Test-tab query — the fixture's subjects are
// other people (can_test_others), list_objects cases enumerate
// (can_test_search), explain cases read reason paths
// (can_test_explain_full). Saving is a model-authoring act: can_edit_model.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"thomasdarimont.de/authz/pgauthzadm"
)

const scenariosMaxBytes = 256 << 10

type scenariosRow struct {
	YAML      string     `json:"yaml"`
	UpdatedAt *time.Time `json:"updated_at"`
	UpdatedBy string     `json:"updated_by"`
}

func (s *Server) loadScenarios(ctx context.Context, store string) (scenariosRow, error) {
	var row scenariosRow
	var by *string
	err := s.db.QueryRow(ctx, `SELECT yaml, updated_at, updated_by FROM scenarios WHERE store = $1`, store).
		Scan(&row.YAML, &row.UpdatedAt, &by)
	if errors.Is(err, pgx.ErrNoRows) {
		return scenariosRow{}, nil
	}
	if by != nil {
		row.UpdatedBy = *by
	}
	return row, err
}

// parseConsoleFixture — ParseFixture with the console's model rule: no
// model_file, no other store (this store's current model instead, unless
// a registry ref). The fixture's Store is this store when it names none.
func parseConsoleFixture(store, yml string) (*pgauthzadm.Fixture, error) {
	if len(yml) > scenariosMaxBytes {
		return nil, fmt.Errorf("scenarios exceed %d KiB", scenariosMaxBytes>>10)
	}
	var fix pgauthzadm.Fixture
	if err := pgauthzadm.UnmarshalFixture([]byte(yml), &fix); err != nil {
		return nil, err
	}
	if fix.ModelFile != "" {
		return nil, fmt.Errorf("model_file is not available in the console: leave the model out to test this store's current model, or name a registry model (model: name@version)")
	}
	if fix.Store != "" && fix.Store != store {
		return nil, fmt.Errorf("store: %s — scenarios here test this store's current model; leave the store out", fix.Store)
	}
	if fix.Model == "" {
		fix.Store = store
	}
	if err := fix.Validate(); err != nil {
		return nil, err
	}
	return &fix, nil
}

// handleScenarios — GET .../scenarios: the saved fixture and whether the
// person may change it.
func (s *Server) handleScenarios(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_run_tests")
	if p == nil {
		return
	}
	row, err := s.loadScenarios(r.Context(), store)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	canEdit, err := s.can(r.Context(), p, "can_edit_model", "store", store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	cases := 0
	if row.YAML != "" {
		if fix, err := parseConsoleFixture(store, row.YAML); err == nil {
			cases = countCases(fix)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"yaml": row.YAML, "updated_at": row.UpdatedAt, "updated_by": row.UpdatedBy,
		"can_edit": canEdit, "cases": cases,
	})
}

func countCases(fix *pgauthzadm.Fixture) int {
	n := 0
	for _, tc := range fix.Tests {
		for _, c := range tc.Check {
			n += len(c.Assertions)
		}
		for _, l := range tc.ListObjects {
			n += len(l.Assertions)
		}
		n += len(tc.Explain)
	}
	return n
}

type scenariosReq struct {
	YAML string `json:"yaml"`
}

// handleScenariosSave — PUT .../scenarios: validate and store the fixture,
// recorded as the person (an empty body deletes it).
func (s *Server) handleScenariosSave(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_edit_model")
	if p == nil {
		return
	}
	var req scenariosReq
	if !decodeJSON(w, r, &req) {
		return
	}
	cases := 0
	if strings.TrimSpace(req.YAML) != "" {
		fix, err := parseConsoleFixture(store, req.YAML)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		cases = countCases(fix)
	}
	ctx := r.Context()
	err := s.asPerson(ctx, p, "can_edit_model", "store", store, map[string]any{"op": "scenarios_save", "cases": cases, "bytes": len(req.YAML)}, func(pgx.Tx) error {
		if strings.TrimSpace(req.YAML) == "" {
			_, err := s.db.Exec(ctx, `DELETE FROM scenarios WHERE store = $1`, store)
			return err
		}
		_, err := s.db.Exec(ctx, `
			INSERT INTO scenarios (store, yaml, updated_at, updated_by) VALUES ($1, $2, now(), $3)
			ON CONFLICT (store) DO UPDATE SET yaml = EXCLUDED.yaml, updated_at = now(), updated_by = EXCLUDED.updated_by`,
			store, req.YAML, p.typ+":"+p.id)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cases": cases})
}

// handleScenariosRun — POST .../scenarios/run: run the posted fixture (the
// editor's draft; the saved one when the body is empty) in an ephemeral
// store, as the person, bound by the test policy.
func (s *Server) handleScenariosRun(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_run_tests")
	if p == nil {
		return
	}
	var req scenariosReq
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	yml := req.YAML
	if strings.TrimSpace(yml) == "" {
		row, err := s.loadScenarios(ctx, store)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		yml = row.YAML
	}
	if strings.TrimSpace(yml) == "" {
		writeError(w, http.StatusBadRequest, "no scenarios to run")
		return
	}
	fix, err := parseConsoleFixture(store, yml)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pol, err := s.testPolicyFor(ctx, p, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if !pol.Others {
		writePolicyDenied(w, "can_test_others", "the test policy limits you to your own access; scenarios decide for other subjects")
		return
	}
	for _, tc := range fix.Tests {
		if len(tc.ListObjects) > 0 && !pol.Search {
			writePolicyDenied(w, "can_test_search", "the test policy does not let you enumerate objects (scenario "+tc.Name+" has list_objects)")
			return
		}
		if len(tc.Explain) > 0 && !pol.ExplainFull {
			writePolicyDenied(w, "can_test_explain_full", "the test policy does not let you read resolution paths (scenario "+tc.Name+" has explain)")
			return
		}
	}

	b := make([]byte, 4)
	_, _ = rand.Read(b)
	// fix.Store is this store (parseConsoleFixture): RunFixture exports its
	// live model and rebuilds it in the ephemeral store, loss-free
	opts := pgauthzadm.RunOptions{Store: "console_scenarios_" + hex.EncodeToString(b), PurgeAudit: true}
	var report *pgauthzadm.RunReport
	err = s.asPerson(ctx, p, "can_run_tests", "store", store, map[string]any{"op": "scenarios_run", "cases": countCases(fix), "tests": len(fix.Tests)}, func(tx pgx.Tx) error {
		var err error
		report, err = pgauthzadm.RunFixture(ctx, tx, fix, opts)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results": report.Results, "failed": report.Failed, "passed": len(report.Results) - report.Failed,
		"duration_ms": report.Duration.Milliseconds(),
	})
}

// handleScenariosExport — GET .../scenarios/export: the fixture for
// pgauthzctl (model_file filled in when it tests the store's model) and
// the store's model as DSL to save beside it.
func (s *Server) handleScenariosExport(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_run_tests")
	if p == nil {
		return
	}
	ctx := r.Context()
	row, err := s.loadScenarios(ctx, store)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if strings.TrimSpace(row.YAML) == "" {
		writeError(w, http.StatusNotFound, "no scenarios saved")
		return
	}
	fix, err := parseConsoleFixture(store, row.YAML)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out := map[string]any{"store": store}
	yml := row.YAML
	if fix.Store == store {
		dsl, err := pgauthzadm.DescribeModel(ctx, s.engine, store)
		if err != nil {
			writeEngineError(w, err)
			return
		}
		out["model_fga"] = dsl
		yml = "model_file: ./model.fga\n" + yml
	}
	out["yaml"] = yml
	out["command"] = "pgauthzctl model test ./tests.authz.yaml --junit report.xml"
	writeJSON(w, http.StatusOK, out)
}
