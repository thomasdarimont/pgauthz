package main

// The model verbs over the admin API (--server): the same verbs, the
// daemon's gate and audit, no database credentials. One method per verb;
// each cmd* below asks apiModelVerbs first and falls back to the database.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"thomasdarimont.de/authz/pgauthzadm"
)

type apiModel struct{ c *adminClient }

func apiModelFor(fs serverFlags) (*apiModel, error) {
	if !fs.set() {
		return nil, nil
	}
	c, err := newAdminClient(fs)
	if err != nil {
		return nil, err
	}
	return &apiModel{c: c}, nil
}

func modelRef(name string, version int) string {
	if version > 0 {
		return name + "@" + strconv.Itoa(version)
	}
	return name
}

// plan: PUT …/model?plan=true
func (m *apiModel) plan(ctx context.Context, store, name string, version int) (pgauthzadm.Plan, error) {
	var res struct {
		Plan pgauthzadm.Plan `json:"plan"`
	}
	err := m.c.do(ctx, "PUT", "/pgauthz/v1/admin/stores/"+url.PathEscape(store)+"/model?plan=true", map[string]string{"model": modelRef(name, version)}, &res)
	return res.Plan, err
}

// apply: PUT …/model — the daemon plans first; blockers come back as 409 with the plan.
func (m *apiModel) apply(ctx context.Context, store, name string, version int) (int, error) {
	var res struct {
		Applied int `json:"applied"`
	}
	err := m.c.do(ctx, "PUT", "/pgauthz/v1/admin/stores/"+url.PathEscape(store)+"/model", map[string]string{"model": modelRef(name, version)}, &res)
	return res.Applied, err
}

func (m *apiModel) export(ctx context.Context, store string, dsl bool) (json.RawMessage, string, error) {
	var res struct {
		Definition json.RawMessage `json:"definition"`
		DSL        string          `json:"dsl"`
	}
	q := ""
	if dsl {
		q = "?dsl=true"
	}
	err := m.c.do(ctx, "GET", "/pgauthz/v1/admin/stores/"+url.PathEscape(store)+"/model"+q, nil, &res)
	return res.Definition, res.DSL, err
}

func (m *apiModel) status(ctx context.Context, store string) (*pgauthzadm.Status, error) {
	var res struct {
		Model pgauthzadm.Status `json:"model"`
	}
	if err := m.c.do(ctx, "GET", "/pgauthz/v1/admin/stores/"+url.PathEscape(store), nil, &res); err != nil {
		return nil, err
	}
	res.Model.Store = store
	return &res.Model, nil
}

func (m *apiModel) versions(ctx context.Context, name string) ([]pgauthzadm.Version, error) {
	var res struct {
		Versions []pgauthzadm.Version `json:"versions"`
	}
	q := ""
	if name != "" {
		q = "?name=" + url.QueryEscape(name)
	}
	err := m.c.do(ctx, "GET", "/pgauthz/v1/admin/models"+q, nil, &res)
	return res.Versions, err
}

func (m *apiModel) rollout(ctx context.Context, name string) ([]pgauthzadm.RolloutRow, error) {
	var res struct {
		Stores []pgauthzadm.RolloutRow `json:"stores"`
	}
	err := m.c.do(ctx, "GET", "/pgauthz/v1/admin/models/"+url.PathEscape(name)+"/rollout", nil, &res)
	return res.Stores, err
}

// publish: an OpenFGA model (what the file parsed to), converted on the server.
func (m *apiModel) publish(ctx context.Context, name string, openfga json.RawMessage, description string) (int, error) {
	var res struct {
		Version int `json:"version"`
	}
	err := m.c.do(ctx, "POST", "/pgauthz/v1/admin/models/"+url.PathEscape(name)+"/versions", map[string]any{"openfga": openfga, "description": description}, &res)
	return res.Version, err
}

// explain409 renders the plan a refused apply carried.
func explain409(err error) error {
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == 409 {
		return fmt.Errorf("apply refused: %s", ae.Message)
	}
	return err
}

// deprecatedDSN says, once per run, where routine operations are going.
func noteDSN(verb string) {
	fmt.Fprintf(os.Stderr, "note: %s ran over the database (--dsn); the admin API (--server, PGAUTHZ_SERVER) is the long-run transport for routine operations\n", verb)
}

var _ = strings.TrimSpace
