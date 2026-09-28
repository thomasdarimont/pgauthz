// Package doctor is `pgauthzd doctor`: a preflight that evaluates a
// deployment's configuration and reachable dependencies the way the daemon
// would at startup, plus the checks the production guide asks operators to
// verify by hand — demo secrets, open diagnostic surfaces, issuer bindings,
// JWKS reachability, DB role capability, the callback listener, OPA, the
// decision-log sink. It never serves and never writes to the engine.
//
// Statuses: ok | warn | fail | skip. The exit code is 1 when anything fails
// (2 with --strict when anything warns). `--profile production` evaluates the
// production profile even when DEPLOYMENT_ENVIRONMENT is not set, so a
// pipeline can ask "would this config pass in production?" before promoting.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/internal/decisionlog"
	"thomasdarimont.de/authz/pgauthzd/internal/pgbackend"
)

// Check is one preflight result.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail | skip
	Detail string `json:"detail,omitempty"`
}

// Report is the full preflight result.
type Report struct {
	Version     string  `json:"pgauthzd_version"`
	Profile     string  `json:"profile,omitempty"`     // decision-only | full
	Environment string  `json:"environment,omitempty"` // DEPLOYMENT_ENVIRONMENT as evaluated
	Checks      []Check `json:"checks"`
	Failed      int     `json:"failed"`
	Warned      int     `json:"warned"`
}

// Options control a run.
type Options struct {
	// ForceProduction evaluates the production profile regardless of
	// DEPLOYMENT_ENVIRONMENT.
	ForceProduction bool
	// Timeout bounds every network probe (JWKS, OPA, DB).
	Timeout time.Duration
	// Version is the daemon build, reported in the header.
	Version string
	// HTTP is the client for JWKS/OPA probes (tests inject one).
	HTTP *http.Client
}

const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusFail = "fail"
	StatusSkip = "skip"
)

// demoSecrets are values shipped in the compose/Helm demos; any of them in a
// real deployment is a finding.
var demoSecrets = []string{"dev-native-service-token", "playground-bff-demo-secret", "pgauthz-demo-secret"}

// Run performs the preflight.
func Run(ctx context.Context, opts Options) *Report {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.HTTP == nil {
		opts.HTTP = &http.Client{Timeout: opts.Timeout}
	}
	r := &Report{Version: opts.Version}
	add := func(name, status, detail string) {
		r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
		switch status {
		case StatusFail:
			r.Failed++
		case StatusWarn:
			r.Warned++
		}
	}

	if opts.ForceProduction {
		os.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
	}
	cfg, err := config.Load()
	if err != nil {
		// The same error the daemon would die with — the production profile's
		// gate checks, invalid values, unbound issuers, etc.
		add("config", StatusFail, err.Error())
		return r
	}
	r.Profile = string(cfg.Profile)
	r.Environment = cfg.DeploymentEnvironment
	add("config", StatusOK, fmt.Sprintf("profile=%s listen=%s", cfg.Profile, cfg.ListenAddr))

	// ── production profile ────────────────────────────────────────────────
	prod := cfg.DeploymentEnvironment == "production" || cfg.DeploymentEnvironment == "prod"
	if prod {
		if cfg.AllowOpenDiagnostics {
			add("production profile", StatusWarn, "ALLOW_OPEN_DIAGNOSTICS=true overrides the production gates — deliberate?")
		} else {
			add("production profile", StatusOK, "DEPLOYMENT_ENVIRONMENT="+cfg.DeploymentEnvironment+", diagnostic gates enforced")
		}
	} else {
		add("production profile", StatusWarn, "not evaluated: DEPLOYMENT_ENVIRONMENT is not production (run `pgauthzd doctor --profile production` before promoting)")
	}

	// ── diagnostic surfaces ──────────────────────────────────────────────
	var open []string
	if cfg.SearchRequiredRole == "" {
		open = append(open, "search (SEARCH_REQUIRED_ROLE)")
	}
	if cfg.ExplainRequiredRole == "" {
		open = append(open, "explain (EXPLAIN_REQUIRED_ROLE)")
	}
	if cfg.WatchRequiredRole == "*" {
		open = append(open, "watch (WATCH_REQUIRED_ROLE=\"*\")")
	}
	switch {
	case len(open) == 0:
		add("diagnostic surfaces", StatusOK, "search, explain and watch are role-gated or disabled")
	case prod:
		add("diagnostic surfaces", StatusFail, "open in production: "+strings.Join(open, ", "))
	default:
		add("diagnostic surfaces", StatusWarn, "open to any authenticated caller: "+strings.Join(open, ", "))
	}

	// ── demo secrets ─────────────────────────────────────────────────────
	var demo []string
	for _, s := range demoSecrets {
		if cfg.InternalServiceToken == s {
			demo = append(demo, "INTERNAL_SERVICE_TOKEN is the demo value")
		}
	}
	if pw := dbPassword(cfg.DatabaseURL); pw == "authz" || pw == "postgres" || pw == "password" {
		demo = append(demo, "DATABASE_URL uses the demo password")
	}
	for _, iss := range cfg.Issuers {
		if iss.Issuer == "https://auth.example.com" {
			demo = append(demo, "the demo issuer https://auth.example.com is trusted")
		}
	}
	if len(demo) > 0 {
		status := StatusWarn
		if prod {
			status = StatusFail
		}
		add("demo secrets", status, strings.Join(demo, "; "))
	} else {
		add("demo secrets", StatusOK, "no demo credentials or issuers")
	}

	// ── issuers, bindings, JWKS ──────────────────────────────────────────
	if len(cfg.Issuers) == 0 {
		add("issuers", StatusFail, "no trusted issuer configured")
	} else {
		var unbound, unreachable []string
		for _, iss := range cfg.Issuers {
			if len(iss.Stores) == 0 {
				unbound = append(unbound, iss.Issuer)
			}
			if perr := probeJWKS(ctx, opts.HTTP, iss); perr != nil {
				unreachable = append(unreachable, iss.Issuer+": "+perr.Error())
			}
		}
		add("issuers", StatusOK, fmt.Sprintf("%d issuer(s)", len(cfg.Issuers)))
		switch {
		case len(unbound) == 0:
			add("issuer store bindings", StatusOK, "every issuer is bound to its stores")
		case len(cfg.Issuers) > 1:
			add("issuer store bindings", StatusFail, "unbound in a multi-issuer setup: "+strings.Join(unbound, ", "))
		default:
			add("issuer store bindings", StatusWarn, "single issuer without a stores binding (reaches every store)")
		}
		if len(unreachable) == 0 {
			add("jwks", StatusOK, "signing keys loaded for every issuer")
		} else {
			add("jwks", StatusFail, strings.Join(unreachable, "; "))
		}
	}

	// ── subject trust ────────────────────────────────────────────────────
	if cfg.AllowSubjectOverride {
		add("subject override", StatusWarn, "ALLOW_SUBJECT_OVERRIDE=true: callers may name any subject (trusted-PEP mode) — keep this listener PEP-only")
	} else {
		add("subject override", StatusOK, "the token subject is authoritative")
	}

	// ── cursor sealing / freshness ───────────────────────────────────────
	if cfg.UsesOPA() && cfg.CursorSealKey == "" {
		status := StatusWarn
		if prod {
			status = StatusFail
		}
		add("cursor seal key", status, "CURSOR_SEAL_KEY unset on an OPA-fronted instance: filtered-enumeration cursors do not survive restarts or replica hops")
	} else {
		add("cursor seal key", StatusOK, "set or not needed")
	}
	if cfg.FreshnessEnabled() {
		add("freshness tokens", StatusOK, "enabled")
	} else {
		add("freshness tokens", StatusSkip, "disabled (no FRESHNESS_KEYS)")
	}

	// ── database ─────────────────────────────────────────────────────────
	if cfg.DatabaseURL == "" {
		if cfg.UsesOPA() {
			add("database", StatusSkip, "DB-less OPA gateway")
		} else {
			add("database", StatusFail, "DATABASE_URL is required without OPA_URL")
		}
	} else {
		probeDB(ctx, cfg, opts.Timeout, add)
	}

	// ── callback listener ────────────────────────────────────────────────
	if cfg.InternalListenAddr == "" {
		add("callback listener", StatusSkip, "not enabled (INTERNAL_LISTEN_ADDR unset)")
	} else {
		mtls := cfg.InternalTLSCert != "" && cfg.InternalClientCA != ""
		detail := "addr=" + cfg.InternalListenAddr + ", service token set"
		if mtls {
			add("callback listener", StatusOK, detail+", mTLS on")
		} else if prod {
			add("callback listener", StatusWarn, detail+", no mTLS — relies on network isolation (NetworkPolicy) plus the service token")
		} else {
			add("callback listener", StatusOK, detail+", no mTLS")
		}
	}

	// ── OPA ──────────────────────────────────────────────────────────────
	if !cfg.UsesOPA() {
		add("opa", StatusSkip, "not fronting OPA")
	} else if perr := probeHTTP(ctx, opts.HTTP, strings.TrimRight(cfg.OPAURL, "/")+"/health"); perr != nil {
		add("opa", StatusFail, cfg.OPAURL+": "+perr.Error())
	} else {
		add("opa", StatusOK, cfg.OPAURL+" healthy (package "+cfg.OPAPackage+")")
	}

	// ── decision log sink ────────────────────────────────────────────────
	if cfg.DecisionLog == "" || cfg.DecisionLog == "off" {
		add("decision log", StatusSkip, "off")
	} else if l, lerr := decisionlog.Open(decisionlog.Config{Sink: cfg.DecisionLog, Sample: cfg.DecisionLogSample}); lerr != nil {
		add("decision log", StatusFail, lerr.Error())
	} else {
		_ = l.Close()
		add("decision log", StatusOK, fmt.Sprintf("sink=%s sample=%v detail=%v", cfg.DecisionLog, cfg.DecisionLogSample, cfg.DecisionLogDetail))
	}

	// ── metrics ──────────────────────────────────────────────────────────
	if cfg.MetricsListenAddr == "" {
		add("metrics", StatusWarn, "METRICS_LISTEN_ADDR unset: no Prometheus endpoint")
	} else {
		add("metrics", StatusOK, "listener "+cfg.MetricsListenAddr)
	}
	return r
}

// probeJWKS loads an issuer's signing keys the way the daemon does: a file
// must exist and parse as a JWKS with keys; a URL must answer 200 with one.
func probeJWKS(ctx context.Context, hc *http.Client, iss config.Issuer) error {
	var raw []byte
	switch {
	case iss.JWKSFile != "":
		b, err := os.ReadFile(iss.JWKSFile)
		if err != nil {
			return err
		}
		raw = b
	case iss.JWKSURL != "":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, iss.JWKSURL, nil)
		if err != nil {
			return err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s returned %d", iss.JWKSURL, resp.StatusCode)
		}
		raw, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("no jwks_url or jwks_file")
	}
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &jwks); err != nil {
		return fmt.Errorf("not a JWKS document: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return fmt.Errorf("JWKS has no keys")
	}
	return nil
}

func probeHTTP(ctx context.Context, hc *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// probeDB connects, verifies the role matches the profile (the same
// assertions the daemon makes at startup), and reports migrations + stores.
func probeDB(ctx context.Context, cfg *config.Config, timeout time.Duration, add func(name, status, detail string)) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pool, err := pgxpool.New(cctx, cfg.DatabaseURL)
	if err != nil {
		add("database", StatusFail, err.Error())
		return
	}
	defer pool.Close()
	var user string
	if err := pool.QueryRow(cctx, "SELECT current_user").Scan(&user); err != nil {
		add("database", StatusFail, "connect: "+redactErr(err))
		return
	}
	// "Engine installed" must be answerable by every connection role: the
	// catalog is readable by all, the engine's tables are not (SECURITY
	// DEFINER functions are the API). Counts are reported only when the role
	// may read the tables (an admin/migration role), never required.
	var installed bool
	if err := pool.QueryRow(cctx,
		"SELECT to_regprocedure('authz.check_access(text,text,text,text,text,text)') IS NOT NULL").Scan(&installed); err != nil {
		add("database", StatusFail, "connected as "+user+" but could not inspect the catalog: "+redactErr(err))
		return
	}
	if !installed {
		add("database", StatusFail, "connected as "+user+" but the pgauthz engine is not installed (authz.check_access missing) — run the migrations + engine load")
		return
	}
	detail := "connected as " + user + ", engine installed"
	var migrations, stores *int
	_ = pool.QueryRow(cctx, `SELECT CASE WHEN has_table_privilege('public._sqlx_migrations', 'SELECT')
	                                THEN (SELECT count(*)::int FROM public._sqlx_migrations) END`).Scan(&migrations)
	_ = pool.QueryRow(cctx, `SELECT CASE WHEN has_table_privilege('authz.stores', 'SELECT')
	                                THEN (SELECT count(*)::int FROM authz.stores WHERE deleted_at IS NULL) END`).Scan(&stores)
	if migrations != nil {
		detail += fmt.Sprintf(", %d migrations applied", *migrations)
	}
	if stores != nil {
		detail += fmt.Sprintf(", %d store(s)", *stores)
	}
	add("database", StatusOK, detail)

	b := pgbackend.New(pool, nil, time.Duration(cfg.DBRoleCacheTTLSeconds)*time.Second, cfg.DefaultDBRole, "doctor")
	if cfg.Profile == config.ProfileDecisionOnly {
		if err := b.AssertReadOnly(cctx); err != nil {
			add("db role", StatusFail, err.Error())
		} else {
			add("db role", StatusOK, "read-only, as a decision-only instance requires")
		}
	} else {
		if err := b.AssertWritable(cctx); err != nil {
			add("db role", StatusFail, err.Error())
		} else {
			add("db role", StatusOK, "writer-capable, as a full instance requires")
		}
	}
}

// dbPassword extracts the password of a postgres:// URL without importing a
// parser that would log it; only used to compare against demo values.
func dbPassword(dsn string) string {
	if i := strings.Index(dsn, "://"); i >= 0 {
		rest := dsn[i+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			userinfo := rest[:at]
			if c := strings.Index(userinfo, ":"); c >= 0 {
				return userinfo[c+1:]
			}
		}
	}
	for _, kv := range strings.Fields(dsn) {
		if strings.HasPrefix(kv, "password=") {
			return strings.TrimPrefix(kv, "password=")
		}
	}
	return ""
}

func redactErr(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// Print writes the report as a table.
func (r *Report) Print(w io.Writer) {
	fmt.Fprintf(w, "pgauthzd doctor  version=%s profile=%s environment=%s\n\n", r.Version, orDash(r.Profile), orDash(r.Environment))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, c := range r.Checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", strings.ToUpper(c.Status), c.Name, c.Detail)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n%d failed, %d warning(s)\n", r.Failed, r.Warned)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ExitCode maps a report to a process exit code.
func (r *Report) ExitCode(strict bool) int {
	switch {
	case r.Failed > 0:
		return 1
	case strict && r.Warned > 0:
		return 2
	default:
		return 0
	}
}
