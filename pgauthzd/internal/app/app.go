// Package app is the entrypoint for pgauthzd. PGAUTHORIZER_PROFILE selects the
// backend + capability (decision-only | full; OPA_URL orthogonally fronts OPA); everything else is
// identical.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"thomasdarimont.de/authz/pgauthzd/internal/api"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/internal/decisionlog"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
	"thomasdarimont.de/authz/pgauthzd/internal/opabackend"
	"thomasdarimont.de/authz/pgauthzd/internal/pgbackend"
	"thomasdarimont.de/authz/pgauthzd/internal/telemetry"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Run loads config, wires the profile's backend, and serves. `name` is used for
// log lines; `version` labels the build_info metric.
func Run(name, version string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	setupLogging(cfg.LogLevel)

	// Sealed page cursors (filtered enumeration, ADR 0011): derive the AEAD
	// keyring once. The per-process fallback is DEVELOPMENT-ONLY — on an
	// OPA-fronted instance every restart/replica-hop then 400s in-flight
	// filtered paginations, so production sets a shared key.
	api.InitCursorSeal(cfg.CursorSealKey)
	if cfg.CursorSealKey == "" && cfg.UsesOPA() {
		slog.Warn("CURSOR_SEAL_KEY is not set: filtered-enumeration page cursors use a per-process key " +
			"(dev-only — they will not survive restarts or replica hops; set a shared CURSOR_SEAL_KEY in production)")
	}

	// build_info (ADR 0010): value 1, labels carry version/commit/profile/features.
	fallbackEnabled := cfg.FreshnessPrimaryURL != "" && cfg.Profile == config.ProfileDecisionOnly && !cfg.UsesOPA()
	metrics.SetBuildInfo(version, buildCommit(), runtime.Version(), string(cfg.Profile),
		cfg.UsesOPA(), cfg.FreshnessEnabled(), fallbackEnabled)
	// Pre-init the per-kid rotation-drain series so a retiring key exports 0
	// (not "missing") from startup.
	metrics.InitFreshnessKeyIDs(authz.NewKeyring(cfg.FreshnessKeys).KIDs())
	// The served OpenAPI document reports the build version as info.version.
	api.SetOpenAPIVersion(version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// OpenTelemetry — set up BEFORE the backends and listeners are built: the
	// engine pool's query tracer and the OPA client's transport are chosen at
	// construction from telemetry.Enabled(). TRACING=auto is on only when the
	// OTEL_* environment configures an OTLP exporter; on: propagation (W3C +
	// B3, in and out), a span per request (newServer) and per decision
	// (api.logDecision), the decision log carrying the trace and span ids.
	tracing := cfg.Tracing == "on" || (cfg.Tracing == "auto" && telemetry.Exporting())
	otelShutdown, otelStatus, err := telemetry.Setup(ctx, telemetry.Config{Enabled: tracing, Identifiers: cfg.TracingIdentifiers, ServiceName: "pgauthzd", Version: version})
	if err != nil {
		return err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = otelShutdown(sctx)
	}()
	switch {
	case otelStatus.Exporting:
		slog.Info("opentelemetry", "tracing", cfg.Tracing, "exporting", true, "protocol", otelStatus.Protocol, "endpoint", otelStatus.Endpoint)
	case otelStatus.Enabled:
		slog.Info("opentelemetry", "tracing", cfg.Tracing, "exporting", false, "propagation", "w3c+b3")
	default:
		slog.Info("opentelemetry", "tracing", "off")
	}

	// raw/rawWrite serve the native /pgauthz/v1 surface and are ALWAYS a direct
	// pgx backend (never OPA), so the native path never re-enters the policy
	// layer. rawWrite is set only on a WRITER-capable (full) instance. backend
	// serves the AuthZEN /access/v1 surface: the OPA sidecar when OPA_URL is set
	// (policy enrichment — OPA calls BACK into the native callback listener),
	// otherwise the same direct pgx backend. Fronting OPA is orthogonal to the
	// profile; the profile only decides read-only vs read+write.
	var backend, raw, rawWrite authz.Backend
	var pgb *pgbackend.Backend // the direct backend, when there is a local DB (issuer bindings read it)

	if cfg.DatabaseURL == "" {
		// No local DB — valid only as a pure OPA-AuthZEN gateway: OPA fronts
		// /access/v1 and calls BACK into OTHER instances' native callbacks for
		// the graph. No native surface and no callback listener are served here
		// (raw/rawWrite stay nil). Fail closed otherwise.
		if !cfg.UsesOPA() {
			return fmt.Errorf("profile %q requires DATABASE_URL (or set OPA_URL for a DB-less OPA-AuthZEN gateway)", cfg.Profile)
		}
		backend = newOPABackend(ctx, cfg)
		slog.Info("DB-less OPA-AuthZEN gateway (native surface disabled)", "opa", cfg.OPAURL)
	} else {
		var cleanup func()
		var perr error
		pgb, cleanup, perr = newPGBackend(ctx, cfg)
		if perr != nil {
			return perr
		}
		defer cleanup()
		raw = pgb
		if cfg.Profile == config.ProfileDecisionOnly {
			// Fail-closed: a decision-only instance must sit on a read-only role.
			if perr := awaitEngine(ctx, "decision-only", pgb.AssertReadOnly); perr != nil {
				return perr
			}
			slog.Info("decision-only: verified read-only DB role")
		} else {
			// full: fail closed if the role can't actually write.
			if perr := awaitEngine(ctx, "full", pgb.AssertWritable); perr != nil {
				return perr
			}
			rawWrite = pgb
			slog.Info("full: verified writer DB role")
		}

		// AuthZEN /access/v1 backend: OPA policy sidecar when OPA_URL is set,
		// else the direct pgx backend. The native surface stays pgx either way.
		if cfg.UsesOPA() {
			backend = newOPABackend(ctx, cfg)
			slog.Info("AuthZEN /access/v1 fronted by OPA policy sidecar", "url", cfg.OPAURL)
		} else {
			backend = pgb
		}
		slog.Info("connected to PostgreSQL", "profile", cfg.Profile, "opa", cfg.UsesOPA())

		// Engine/tenant gauge sampler (ADR 0010 Slice 3) — only when metrics are
		// exposed, so we never add DB load no one scrapes.
		if cfg.MetricsListenAddr != "" && cfg.MetricsSampleIntervalSeconds > 0 {
			if ss, ok := raw.(authz.StoreStatser); ok {
				startStoreSampler(ctx, ss, time.Duration(cfg.MetricsSampleIntervalSeconds)*time.Second, cfg.MetricsMaxStores)
				slog.Info("metrics: store-stats sampler started", "interval_s", cfg.MetricsSampleIntervalSeconds)
			}
			if gr, ok := raw.(authz.GateReadinessReporter); ok {
				startGateSampler(ctx, gr, time.Duration(cfg.MetricsSampleIntervalSeconds)*time.Second)
			}
		}
	}

	// The trusted-issuer set, one swappable value shared by the JWT
	// middleware and every handler; with ISSUERS_SOURCE=env+db the reloader
	// merges the database's bindings over it and swaps a new revision in.
	issuerSet := api.NewIssuers(api.IssuerConfigsFrom(cfg.Issuers))
	if cfg.IssuersSource == "env+db" {
		if pgb == nil {
			return fmt.Errorf("ISSUERS_SOURCE=env+db needs the direct PostgreSQL backend (DATABASE_URL)")
		}
		startIssuerReloader(ctx, pgb, cfg.Issuers, issuerSet, time.Duration(cfg.IssuersPollInterval)*time.Second)
	}
	jwtMW := api.NewJWTMiddleware(api.JWTConfig{
		Issuers:            api.IssuerConfigsFrom(cfg.Issuers),
		Set:                issuerSet,
		RequiredScope:      cfg.RequiredScope,
		RolesClaims:        cfg.RolesClaims,
		DBRoleClaim:        cfg.DBRoleClaim,
		ClientDBRoles:      cfg.ClientDBRoles,
		SubjectIDClaim:     cfg.SubjectIDClaim,
		SubjectIDFallback:  cfg.SubjectIDFallback,
		SubjectTypeClaim:   cfg.SubjectTypeClaim,
		SubjectTypeDefault: cfg.SubjectTypeDefault,
		ActorClaim:         cfg.ActorClaim,
		ActorSubjectType:   cfg.ActorSubjectType,
	})

	// Build the listeners.
	//  - The main JWT-authed listener serves everything: the AuthZEN /access/v1
	//    surface (OPA-fronted when OPA_URL is set, else direct pgx) plus the
	//    native /pgauthz/v1 surface (always direct pgx; writes gated by the
	//    writer-role claim on a full instance).
	//  - ANY instance may additionally expose the OPA CALLBACK listener
	//    (service-auth): the native surface a co-located OPA sidecar calls back
	//    into. Its capability follows the instance's role — read-only instances
	//    serve read callbacks, a full instance serves read+write.
	// Decision log (ADR 0013): off unless DECISION_LOG is set; one logger is
	// shared by both listeners (lines carry the listener label).
	dlog, err := decisionlog.Open(decisionlog.Config{Sink: cfg.DecisionLog, Sample: cfg.DecisionLogSample,
		DSN: cfg.DecisionLogDSN, RetentionDays: cfg.DecisionLogRetentionDays, QueueSize: cfg.DecisionLogQueue})
	if err != nil {
		return err
	}
	defer dlog.Close() //nolint:errcheck // best-effort flush on exit
	if dlog.Enabled() {
		slog.Info("decision log", "sink", cfg.DecisionLog, "sample", cfg.DecisionLogSample, "detail", cfg.DecisionLogDetail)
		if ps := dlog.Postgres; ps != nil {
			slog.Info("decision log sink", "table", decisionlog.Schema+"."+decisionlog.Table, "retention_days", cfg.DecisionLogRetentionDays, "queue", cfg.DecisionLogQueue)
			ps.OnFlush = func(result string, lines int) {
				metrics.DecisionLogBatches.WithLabelValues(result).Inc()
				if result == "ok" {
					metrics.DecisionLogInserted.Add(float64(lines))
				}
			}
			ps.OnDrop = func(lines int) { metrics.DecisionLogDropped.Add(float64(lines)) }
			ps.OnExpired = func(lines int) { metrics.DecisionLogExpired.Add(float64(lines)) }
		}
	}
	dlogOpt := api.WithDecisionLog(dlog)
	verOpt := api.WithVersion(version)
	issOpt := api.WithIssuers(issuerSet)
	if dlog.Enabled() {
		// OPA-fronted decisions carry the policy/bundle revisions: ask OPA for
		// provenance on every query only when there is a log to put it in.
		if pp, ok := backend.(interface{ EnableProvenance() }); ok {
			pp.EnableProvenance()
		}
	}

	var servers []*http.Server
	// The admin API (ADMIN_API_ENABLED): a full instance; management runs on
	// a backend holding authz_admin — its own pool with ADMIN_DATABASE_URL
	// (the main pool keeps the writer tier), else the main pool, which must
	// then hold the tier itself. Asserted now, so a misconfigured instance
	// refuses to start rather than 403 every management call.
	var admOpts []api.Option
	if cfg.AdminAPIEnabled {
		if rawWrite == nil || pgb == nil {
			return fmt.Errorf("ADMIN_API_ENABLED=true needs a full instance with the direct PostgreSQL backend")
		}
		adminBackend := pgb
		if cfg.AdminDatabaseURL != "" {
			apool, err := newPool(ctx, cfg.AdminDatabaseURL, 4)
			if err != nil {
				return fmt.Errorf("ADMIN_DATABASE_URL: %w", err)
			}
			defer apool.Close()
			adminBackend = pgbackend.New(apool, nil, time.Duration(cfg.DBRoleCacheTTLSeconds)*time.Second, "", "admin")
			admOpts = append(admOpts, api.WithAdminBackend(adminBackend))
		}
		if err := adminBackend.AssertAdmin(ctx); err != nil {
			return fmt.Errorf("ADMIN_API_ENABLED=true: %w", err)
		}
	}
	servers = append(servers, newServer(cfg, cfg.ListenAddr, api.NewRouter(backend, raw, rawWrite, cfg, jwtMW, append([]api.Option{dlogOpt, verOpt, issOpt}, admOpts...)...)))

	// On its own listener when ADMIN_LISTEN_ADDR is set (newPublicMux mounts
	// the routes on the public listener otherwise).
	if cfg.AdminAPIEnabled {
		if cfg.AdminListenAddr != "" {
			hAdm := api.NewHandler(nil, raw, rawWrite, cfg, append([]api.Option{dlogOpt, verOpt, issOpt}, admOpts...)...)
			admSrv := newServer(cfg, cfg.AdminListenAddr, api.NewAdminRouter(hAdm, jwtMW))
			tlsCfg, terr := mtlsConfig(cfg.AdminTLSCert, cfg.AdminTLSKey, cfg.AdminClientCA, "admin")
			if terr != nil {
				return terr
			}
			if tlsCfg != nil {
				admSrv.TLSConfig = tlsCfg
			}
			servers = append(servers, admSrv)
			slog.Info("admin API listener", "addr", cfg.AdminListenAddr, "gate", adminGateLabel(cfg), "mtls", tlsCfg != nil, "own_pool", cfg.AdminDatabaseURL != "")
		} else {
			slog.Info("admin API on the public listener", "prefix", "/pgauthz/v1/admin/", "gate", adminGateLabel(cfg))
		}
	}

	// The management listener (ADR 0010): Prometheus /metrics and the health
	// probes on a SEPARATE, non-public port. With PUBLIC_HEALTH_ENABLED=false
	// it is the only place (besides the admin listener) the probes answer.
	if cfg.MetricsListenAddr != "" {
		hMgmt := api.NewHandler(backend, raw, rawWrite, cfg, dlogOpt, verOpt, issOpt)
		servers = append(servers, newServer(cfg, cfg.MetricsListenAddr, api.NewManagementRouter(hMgmt, metrics.Handler())))
		slog.Info("management listener", "addr", cfg.MetricsListenAddr, "probes_on_public", !cfg.PublicHealthDisabled)
	}

	// OPA callback listener (service-auth), available whenever a direct backend
	// is present and INTERNAL_LISTEN_ADDR is set. Serves native reads, plus
	// writes when this instance is writer-capable (rawWrite != nil).
	if raw != nil && cfg.InternalListenAddr != "" {
		// Fail closed: the callback bypasses the policy layer, so it must never
		// run without the shared service credential.
		if cfg.InternalServiceToken == "" {
			return fmt.Errorf("INTERNAL_LISTEN_ADDR is set but INTERNAL_SERVICE_TOKEN is empty; refusing to expose the native callback surface without a service credential")
		}
		tlsCfg, terr := internalTLSConfig(cfg)
		if terr != nil {
			return terr
		}
		hCb := api.NewHandler(nil, raw, rawWrite, cfg, dlogOpt, verOpt, issOpt)
		cbSrv := newServer(cfg, cfg.InternalListenAddr, api.NewCallbackRouter(hCb, cfg.InternalServiceToken))
		if tlsCfg != nil {
			cbSrv.TLSConfig = tlsCfg
		}
		servers = append(servers, cbSrv)
		slog.Info("OPA callback listener", "addr", cfg.InternalListenAddr, "writable", rawWrite != nil, "mtls", tlsCfg != nil)
	}

	// Graceful shutdown of every listener on signal.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("shutting down...")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		for _, s := range servers {
			s.Shutdown(shutCtx) //nolint:errcheck // best-effort on shutdown
		}
	}()

	slog.Info(name+" listening", "addr", cfg.ListenAddr, "profile", cfg.Profile,
		"issuers", len(cfg.Issuers), "issuers_source", cfg.IssuersSource, "writable", cfg.Writable())

	// Run all listeners; the first hard error (not the clean shutdown) wins.
	errCh := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *http.Server) {
			// Certs come from TLSConfig.Certificates, so the file args are empty.
			var err error
			if s.TLSConfig != nil {
				err = s.ListenAndServeTLS("", "")
			} else {
				err = s.ListenAndServe()
			}
			if err != http.ErrServerClosed {
				errCh <- err
				return
			}
			errCh <- nil
		}(s)
	}
	var firstErr error
	for range servers {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// internalTLSConfig builds the mTLS config for the internal listener, or nil
// for plain HTTP. When any of the three TLS settings is present all three are
// required (server cert+key + client CA), and the listener then REQUIRES and
// verifies a client certificate chained to the CA — so only the OPA sidecar
// holding a matching cert can connect. This layers under the service token.
func internalTLSConfig(cfg *config.Config) (*tls.Config, error) {
	return mtlsConfig(cfg.InternalTLSCert, cfg.InternalTLSKey, cfg.InternalClientCA, "internal")
}

// mtlsConfig builds a require-and-verify client-certificate TLS config for
// a listener (the internal callback, the admin API), or nil when none of
// the three settings is set.
func mtlsConfig(certFile, keyFile, caFile, listener string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" && caFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, fmt.Errorf("%s-listener mTLS requires %s_TLS_CERT, %s_TLS_KEY, and %s_CLIENT_CA together", listener, strings.ToUpper(listener), strings.ToUpper(listener), strings.ToUpper(listener))
	}
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading %s TLS server cert/key: %w", listener, err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s client CA: %w", listener, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s client CA %q contains no valid certificates", listener, caFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// newServer builds a listener with the shared hardening limits (review #9):
// header/idle timeouts against slow-header (slowloris) and idle-connection
// exhaustion. Deliberately NO WriteTimeout — long-running search/explain/watch
// responses must not be killed mid-write.
func newServer(cfg *config.Config, addr string, h http.Handler) *http.Server {
	traced := h
	if telemetry.Enabled() {
		traced = tracedHandler(h)
	}
	return &http.Server{
		Addr:              addr,
		Handler:           traced,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
	}
}

// tracedHandler: one server span per request, named by method and path,
// the incoming trace context extracted (so the RequestID middleware and the
// decision span see it); health probes stay out of the traces.
func tracedHandler(h http.Handler) http.Handler {
	// Named after the matched route pattern (api.SpanName), never the raw
	// path: bounded names, no identifiers; an unmatched route is the method.
	return otelhttp.NewHandler(h, "pgauthzd",
		otelhttp.WithSpanNameFormatter(api.SpanName),
		otelhttp.WithFilter(func(r *http.Request) bool {
			switch r.URL.Path {
			case "/livez", "/readyz", "/healthz":
				return false
			}
			return true
		}))
}

// newOPABackend builds the OPA-fronted AuthZEN backend and logs a startup
// health probe (non-fatal — OPA may still be coming up; bounded by its own
// deadline so a black-holed OPA can't block startup, review #9).
func newOPABackend(ctx context.Context, cfg *config.Config) authz.Backend {
	opab := opabackend.New(cfg.OPAURL, cfg.OPAPackage, cfg.ForwardTokenToOPA,
		cfg.OPARequestTimeout, cfg.OPADeepReadinessRequired, cfg.DeploymentEnvironment, cfg.OPAEvalMetrics, cfg.OPAMaxResponseBytes)
	pctx, cancel := context.WithTimeout(ctx, cfg.OPARequestTimeout)
	defer cancel()
	if herr := opab.Healthz(pctx); herr != nil {
		slog.Warn("OPA health check failed on startup (will retry)", "error", herr)
	} else {
		slog.Info("connected to OPA", "url", cfg.OPAURL)
	}
	return opab
}

// newPGBackend builds a direct pgx backend from cfg.DatabaseURL, plus (for a
// decision-only reader, off in OPA mode) an optional primary-fallback pool for
// transparent freshness fallback (ADR 0009). Returns a cleanup that closes every
// pool the caller must defer.
func newPGBackend(ctx context.Context, cfg *config.Config) (*pgbackend.Backend, func(), error) {
	pool, err := newPool(ctx, cfg.DatabaseURL, cfg.DBPoolMax)
	if err != nil {
		return nil, nil, fmt.Errorf("DATABASE_URL: %w", err)
	}
	// Pool stats for /metrics (ADR 0010): the local pool is the replica on a
	// decision-only reader, the primary on a full instance.
	localPoolName := "replica"
	if cfg.Profile == config.ProfileFull {
		localPoolName = "primary"
	}
	metrics.RegisterPool(localPoolName, func() metrics.PoolStat { return pool.Stat() })
	var primaryPool *pgxpool.Pool
	// Transparent freshness fallback: a decision-only reader may hold a small
	// reader-role pool to the primary. Disabled in OPA mode — the AuthZEN read
	// runs through OPA, which would not honor the primary-route context flag, so
	// enabling it there could serve a stale answer. There the guard keeps the 409.
	if cfg.Profile == config.ProfileDecisionOnly && !cfg.UsesOPA() && cfg.FreshnessPrimaryURL != "" {
		primaryPool, err = newPool(ctx, cfg.FreshnessPrimaryURL, cfg.FreshnessPrimaryPoolMax)
		if err != nil {
			pool.Close()
			return nil, nil, fmt.Errorf("FRESHNESS_PRIMARY_URL: %w", err)
		}
		metrics.RegisterPool("fallback", func() metrics.PoolStat { return primaryPool.Stat() })
		slog.Info("freshness: transparent primary fallback enabled", "pool_max", cfg.FreshnessPrimaryPoolMax)
	}
	cleanup := func() {
		pool.Close()
		if primaryPool != nil {
			primaryPool.Close()
		}
	}
	return pgbackend.New(pool, primaryPool, time.Duration(cfg.DBRoleCacheTTLSeconds)*time.Second, cfg.DefaultDBRole, localPoolName), cleanup, nil
}

// engineRetryInterval paces awaitEngine's re-checks while the engine is absent.
var engineRetryInterval = 2 * time.Second

// awaitEngine runs a profile assertion (AssertReadOnly / AssertWritable) and,
// while PostgreSQL reports that the engine is not installed yet (no authz
// roles/tables — a fresh database before init.sh or the migration job ran),
// keeps re-checking instead of exiting. The daemon stays up (compose's
// `--wait` returns, Kubernetes sees a running pod) and completes startup the
// moment the engine lands; any OTHER assertion failure — a writable role on a
// decision-only instance, a non-writer on a full one — is still fatal, fail
// closed, exactly as before. The wait is unbounded by design: the only way out
// is the engine appearing (or the process being stopped).
func awaitEngine(ctx context.Context, profile string, assert func(context.Context) error) error {
	logged := false
	for {
		err := assert(ctx)
		if err == nil || !pgbackend.IsEngineNotInstalled(err) {
			return err
		}
		if !logged {
			slog.Warn("engine not installed yet — waiting for init.sh / the migrations to land",
				"profile", profile, "error", err, "retry", engineRetryInterval.String())
			logged = true
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for the engine to be installed: %w", ctx.Err())
		case <-time.After(engineRetryInterval):
		}
	}
}

// newPool builds and pings a pgx pool bounded to maxConns.
func newPool(ctx context.Context, dsn string, maxConns int) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing DSN: %w", err)
	}
	poolCfg.MaxConns = int32(maxConns)
	// OpenTelemetry (when tracing is on): a span per engine query
	// (authz.<function>, statement text, never the arguments) under the
	// request's span.
	if telemetry.Enabled() {
		poolCfg.ConnConfig.Tracer = telemetry.NewPgxTracer()
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connecting: %w", err)
	}
	return pool, nil
}

// startStoreSampler periodically samples per-store engine stats and publishes
// them as gauges (ADR 0010 Slice 3). Runs until ctx is cancelled.
// startGateSampler publishes the temporal-gate readiness gauges (review #11)
// on the store-stats interval: history coverage per gated store, recording
// activity and delay, recorder identities.
func startGateSampler(ctx context.Context, gr authz.GateReadinessReporter, interval time.Duration) {
	sample := func() {
		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		rows, err := gr.GateReadiness(sctx)
		if err != nil {
			slog.Warn("metrics: gate-readiness sample failed", "error", err)
			return
		}
		now := time.Now()
		samples := make([]metrics.GateReadinessSample, 0, len(rows))
		for _, r := range rows {
			s := metrics.GateReadinessSample{Store: r.Store, Gates: float64(r.Gates), Covers: r.HistoryCoversGates,
				Recorders24h: float64(r.Recorders24h), RecordingDelayMax: r.MaxRecordingDelay1h}
			if r.HistoryDeficitSecs != nil {
				s.DeficitSeconds = *r.HistoryDeficitSecs
			}
			if r.LastRecordedAt != nil {
				age := now.Sub(*r.LastRecordedAt).Seconds()
				s.LastRecordedAge = &age
			}
			samples = append(samples, s)
		}
		metrics.SetGateReadiness(samples)
	}
	go func() {
		sample()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sample()
			}
		}
	}()
}

func startStoreSampler(ctx context.Context, ss authz.StoreStatser, interval time.Duration, limit int) {
	sample := func() {
		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		stats, total, err := ss.StoreStats(sctx, limit)
		if err != nil {
			slog.Warn("metrics: store-stats sample failed", "error", err)
			return
		}
		byStore := make(map[string]float64, len(stats))
		for _, s := range stats {
			byStore[s.Store] = float64(s.Tuples)
		}
		metrics.SetStoreStats(byStore, float64(total))
	}
	go func() {
		sample() // publish once immediately, then on each tick
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sample()
			}
		}
	}()
}

// buildCommit returns the short VCS revision embedded by the Go toolchain, or ""
// if unavailable (e.g. built without VCS info).
func buildCommit() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			if len(s.Value) > 12 {
				return s.Value[:12]
			}
			return s.Value
		}
	}
	return ""
}

func setupLogging(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}

// adminGateLabel names the admin gate for the logs.
func adminGateLabel(cfg *config.Config) string {
	n := 0
	for _, iss := range cfg.Issuers {
		if iss.Admin != nil && !iss.Admin.Empty() {
			n++
		}
	}
	var parts []string
	if n > 0 {
		parts = append(parts, fmt.Sprintf("%d issuer admin binding(s)", n))
	}
	if cfg.AdminRole != "" {
		parts = append(parts, "ADMIN_ROLE")
	}
	if len(cfg.AdminClientCerts) > 0 {
		parts = append(parts, fmt.Sprintf("%d client certificate mapping(s)", len(cfg.AdminClientCerts)))
	}
	return strings.Join(parts, " + ")
}
