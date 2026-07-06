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
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"thomasdarimont.de/authz/pgauthzd/internal/api"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
	"thomasdarimont.de/authz/pgauthzd/internal/opabackend"
	"thomasdarimont.de/authz/pgauthzd/internal/pgbackend"
)

// Run loads config, wires the profile's backend, and serves. `name` is used for
// log lines; `version` labels the build_info metric.
func Run(name, version string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	setupLogging(cfg.LogLevel)

	// build_info (ADR 0010): value 1, labels carry version/commit/profile/features.
	fallbackEnabled := cfg.FreshnessPrimaryURL != "" && cfg.Profile == config.ProfileDecisionOnly && !cfg.UsesOPA()
	metrics.SetBuildInfo(version, buildCommit(), runtime.Version(), string(cfg.Profile),
		cfg.UsesOPA(), cfg.FreshnessEnabled(), fallbackEnabled)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// raw/rawWrite serve the native /pgauthz/v1 surface and are ALWAYS a direct
	// pgx backend (never OPA), so the native path never re-enters the policy
	// layer. rawWrite is set only on a WRITER-capable (full) instance. backend
	// serves the AuthZEN /access/v1 surface: the OPA sidecar when OPA_URL is set
	// (policy enrichment — OPA calls BACK into the native callback listener),
	// otherwise the same direct pgx backend. Fronting OPA is orthogonal to the
	// profile; the profile only decides read-only vs read+write.
	var backend, raw, rawWrite authz.Backend

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
		pgb, cleanup, perr := newPGBackend(ctx, cfg)
		if perr != nil {
			return perr
		}
		defer cleanup()
		raw = pgb
		if cfg.Profile == config.ProfileDecisionOnly {
			// Fail-closed: a decision-only instance must sit on a read-only role.
			if perr := pgb.AssertReadOnly(ctx); perr != nil {
				return perr
			}
			slog.Info("decision-only: verified read-only DB role")
		} else {
			// full: fail closed if the role can't actually write.
			if perr := pgb.AssertWritable(ctx); perr != nil {
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
	}

	var issuers []api.IssuerConfig
	for _, i := range cfg.Issuers {
		issuers = append(issuers, api.IssuerConfig{
			Issuer: i.Issuer, Audience: i.Audience, JWKSURL: i.JWKSURL, JWKSFile: i.JWKSFile,
			DBRoles: i.DBRoles, ClientDBRoles: i.ClientDBRoles,
		})
	}
	jwtMW := api.NewJWTMiddleware(api.JWTConfig{
		Issuers:            issuers,
		RequiredScope:      cfg.RequiredScope,
		RolesClaims:        cfg.RolesClaims,
		DBRoleClaim:        cfg.DBRoleClaim,
		ClientDBRoles:      cfg.ClientDBRoles,
		SubjectIDClaim:     cfg.SubjectIDClaim,
		SubjectIDFallback:  cfg.SubjectIDFallback,
		SubjectTypeClaim:   cfg.SubjectTypeClaim,
		SubjectTypeDefault: cfg.SubjectTypeDefault,
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
	var servers []*http.Server
	servers = append(servers, &http.Server{Addr: cfg.ListenAddr, Handler: api.NewRouter(backend, raw, rawWrite, cfg, jwtMW)})

	// Prometheus metrics on a SEPARATE, non-public listener (ADR 0010).
	if cfg.MetricsListenAddr != "" {
		mmux := http.NewServeMux()
		mmux.Handle("GET /metrics", metrics.Handler())
		servers = append(servers, &http.Server{Addr: cfg.MetricsListenAddr, Handler: mmux})
		slog.Info("metrics listener", "addr", cfg.MetricsListenAddr)
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
		hCb := api.NewHandler(nil, raw, rawWrite, cfg)
		cbSrv := &http.Server{Addr: cfg.InternalListenAddr, Handler: api.NewCallbackRouter(hCb, cfg.InternalServiceToken)}
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
		"issuers", len(issuers), "writable", cfg.Writable())

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
	if cfg.InternalTLSCert == "" && cfg.InternalTLSKey == "" && cfg.InternalClientCA == "" {
		return nil, nil // plain HTTP — fine for same-pod/localhost or mesh-provided mTLS
	}
	if cfg.InternalTLSCert == "" || cfg.InternalTLSKey == "" || cfg.InternalClientCA == "" {
		return nil, fmt.Errorf("internal-listener mTLS requires INTERNAL_TLS_CERT, INTERNAL_TLS_KEY, and INTERNAL_CLIENT_CA together")
	}
	serverCert, err := tls.LoadX509KeyPair(cfg.InternalTLSCert, cfg.InternalTLSKey)
	if err != nil {
		return nil, fmt.Errorf("loading internal TLS server cert/key: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.InternalClientCA)
	if err != nil {
		return nil, fmt.Errorf("reading internal client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("internal client CA %q contains no valid certificates", cfg.InternalClientCA)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// newOPABackend builds the OPA-fronted AuthZEN backend and logs a startup
// health probe (non-fatal — OPA may still be coming up).
func newOPABackend(ctx context.Context, cfg *config.Config) authz.Backend {
	opab := opabackend.New(cfg.OPAURL, cfg.OPAPackage, cfg.ForwardTokenToOPA)
	if herr := opab.Healthz(ctx); herr != nil {
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
	return pgbackend.New(pool, primaryPool, time.Duration(cfg.DBRoleCacheTTLSeconds)*time.Second, cfg.DefaultDBRole), cleanup, nil
}

// newPool builds and pings a pgx pool bounded to maxConns.
func newPool(ctx context.Context, dsn string, maxConns int) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing DSN: %w", err)
	}
	poolCfg.MaxConns = int32(maxConns)
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
