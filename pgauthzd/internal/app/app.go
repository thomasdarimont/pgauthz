// Package app is the shared entrypoint for pgauthzd and its compat aliases
// (authzen-direct/-opa). The profile selects the backend + capability; the
// aliases pin a profile, everything else is identical.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"thomasdarimont.de/authz/pgauthzd/internal/api"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/internal/opabackend"
	"thomasdarimont.de/authz/pgauthzd/internal/pgbackend"
)

// Run loads config, wires the profile's backend, and serves. `force` pins a
// profile (compat aliases); empty means use PGAUTHORIZER_PROFILE. `name` is the
// binary name for logs.
func Run(name string, force config.Profile) error {

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if force != "" {
		cfg.Profile = force
	}
	setupLogging(cfg.LogLevel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// backend serves the AuthZEN surface; raw serves the native /pgauthz/v1
	// surface and is ALWAYS a direct pgx backend (never OPA). On direct profiles
	// they are the same pool; on compat-opa, backend=OPA and raw is a separate
	// read-only pgx backend that the OPA sidecar calls back into.
	var backend, raw authz.Backend
	switch cfg.Profile {
	case config.ProfileDecisionOnly, config.ProfileFull:
		if cfg.DatabaseURL == "" {
			return fmt.Errorf("profile %q requires DATABASE_URL", cfg.Profile)
		}
		pgb, pool, perr := newPGBackend(ctx, cfg)
		if perr != nil {
			return perr
		}
		defer pool.Close()
		// Fail-closed capability guarantee: a decision-only instance must sit
		// on a role that cannot write.
		if cfg.Profile == config.ProfileDecisionOnly {
			if perr := pgb.AssertReadOnly(ctx); perr != nil {
				return perr
			}
			slog.Info("decision-only: verified read-only DB role")
		}
		backend = pgb
		raw = pgb
		slog.Info("connected to PostgreSQL", "profile", cfg.Profile)

	case config.ProfileCompatOPA:
		if cfg.OPAURL == "" {
			return fmt.Errorf("profile %q requires OPA_URL", cfg.Profile)
		}
		opab := opabackend.New(cfg.OPAURL, cfg.OPAPackage, cfg.ForwardTokenToOPA)
		if herr := opab.Healthz(ctx); herr != nil {
			slog.Warn("OPA health check failed on startup (will retry)", "error", herr)
		} else {
			slog.Info("connected to OPA", "url", cfg.OPAURL)
		}
		backend = opab
		// Optional native callback surface: when a DATABASE_URL is configured,
		// stand up a read-only pgx backend for the policy-FREE /pgauthz/v1 raw
		// endpoints the OPA sidecar calls back into (served on the internal
		// listener). Without it, native routes stay 501 (today's behavior).
		if cfg.DatabaseURL != "" {
			pgb, pool, perr := newPGBackend(ctx, cfg)
			if perr != nil {
				return perr
			}
			defer pool.Close()
			// The callback surface is read-only, and must be a direct pgx
			// backend — asserting both keeps the raw path from ever re-entering
			// the OPA policy layer (no re-entrancy loop) or mutating data.
			if perr := pgb.AssertReadOnly(ctx); perr != nil {
				return fmt.Errorf("compat-opa native callback DB role must be read-only: %w", perr)
			}
			if _, ok := any(pgb).(authz.NativeReader); !ok {
				return fmt.Errorf("compat-opa native callback backend must be a direct pgx backend")
			}
			raw = pgb
			slog.Info("compat-opa: native callback surface enabled (read-only pgx)")
		}

	default:
		return fmt.Errorf("unknown profile %q", cfg.Profile)
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

	// Build the listeners. Direct profiles serve everything on one listener.
	// compat-opa serves the policy-wrapped AuthZEN surface externally, and —
	// when the native callback surface is enabled — the policy-FREE raw
	// endpoints on a SEPARATE internal listener (must not be publicly exposed).
	var servers []*http.Server
	if cfg.Profile == config.ProfileCompatOPA {
		h := api.NewHandler(backend, raw, cfg)
		servers = append(servers, &http.Server{Addr: cfg.ListenAddr, Handler: api.NewExternalRouter(h, jwtMW)})
		if raw != nil && cfg.InternalListenAddr != "" {
			servers = append(servers, &http.Server{Addr: cfg.InternalListenAddr, Handler: api.NewInternalRouter(h, jwtMW)})
			slog.Info("compat-opa internal (native raw) listener", "addr", cfg.InternalListenAddr)
		} else if raw != nil {
			slog.Warn("compat-opa native callback backend configured but INTERNAL_LISTEN_ADDR is empty; native raw surface will not be served")
		}
	} else {
		servers = append(servers, &http.Server{Addr: cfg.ListenAddr, Handler: api.NewRouter(backend, cfg, jwtMW)})
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
			if err := s.ListenAndServe(); err != http.ErrServerClosed {
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

// newPGBackend builds a direct pgx backend + its pool from cfg.DatabaseURL.
// Caller owns closing the returned pool.
func newPGBackend(ctx context.Context, cfg *config.Config) (*pgbackend.Backend, *pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing DATABASE_URL: %w", err)
	}
	poolCfg.MaxConns = int32(cfg.DBPoolMax)
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating connection pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("connecting to database: %w", err)
	}
	return pgbackend.New(pool, time.Duration(cfg.DBRoleCacheTTLSeconds)*time.Second), pool, nil
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
