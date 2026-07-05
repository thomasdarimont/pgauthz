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

	var backend authz.Backend
	switch cfg.Profile {
	case config.ProfileDecisionOnly, config.ProfileFull:
		if cfg.DatabaseURL == "" {
			return fmt.Errorf("profile %q requires DATABASE_URL", cfg.Profile)
		}
		poolCfg, perr := pgxpool.ParseConfig(cfg.DatabaseURL)
		if perr != nil {
			return fmt.Errorf("parsing DATABASE_URL: %w", perr)
		}
		poolCfg.MaxConns = int32(cfg.DBPoolMax)
		pool, perr := pgxpool.NewWithConfig(ctx, poolCfg)
		if perr != nil {
			return fmt.Errorf("creating connection pool: %w", perr)
		}
		defer pool.Close()
		if perr := pool.Ping(ctx); perr != nil {
			return fmt.Errorf("connecting to database: %w", perr)
		}
		pgb := pgbackend.New(pool, time.Duration(cfg.DBRoleCacheTTLSeconds)*time.Second)
		// Fail-closed capability guarantee: a decision-only instance must sit
		// on a role that cannot write.
		if cfg.Profile == config.ProfileDecisionOnly {
			if perr := pgb.AssertReadOnly(ctx); perr != nil {
				return perr
			}
			slog.Info("decision-only: verified read-only DB role")
		}
		backend = pgb
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

	handler := api.NewRouter(backend, cfg, jwtMW)
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: handler}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("shutting down...")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		srv.Shutdown(shutCtx)
	}()

	slog.Info(name+" listening", "addr", cfg.ListenAddr, "profile", cfg.Profile,
		"issuers", len(issuers), "writable", cfg.Writable())
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
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
