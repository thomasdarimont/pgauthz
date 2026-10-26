// Command console-bff is the backend-for-frontend of the pgauthz management
// console (console/README.md).
//
// The browser logs in through OIDC (authorization code + PKCE) at the IdP; the
// BFF keeps the tokens server-side (sessions in its own database) and gives
// the SPA an http-only cookie. Every screen and action is authorized twice:
// first against the console's own pgauthz store ("may alice edit the model of
// store:demo?", with her directory memberships as contextual tuples), then
// performed in the managed store as her (audit performed_by = alice), and
// recorded in the console store's action log.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"thomasdarimont.de/authz/console-bff/internal/config"
	"thomasdarimont.de/authz/console-bff/internal/oidc"
	"thomasdarimont.de/authz/console-bff/internal/server"
)

// version is stamped at build time (go build -ldflags "-X main.version=1.2.3";
// the Dockerfile's VERSION build arg), "dev" otherwise. The VCS revision comes
// from the build info when the module was built inside a git checkout.
var version = "dev"

// revision is the git revision stamped by the Dockerfile (REVISION build arg)
// when the build has no VCS metadata of its own.
var revision = ""

func buildVersion() server.Version {
	v := server.Version{Version: version, Revision: revision, Go: runtime.Version()}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if len(s.Value) >= 12 {
					v.Revision = s.Value[:12]
				}
			case "vcs.modified":
				if s.Value == "true" {
					v.Revision += "-dirty"
				}
			case "vcs.time":
				v.BuiltAt = s.Value
			}
		}
	}
	return v
}

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("%v", err)
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, cfg.PgDSN)
	if err != nil {
		log.Fatalf("session db connect: %v", err)
	}
	defer pool.Close()
	if err := server.InitSchema(ctx, pool); err != nil {
		log.Fatalf("session db schema: %v", err)
	}

	engine, err := pgxpool.New(ctx, cfg.EngineDSN)
	if err != nil {
		log.Fatalf("engine connect: %v", err)
	}
	defer engine.Close()
	if err := server.AwaitEngine(ctx, engine, cfg.ConsoleStore); err != nil {
		log.Fatalf("%v", err)
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	var adminClient *http.Client
	if cfg.PgauthzdAdminCert != "" || cfg.PgauthzdAdminKey != "" {
		if cfg.PgauthzdAdminCert == "" || cfg.PgauthzdAdminKey == "" {
			log.Fatalf("PGAUTHZD_ADMIN_CERT and PGAUTHZD_ADMIN_KEY go together")
		}
		pair, err := tls.LoadX509KeyPair(cfg.PgauthzdAdminCert, cfg.PgauthzdAdminKey)
		if err != nil {
			log.Fatalf("PGAUTHZD_ADMIN_CERT/_KEY: %v", err)
		}
		roots, _ := x509.SystemCertPool()
		if roots == nil {
			roots = x509.NewCertPool()
		}
		for _, f := range []string{cfg.TLSCAFile, cfg.PgauthzdAdminCA} {
			if f == "" {
				continue
			}
			pem, err := os.ReadFile(f)
			if err != nil || !roots.AppendCertsFromPEM(pem) {
				log.Fatalf("CA file %s: %v", f, err)
			}
		}
		adminClient = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: roots, MinVersion: tls.VersionTLS12}}}
		log.Printf("admin API client certificate from %s", cfg.PgauthzdAdminCert)
	}
	if cfg.TLSCAFile != "" {
		certPool, _ := x509.SystemCertPool()
		if certPool == nil {
			certPool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			log.Fatalf("TLS_CA_FILE %s: %v", cfg.TLSCAFile, err)
		}
		if !certPool.AppendCertsFromPEM(pem) {
			log.Fatalf("TLS_CA_FILE %s: no certificates parsed", cfg.TLSCAFile)
		}
		// Proxy: a custom transport does not inherit the default's proxy
		// lookup; an egress proxy (CONSOLE_OUTBOUND_HOST_POLICY=proxy) must still apply
		httpClient.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: certPool}}
		log.Printf("trusting extra CA from %s", cfg.TLSCAFile)
	}

	// Sign-in: an OpenID Provider (ISSUER), the local admin (no IdP), or both.
	if cfg.LocalAdminEnabled() {
		if cfg.Production() && !cfg.LocalAdminAllowInProduction {
			log.Fatalf("CONSOLE_LOCAL_ADMIN_USER is set under DEPLOYMENT_ENVIRONMENT=%s: the local sign-in is for tests and first looks, not production. Unset it, or set CONSOLE_LOCAL_ADMIN_ALLOW_IN_PRODUCTION=true deliberately.", cfg.DeploymentEnvironment)
		}
		log.Printf("WARNING: local admin sign-in enabled for %s:%s (teams %v) — a shared password, no IdP; unset CONSOLE_LOCAL_ADMIN_USER/_PASSWORD to deactivate", cfg.SubjectType, cfg.LocalAdminUser, cfg.LocalAdminTeams)
	}
	var disco oidc.Metadata
	var oidcClient *oidc.Client
	if cfg.Issuer != "" {
		var err error
		disco, err = oidc.Discover(ctx, httpClient, cfg.Issuer)
		if err != nil {
			log.Fatalf("%v", err)
		}
		log.Printf("OIDC discovered from %s: authorize=%s token=%s logout=%s", cfg.Issuer, disco.AuthURL, disco.TokenURL, disco.LogoutURL)
		oidcClient = &oidc.Client{HTTP: httpClient, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, TokenURL: disco.TokenURL}
	} else if !cfg.LocalAdminEnabled() {
		log.Fatalf("no sign-in configured: set ISSUER (an OpenID Provider) or CONSOLE_LOCAL_ADMIN_USER + CONSOLE_LOCAL_ADMIN_PASSWORD")
	} else {
		log.Printf("no ISSUER: the local admin sign-in is the only way in")
	}
	srv := server.New(cfg, pool, engine, httpClient, oidcClient, disco).WithAdminHTTPClient(adminClient)
	srv.SetVersion(buildVersion())

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("console BFF %s (%s) listening on %s (console store=%s, app=%s%s)", version, buildVersion().Revision, cfg.Addr, cfg.ConsoleStore, cfg.BaseURL, cfg.BasePath)
	log.Fatal(httpSrv.ListenAndServe())
}
