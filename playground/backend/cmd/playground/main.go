// Command playground-bff is a backend-for-frontend for the pgauthz Lit SPA.
//
// Browser does OIDC authorization-code + PKCE against Keycloak; this BFF holds
// the tokens server-side (sessions in the pgauthz_playground DB) and exposes only
// an http-only secure cookie to the SPA. The SPA's /api/q calls are forwarded to
// OPA with the session's access token, so every query runs as the logged-in user.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"thomasdarimont.de/authz/playground-bff/internal/config"
	"thomasdarimont.de/authz/playground-bff/internal/oidc"
	"thomasdarimont.de/authz/playground-bff/internal/server"
)

func main() {
	cfg := config.Load()
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, cfg.PgDSN)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer pool.Close()
	if err := server.InitSchema(ctx, pool); err != nil {
		log.Fatalf("db schema: %v", err)
	}

	var engineDB *pgxpool.Pool
	if cfg.EngineDSN != "" {
		if ep, err := pgxpool.New(ctx, cfg.EngineDSN); err != nil {
			log.Printf("engine metadata DB unavailable (autocomplete disabled): %v", err)
		} else {
			engineDB = ep
			defer ep.Close()
		}
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	// Optionally trust an extra CA (e.g. the mkcert dev root) so the BFF can reach
	// the issuer over its real https URL. Appended to the system pool, so public
	// CAs still work. Unset in production, where the issuer has a real certificate.
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
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool}}
		log.Printf("trusting extra CA from %s", cfg.TLSCAFile)
	}

	// Resolve OIDC endpoints from the issuer's discovery document (single ISSUER
	// setting, instead of separate authorize/token/logout URLs).
	disco, err := oidc.Discover(ctx, httpClient, cfg.Issuer)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("OIDC discovered from %s: authorize=%s token=%s logout=%s",
		cfg.Issuer, disco.AuthURL, disco.TokenURL, disco.LogoutURL)

	oidcClient := &oidc.Client{
		HTTP: httpClient, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, TokenURL: disco.TokenURL,
	}
	srv := server.New(cfg, pool, engineDB, httpClient, oidcClient, disco)

	log.Printf("playground BFF listening on %s (opa=%s, app=%s)", cfg.Addr, cfg.OpaURL, cfg.BaseURL)
	log.Fatal(http.ListenAndServe(cfg.Addr, srv.Routes()))
}
