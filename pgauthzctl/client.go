package main

// The two transports of pgauthzctl. The long-run one is pgauthzd's admin
// API (ADR 0016): --server with a bearer token of the admin identity
// provider (people) or a client certificate the admin listener's mTLS maps
// (machines: CI, Terraform runners) — the actor in the audit trail is then
// whoever authenticated, not a flag. The direct database connection (--dsn)
// remains for installation-time work, `model test`, break-glass and the
// verbs that have no admin endpoint yet; it is on its way out for routine
// operations.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// serverFlags are the admin-API connection flags, registered next to --dsn.
type serverFlags struct {
	server, token, cert, key, ca *string
}

func newServerFlags(fs *flag.FlagSet) serverFlags {
	return serverFlags{
		server: fs.String("server", os.Getenv("PGAUTHZ_SERVER"), "pgauthzd admin API base URL, e.g. https://pgauthz-admin.example:8082 (or PGAUTHZ_SERVER); the long-run transport"),
		token:  fs.String("token", os.Getenv("PGAUTHZ_TOKEN"), "bearer token of the admin identity provider (or PGAUTHZ_TOKEN)"),
		cert:   fs.String("cert", os.Getenv("PGAUTHZ_CLIENT_CERT"), "client certificate (PEM) for the admin listener's mTLS (or PGAUTHZ_CLIENT_CERT)"),
		key:    fs.String("key", os.Getenv("PGAUTHZ_CLIENT_KEY"), "the certificate's private key (PEM) (or PGAUTHZ_CLIENT_KEY)"),
		ca:     fs.String("ca", os.Getenv("PGAUTHZ_CA"), "CA bundle (PEM) that signs the admin listener's certificate (or PGAUTHZ_CA); default: the system roots"),
	}
}

func (f serverFlags) set() bool { return *f.server != "" }

// adminClient talks to pgauthzd's admin API.
type adminClient struct {
	base string
	hc   *http.Client
	tok  string
}

func newAdminClient(f serverFlags) (*adminClient, error) {
	base := strings.TrimRight(*f.server, "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return nil, fmt.Errorf("--server must be an http(s) URL, got %q", base)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if *f.ca != "" {
		pem, err := os.ReadFile(*f.ca)
		if err != nil {
			return nil, fmt.Errorf("reading --ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca %q contains no certificates", *f.ca)
		}
		tlsCfg.RootCAs = pool
	}
	if (*f.cert == "") != (*f.key == "") {
		return nil, fmt.Errorf("--cert and --key go together")
	}
	if *f.cert != "" {
		c, err := tls.LoadX509KeyPair(*f.cert, *f.key)
		if err != nil {
			return nil, fmt.Errorf("loading the client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{c}
	}
	if *f.token == "" && *f.cert == "" {
		return nil, fmt.Errorf("the admin API needs a credential: --token (or PGAUTHZ_TOKEN) or --cert/--key (or PGAUTHZ_CLIENT_CERT/_KEY) against an mTLS admin listener")
	}
	return &adminClient{base: base, tok: *f.token, hc: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}}, nil
}

// apiError is pgauthzd's {status, message}.
type apiError struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("pgauthzd answered %d: %s", e.Status, e.Message)
}

// do sends a request; out receives the JSON answer (nil to ignore it); a
// non-2xx answer is an *apiError.
func (c *adminClient) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.tok != "" {
		req.Header.Set("Authorization", "Bearer "+c.tok)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		e := &apiError{Status: resp.StatusCode}
		if json.Unmarshal(raw, e) != nil || e.Message == "" {
			e.Message = strings.TrimSpace(string(raw))
		}
		return e
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
