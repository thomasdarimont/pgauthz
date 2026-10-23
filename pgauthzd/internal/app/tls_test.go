package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"strings"
	"thomasdarimont.de/authz/pgauthzd/internal/api"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/pkg/issuers"
)

// mkCert issues a cert from a template, signed by (parent, parentKey); a nil
// parent self-signs (a CA). Returns the leaf cert + its key.
func mkCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, signerKey := parent, parentKey
	if signer == nil {
		signer, signerKey = tmpl, key // self-sign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, certPEM
}

func writePEM(t *testing.T, path string, block *pem.Block) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) *pem.Block {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
}

// TestInternalTLSConfigModes covers the three configuration shapes.
func TestInternalTLSConfigModes(t *testing.T) {
	// none set → plain HTTP (nil, no error)
	c, err := internalTLSConfig(&config.Config{})
	if err != nil || c != nil {
		t.Fatalf("empty: want (nil,nil), got (%v,%v)", c, err)
	}
	// partial → error
	if _, err := internalTLSConfig(&config.Config{InternalTLSCert: "x"}); err == nil {
		t.Fatal("partial config should error")
	}
}

// TestInternalMTLSEnforced proves the internal listener REQUIRES a client cert
// chained to the configured CA: a client without one is rejected at the TLS
// handshake, a client presenting a CA-signed cert is accepted.
func TestInternalMTLSEnforced(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	ca, caKey, caPEM := mkCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}, nil, nil)

	// Server leaf (for the internal listener).
	srvCert, srvKey, srvPEM := mkCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "pgauthzd-internal"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, caKey)

	// Client leaf (OPA's identity).
	cliCert, cliKey, _ := mkCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "opa-sidecar"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca, caKey)

	certFile := filepath.Join(dir, "srv.crt")
	keyFile := filepath.Join(dir, "srv.key")
	caFile := filepath.Join(dir, "ca.crt")
	writePEM(t, certFile, &pem.Block{Type: "CERTIFICATE", Bytes: srvCert.Raw})
	writePEM(t, keyFile, keyPEM(t, srvKey))
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = srvPEM

	tlsCfg, err := internalTLSConfig(&config.Config{
		InternalTLSCert: certFile, InternalTLSKey: keyFile, InternalClientCA: caFile,
	})
	if err != nil {
		t.Fatalf("internalTLSConfig: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsCfg.ClientAuth)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	// The client must trust the server cert (CA pool).
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	// No client cert → handshake rejected.
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	if _, err := noCert.Get(srv.URL); err == nil {
		t.Fatal("expected TLS failure without a client cert, got success")
	}

	// Valid CA-signed client cert → accepted.
	withCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{{Certificate: [][]byte{cliCert.Raw}, PrivateKey: cliKey, Leaf: cliCert}},
	}}}
	resp, err := withCert.Get(srv.URL)
	if err != nil {
		t.Fatalf("valid client cert should be accepted: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
}

// TestAdminMTLSCredential: the admin listener under mTLS accepts a mapped
// client certificate as the credential — no token — and refuses an
// unmapped one with 403 and a client without a certificate at the
// handshake; the health probes answer the certificate holder too.
func TestAdminMTLSCredential(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	ca, caKey, caPEM := mkCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "admin-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}, nil, nil)
	srvCert, srvKey, _ := mkCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "pgauthzd-admin"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, caKey)
	leaf := func(cn string) tls.Certificate {
		c, k, _ := mkCert(t, &x509.Certificate{
			SerialNumber: big.NewInt(int64(len(cn) + 10)), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, ca, caKey)
		return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: k, Leaf: c}
	}
	certFile, keyFile, caFile := filepath.Join(dir, "srv.crt"), filepath.Join(dir, "srv.key"), filepath.Join(dir, "ca.crt")
	writePEM(t, certFile, &pem.Block{Type: "CERTIFICATE", Bytes: srvCert.Raw})
	writePEM(t, keyFile, keyPEM(t, srvKey))
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Profile: config.ProfileFull, AdminAPIEnabled: true, AdminListenAddr: ":0",
		AdminTLSCert: certFile, AdminTLSKey: keyFile, AdminClientCA: caFile,
		AdminClientCerts: []config.AdminClientCert{{CN: "terraform", Scope: "platform"}},
		HTTPMaxBodyBytes: 1 << 20,
		Issuers:          []issuers.Issuer{{Issuer: "https://idp", Audience: "api", JWKSFile: "/dev/null", Stores: []string{"demo"}}},
	}
	set := api.NewIssuers(api.IssuerConfigsFrom(cfg.Issuers))
	h := api.NewHandler(nil, nil, nil, cfg, api.WithIssuers(set))
	tlsCfg, err := mtlsConfig(cfg.AdminTLSCert, cfg.AdminTLSKey, cfg.AdminClientCA, "admin")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(api.NewAdminRouter(h, api.NewJWTMiddleware(api.JWTConfig{Set: set})))
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certs}}}
	}
	if _, err := client().Get(srv.URL + "/pgauthz/v1/admin/issuers"); err == nil {
		t.Fatal("a client without a certificate must fail the handshake")
	}
	resp, err := client(leaf("terraform")).Get(srv.URL + "/pgauthz/v1/admin/issuers")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "https://idp") {
		t.Fatalf("mapped certificate, no token: %d %s", resp.StatusCode, body)
	}
	resp, err = client(leaf("stranger")).Get(srv.URL + "/pgauthz/v1/admin/issuers")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 || !strings.Contains(string(body), "not mapped") {
		t.Fatalf("unmapped certificate: %d %s", resp.StatusCode, body)
	}
	resp, err = client(leaf("stranger")).Get(srv.URL + "/livez")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("probe under mTLS: %v %v", err, resp)
	}
	resp.Body.Close()
}
