package conformance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"
)

// Proxy is the https front for pgauthzd. The suite insists on https for the PDP identifier and
// every endpoint (CheckPDPServerConfiguration) but does not verify the certificate, and
// pgauthzd's public listener speaks plain http, so the tests terminate TLS here with a
// certificate made up at start and forward to the daemon. X-Forwarded-Proto/-Host tell the
// daemon the public scheme and host, for a discovery document that names the public URL.
type Proxy struct {
	server   *http.Server
	listener net.Listener
	port     int
}

// StartProxy listens for https on port and forwards every request to target (pgauthzd's
// base URL, e.g. http://localhost:8090).
func StartProxy(target *url.URL, port int) (*Proxy, error) {
	certificate, err := selfSignedCertificate()
	if err != nil {
		return nil, fmt.Errorf("could not create the certificate of the https front: %w", err)
	}
	forward := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			// X-Forwarded-For/-Host/-Proto from the inbound (https) request
			r.SetXForwarded()
		},
	}
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("could not listen on port %d for the https front: %w", port, err)
	}
	server := &http.Server{
		Handler:           forward,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	return &Proxy{server: server, listener: listener, port: port}, nil
}

// URL is the base URL under which host reaches the front: https://<host>:<port>.
func (p *Proxy) URL(host string) string {
	return "https://" + net.JoinHostPort(host, strconv.Itoa(p.port))
}

// Close stops the front.
func (p *Proxy) Close() {
	_ = p.server.Close()
}

// selfSignedCertificate is a fresh ECDSA certificate for the names the suite and a developer
// use for the Docker host. Nobody verifies it; it only has to be a certificate.
func selfSignedCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pgauthz conformance PDP front"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "host.testcontainers.internal", "host.docker.internal"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
