package conformance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	mobynet "github.com/moby/moby/api/types/network"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Suite is the OpenID conformance suite the tests run against, started with Testcontainers like
// docker-compose-prebuilt.yml of the suite's repository does: MongoDB, the suite and its nginx
// in front. The suite has to know its public URL before it starts, so nginx is bound to a fixed
// host port and the suite's URL is https://localhost:<port>; the PDP under test on the Docker
// host is reached from the containers as host.testcontainers.internal. See Settings for the
// images and ports. The same bootstrap as easyssf-go's conformance module.
type Suite struct {
	settings    Settings
	baseURL     *url.URL
	certificate *x509.Certificate
	client      *APIClient
	network     *tc.DockerNetwork
	containers  []tc.Container
}

const (
	suitePort            = "8080/tcp"
	nginxPort            = "8443/tcp"
	nginxCertificatePath = "/etc/ssl/certs/nginx-selfsigned.crt"
)

// StartSuite starts the suite and waits until its API is available. Stop it with Close; the
// containers are removed by the Testcontainers reaper otherwise.
func StartSuite(ctx context.Context, settings Settings, log *slog.Logger) (*Suite, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	baseURL, _ := url.Parse("https://localhost:" + strconv.Itoa(settings.SuitePort))
	log.Info("Starting conformance suite", "image", settings.SuiteImage, "url", baseURL)
	nw, err := network.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create the network of the conformance suite: %w", err)
	}
	suite := &Suite{settings: settings, baseURL: baseURL, network: nw}
	fail := func(err error) (*Suite, error) {
		suite.Close()
		return nil, err
	}
	mongodb, err := tc.Run(ctx, settings.SuiteMongoDBImage,
		network.WithNetwork([]string{"mongodb"}, nw),
		tc.WithExposedPorts("27017/tcp"),
		tc.WithLogConsumers(&logConsumer{log: log.With("container", "mongodb"), level: slog.LevelDebug}),
		tc.WithWaitStrategy(wait.ForListeningPort("27017/tcp").WithStartupTimeout(2*time.Minute)))
	if mongodb != nil {
		suite.containers = append(suite.containers, mongodb)
	}
	if err != nil {
		return fail(fmt.Errorf("could not start MongoDB for the conformance suite: %w", err))
	}
	server, err := tc.Run(ctx, settings.SuiteImage,
		network.WithNetwork([]string{"server"}, nw),
		tc.WithExposedPorts(suitePort),
		tc.WithEnv(map[string]string{
			"BASE_URL":      baseURL.String(),
			"BASE_MTLS_URL": baseURL.String(),
			"MONGODB_HOST":  "mongodb",
			// The suite pins MongoDB's feature compatibility version to the one it runs in
			// production (6.0) and refuses to start otherwise. The tests run a current MongoDB,
			// so the suite is told not to touch the version (an empty target skips the step).
			"OPENID_MONGODB_TARGETFEATURECOMPATIBILITYVERSION": "",
			// the dev profile needs no login
			"SPRING_PROFILES_ACTIVE": "dev",
			"OIDC_GOOGLE_CLIENTID":   "google-client",
			"OIDC_GOOGLE_SECRET":     "google-secret",
			"OIDC_GITLAB_CLIENTID":   "gitlab-client",
			"OIDC_GITLAB_SECRET":     "gitlab-secret",
		}),
		// the suite reaches the PDP under test on the Docker host as host.testcontainers.internal
		tc.WithHostPortAccess(settings.PDPPort),
		tc.WithLogConsumers(&logConsumer{log: log.With("container", "suite"), level: slog.LevelDebug}),
		tc.WithWaitStrategy(wait.ForListeningPort(suitePort).WithStartupTimeout(4*time.Minute)))
	if server != nil {
		suite.containers = append(suite.containers, server)
	}
	if err != nil {
		return fail(fmt.Errorf("could not start the conformance suite: %w", err))
	}
	nginx, err := tc.Run(ctx, settings.SuiteNginxImage,
		network.WithNetwork([]string{"nginx"}, nw),
		tc.WithExposedPorts(nginxPort),
		tc.WithHostConfigModifier(func(hostConfig *container.HostConfig) {
			hostConfig.PortBindings = mobynet.PortMap{mobynet.MustParsePort(nginxPort): []mobynet.PortBinding{{HostIP: netip.IPv4Unspecified(), HostPort: strconv.Itoa(settings.SuitePort)}}}
		}),
		tc.WithLogConsumers(&logConsumer{log: log.With("container", "nginx"), level: slog.LevelDebug}),
		tc.WithWaitStrategy(wait.ForListeningPort(nginxPort).WithStartupTimeout(2*time.Minute)))
	if nginx != nil {
		suite.containers = append(suite.containers, nginx)
	}
	if err != nil {
		return fail(fmt.Errorf("could not start the nginx of the conformance suite: %w", err))
	}
	certificate, err := nginxCertificate(ctx, nginx)
	if err != nil {
		return fail(err)
	}
	suite.certificate = certificate
	// the self-signed certificate of nginx names its host in the Common Name only, which Go
	// does not match, so the certificate itself is pinned instead of verified by host name
	suite.client = NewAPIClient(baseURL, newPinnedClient(certificate))
	if err := suite.client.WaitUntilAvailable(ctx, 4*time.Minute); err != nil {
		return fail(err)
	}
	log.Info("Conformance suite is available", "image", settings.SuiteImage, "url", baseURL)
	return suite, nil
}

// BaseURL is the URL under which the tests reach the suite (its UI shows the plans there).
func (s *Suite) BaseURL() *url.URL { return s.baseURL }

// Settings are the settings the suite was started with.
func (s *Suite) Settings() Settings { return s.settings }

// PDPHost is the host under which the suite reaches the PDP under test.
func (s *Suite) PDPHost() string { return tc.HostInternal }

// Client is the API of the suite.
func (s *Suite) Client() *APIClient { return s.client }

// Certificate is the TLS certificate of the suite.
func (s *Suite) Certificate() *x509.Certificate { return s.certificate }

// Close stops the containers and removes the network.
func (s *Suite) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for i := len(s.containers) - 1; i >= 0; i-- {
		_ = s.containers[i].Terminate(ctx)
	}
	if s.network != nil {
		_ = s.network.Remove(ctx)
	}
}

func nginxCertificate(ctx context.Context, nginx tc.Container) (*x509.Certificate, error) {
	reader, err := nginx.CopyFileFromContainer(ctx, nginxCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("could not read the TLS certificate of the conformance suite from %s: %w", nginxCertificatePath, err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("the TLS certificate of the conformance suite at %s is not PEM", nginxCertificatePath)
	}
	return x509.ParseCertificate(block.Bytes)
}

// newPinnedClient is an HTTP client that trusts exactly the given certificate, whatever host
// name it names (the suite's nginx certificate carries its host in the Common Name only).
func newPinnedClient(trusted *x509.Certificate) *http.Client {
	config := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // the certificate itself is checked below, only its host name is not
		// VerifyConnection, not VerifyPeerCertificate: it runs for resumed sessions as well
		VerifyConnection: func(state tls.ConnectionState) error {
			for _, certificate := range state.PeerCertificates {
				if certificate.Equal(trusted) {
					return nil
				}
			}
			return errors.New("the certificate of the conformance suite is not the trusted one")
		},
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = config
	return &http.Client{Transport: transport}
}

// logConsumer forwards the log of a container to slog.
type logConsumer struct {
	log   *slog.Logger
	level slog.Level
}

func (c *logConsumer) Accept(entry tc.Log) {
	c.log.Log(context.Background(), c.level, string(entry.Content))
}

var (
	sharedMu    sync.Mutex
	sharedSuite *Suite
)

// SharedSuite is the one suite the plan tests of a process share, started on first use with
// the given settings. CloseSharedSuite stops it.
func SharedSuite(ctx context.Context, settings Settings, log *slog.Logger) (*Suite, error) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if sharedSuite != nil {
		return sharedSuite, nil
	}
	suite, err := StartSuite(ctx, settings, log)
	if err != nil {
		return nil, err
	}
	sharedSuite = suite
	return suite, nil
}

// CloseSharedSuite stops the shared suite, if one was started.
func CloseSharedSuite() {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if sharedSuite != nil {
		sharedSuite.Close()
		sharedSuite = nil
	}
}
