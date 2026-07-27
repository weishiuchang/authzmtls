package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/weishiuchang/authzmtls/internal/config"
	"github.com/weishiuchang/authzmtls/internal/dockerapi"
)

// discardLogger returns a *slog.Logger that writes nowhere, for tests that
// need a non-nil logger but don't care about its output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// # minimal valid *config.Config construction

// baseConfig returns a minimal, valid *config.Config built directly
// (rather than loaded from YAML) so these tests don't depend on
// internal/config's file-loading machinery.
func baseConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		LoggingLevel: "info",
		Server: config.ServerConfig{
			ListenAddr:      "127.0.0.1:0",
			MetricsPath:     "/metrics",
			DecisionTimeout: config.Duration(2 * time.Second),
		},
		Allowlist: []string{"/nonexistent-allowlist-placeholder"},
		Checks: config.ChecksConfig{
			HostNetwork: config.CheckAllow,
			Privileged:  config.CheckAllow,
			DockerCP:    config.CheckAllow,
			DockerExec:  config.CheckAllow,
		},
	}
}

// # TLS test certificates

// certCounter guarantees generateCertFiles never reuses a filename, even
// when called twice within the same nanosecond (observed on fast machines).
var certCounter int

// generateCertFiles writes a fresh self-signed ECDSA cert/key pair (CN and
// SANs "localhost"+"127.0.0.1") as PEM files under dir. Each call produces
// a distinct keypair, which is what cert-rotation tests need.
func generateCertFiles(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate key")

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err, "generate serial")

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err, "create certificate")

	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err, "marshal key")

	certCounter++
	certPath = filepath.Join(dir, fmt.Sprintf("cert-%d.pem", certCounter))
	keyPath = filepath.Join(dir, fmt.Sprintf("key-%d.pem", certCounter))

	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)

	return certPath, keyPath
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err, "create %s", path)
	defer func() { _ = f.Close() }()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}), "encode PEM %s", path)
}

// # stub deciders

// fixedDecider returns the same (allow, msg, nil) for every call.
func fixedDecider(allow bool, msg string) dockerapi.DeciderFunc {
	return func(context.Context, *dockerapi.AuthZReq) (bool, string, error) {
		return allow, msg, nil
	}
}

// blockingDecider blocks until release is closed. started is closed the
// moment Decide is entered, so a test can know the call is in flight
// without racing on a sleep.
type blockingDecider struct {
	started chan struct{}
	release chan struct{}
	allow   bool
	msg     string
}

func newBlockingDecider() *blockingDecider {
	return &blockingDecider{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (d *blockingDecider) Decide(ctx context.Context, req *dockerapi.AuthZReq) (bool, string, error) {
	close(d.started)
	select {
	case <-d.release:
	case <-ctx.Done():
		return false, "", ctx.Err()
	}
	return d.allow, d.msg, nil
}

// ctxAwareDecider blocks until ctx is done and reports the elapsed time, to
// prove the ctx actually carries decision_timeout's deadline.
type ctxAwareDecider struct {
	result chan time.Duration
	start  time.Time
}

func newCtxAwareDecider() *ctxAwareDecider {
	return &ctxAwareDecider{result: make(chan time.Duration, 1), start: time.Now()}
}

func (d *ctxAwareDecider) Decide(ctx context.Context, req *dockerapi.AuthZReq) (bool, string, error) {
	<-ctx.Done()
	d.result <- time.Since(d.start)
	return false, "timed out", ctx.Err()
}

// # request/body fixtures

func authReq(user, method, uri string, body []byte) *dockerapi.AuthZReq {
	return &dockerapi.AuthZReq{
		User:          user,
		RequestMethod: method,
		RequestURI:    uri,
		RequestBody:   body,
	}
}

func containerCreateBody(t *testing.T, hostPaths ...string) []byte {
	t.Helper()
	binds := make([]string, len(hostPaths))
	for i, p := range hostPaths {
		binds[i] = fmt.Sprintf("%s:/mnt%d", p, i)
	}
	b, err := json.Marshal(map[string]any{
		"Image":      "alpine",
		"HostConfig": map[string]any{"Binds": binds},
	})
	require.NoError(t, err, "marshal container create body")
	return b
}
