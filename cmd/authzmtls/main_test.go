package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/weishiuchang/authzmtls/internal/dockerapi"
)

// This file is the integration test where internal/server and this
// package's own main.go are actually exercised together - the most
// important test in the whole project: it drives run (main's testable body,
// factored out precisely so this could happen without os.Exit tearing down
// the test binary) exactly as main() does, over real TLS, against a real
// listening port, with a real on-disk config file it edits and SIGHUPs
// mid-test - no stubs standing in for internal/server or internal/config.

// # self-signed TLS test certificate

// generateSelfSignedCert writes a fresh ECDSA self-signed certificate/key
// pair (CN/SAN "localhost", plus SAN 127.0.0.1 so dialing either name
// validates) as PEM files under dir. A self-signed leaf can be its own
// trust anchor - tlsClientTrusting below adds this exact certificate to a
// client's RootCAs pool rather than needing a separate CA.
func generateSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
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

	certPath = filepath.Join(dir, "server-cert.pem")
	keyPath = filepath.Join(dir, "server-key.pem")
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

// tlsClientTrusting builds an *http.Client that trusts certPath (a
// self-signed leaf, added directly to RootCAs) and expects ServerName
// "localhost", matching generateSelfSignedCert's SAN.
func tlsClientTrusting(t *testing.T, certPath string) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	der, err := os.ReadFile(certPath)
	require.NoError(t, err, "read %s", certPath)
	ok := pool.AppendCertsFromPEM(der)
	require.True(t, ok, "AppendCertsFromPEM(%s): no certificates found", certPath)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
		},
		Timeout: 10 * time.Second,
	}
}

// # misc test plumbing

// freePort asks the OS for an ephemeral TCP port, then immediately releases
// it - used to pick config.yaml's listen_addr up front, since run (unlike
// internal/server's own tests) has no Addr()-style accessor to discover
// whatever port ":0" bound after the fact.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "reserve free port")
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644), "write %s", path)
}

// waitServing polls baseURL's /Plugin.Activate (the one endpoint that never
// depends on datasources/allowlist content, only on the listener being up)
// until it answers 200 OK, bounded so a real startup failure fails the test
// promptly instead of hanging. It's kept as a manual poll loop (rather than
// require/assert.Eventually) because the failure message depends on lastErr
// accumulated across iterations, and Eventually's msgAndArgs are evaluated
// once at call time, before the loop runs - using it here would silently
// drop that diagnostic.
func waitServing(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/Plugin.Activate")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Failf(t, "timed out waiting for server to start serving", "%s: %v", baseURL, lastErr)
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
	require.NoError(t, err, "marshal container-create body")
	return b
}

func postAuthZReq(t *testing.T, client *http.Client, baseURL string, req *dockerapi.AuthZReq) *dockerapi.AuthZRes {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err, "marshal AuthZReq")
	resp, err := client.Post(baseURL+"/AuthZPlugin.AuthZReq", "application/json", bytes.NewReader(body))
	require.NoError(t, err, "POST /AuthZPlugin.AuthZReq")
	defer func() { _ = resp.Body.Close() }()
	var res dockerapi.AuthZRes
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&res), "decode AuthZRes")
	return &res
}

// configYAML renders a complete config.yaml: TLS on (certPath/keyPath), a
// short-but-real decision_timeout, no datasources at all (the "no
// datasource configured" half of the rule chain's deny contract), and two
// allowlist entries - a literal directory (allowedDir, swapped between
// subtests to prove hot reload) and a $GROUP-only pattern rooted under base
// (never matchable without a configured datasource, by construction).
func configYAML(listenAddr, certPath, keyPath, allowedDir, base string) string {
	return fmt.Sprintf(`
logging_level: info

server:
  listen_addr: %q
  server_cert: %q
  server_key: %q
  metrics_path: /metrics
  decision_timeout: 2s

allowlist:
  - %q
  - %q

checks:
  host_network: allow
  privileged: allow
  docker_cp: allow
  docker_exec: allow
`, listenAddr, certPath, keyPath, allowedDir, filepath.Join(base, "remote", "$GROUP"))
}

// # the end-to-end test

func TestRun_EndToEnd(t *testing.T) {
	base := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, base)

	allowedDir := filepath.Join(base, "allowed")
	disallowedDir := filepath.Join(base, "disallowed")
	remoteGroupDir := filepath.Join(base, "remote", "engineering") // real dir, only reachable via the unmatchable $GROUP pattern
	for _, d := range []string{allowedDir, disallowedDir, remoteGroupDir} {
		require.NoError(t, os.MkdirAll(d, 0o755), "mkdir %s", d)
	}

	listenAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	configPath := filepath.Join(base, "config.yaml")
	writeFile(t, configPath, configYAML(listenAddr, certPath, keyPath, allowedDir, base))

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, []string{configPath}) }()

	baseURL := "https://" + listenAddr
	client := tlsClientTrusting(t, certPath)
	waitServing(t, client, baseURL)

	t.Cleanup(func() {
		// Cancel is ctx's own shutdown trigger (see run's doc comment on why
		// this doesn't require sending the test binary a real signal) - this
		// exercises the exact SIGINT/SIGTERM-driven graceful-shutdown code
		// path, just via context cancellation instead of an OS signal.
		//
		// This runs on the test's own goroutine (t.Cleanup callbacks execute
		// on the goroutine running the test, not a spawned one), so assert
		// here is safe; it stays assert (not require) because it already was
		// t.Errorf, and there's nothing left to protect by aborting early.
		cancel()
		select {
		case err := <-runErr:
			assert.NoError(t, err, "run() returned error on graceful shutdown")
		case <-time.After(10 * time.Second):
			assert.Fail(t, "run() did not return within the grace period after ctx cancellation")
		}
	})

	// 1. Allowed mount: a literal allowlist entry, no datasource involved.
	res := postAuthZReq(t, client, baseURL, &dockerapi.AuthZReq{
		User:          "CN=alice,OU=eng",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.43/containers/create",
		RequestBody:   containerCreateBody(t, allowedDir),
	})
	require.True(t, res.Allow, "allowed-mount request: Msg=%q Err=%q, want Allow=true", res.Msg, res.Err)

	// 2. Disallowed mount: a real directory, just not in the allowlist.
	res = postAuthZReq(t, client, baseURL, &dockerapi.AuthZReq{
		User:          "CN=alice,OU=eng",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.43/containers/create",
		RequestBody:   containerCreateBody(t, disallowedDir),
	})
	require.False(t, res.Allow, "disallowed-mount request: want false (Msg=%q)", res.Msg)

	// 3. No mount: every rule abstains, and an all-abstain Chain is
	// default-allow (rules/chain.go's Decide) - this is not "nothing
	// happened," it's a deliberate policy outcome this test pins down.
	noMountBody, err := json.Marshal(map[string]any{"Image": "alpine"})
	require.NoError(t, err, "marshal no-mount body")
	res = postAuthZReq(t, client, baseURL, &dockerapi.AuthZReq{
		User:          "CN=alice,OU=eng",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.43/containers/create",
		RequestBody:   noMountBody,
	})
	require.True(t, res.Allow, "no-mount request: Msg=%q, want Allow=true", res.Msg)

	// 4. A mount only matchable via the $GROUP-only allowlist entry, with no
	// datasource configured at all: allowlist.Expand drops the pattern (no
	// GROUP value to substitute), so the Matcher never gets a prefix for it
	// - a real, wire-level Allow:false, measured to arrive well inside
	// decision_timeout (2s), not a hang.
	start := time.Now()
	res = postAuthZReq(t, client, baseURL, &dockerapi.AuthZReq{
		User:          "CN=alice,OU=eng",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.43/containers/create",
		RequestBody:   containerCreateBody(t, remoteGroupDir),
	})
	elapsed := time.Since(start)
	require.False(t, res.Allow, "$GROUP-only mount with no datasource configured: want false (Msg=%q)", res.Msg)
	require.LessOrEqual(t, elapsed, 2*time.Second,
		"$GROUP-only mount with no datasource configured took too long - looks like a hang, not a deny")

	// 5. Hot reload: rewrite config.yaml so the *disallowed* directory from
	// step 2 becomes the sole literal allowlist entry, SIGHUP, and prove a
	// subsequent decision reflects the new config - both that the
	// newly-allowed directory is now allowed, and that the old one no
	// longer is (config.yaml is fully replaced here, not conf.d-merged, so
	// this is a real swap, not a union).
	writeFile(t, configPath, configYAML(listenAddr, certPath, keyPath, disallowedDir, base))
	sendSIGHUPAndWaitReloaded(t, client, baseURL, disallowedDir)

	res = postAuthZReq(t, client, baseURL, &dockerapi.AuthZReq{
		User:          "CN=alice,OU=eng",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.43/containers/create",
		RequestBody:   containerCreateBody(t, allowedDir),
	})
	require.False(t, res.Allow, "post-reload request for the now-removed allowlist entry: want false")

	// 6. Metrics: server.metrics_path serves Prometheus exposition output
	// reflecting the decisions made above, using the exact scraped names
	// internal/telemetry/doc.go confirms.
	metricsResp, err := client.Get(baseURL + "/metrics")
	require.NoError(t, err, "GET /metrics")
	defer func() { _ = metricsResp.Body.Close() }()
	require.Equal(t, http.StatusOK, metricsResp.StatusCode, "GET /metrics")
	metricsBody, err := io.ReadAll(metricsResp.Body)
	require.NoError(t, err, "read /metrics body")
	requireMetricPositive(t, string(metricsBody), "authzmtls_requests_total")
	requireMetricPositive(t, string(metricsBody), "authzmtls_denied_total")
	require.Contains(t, string(metricsBody), "authzmtls_latency_milliseconds_count", "/metrics")
}

// sendSIGHUPAndWaitReloaded sends this test process itself a SIGHUP (the
// same self-signal pattern internal/config's own watch_test.go uses - the
// running server under test is this same test binary, via run) and polls
// until a request for wantAllowedDir succeeds, proving Server.Reload's
// atomic swap has actually landed rather than just asserting immediately
// after signaling (a successful reload logs nothing, per README's
// "Logging", so there's no log line to synchronize on instead).
//
// Kept as a manual poll loop rather than require/assert.Eventually: its
// condition calls postAuthZReq, which itself uses require internally, and
// Eventually runs its condition function on a separate goroutine per tick -
// require.FailNow from that goroutine would not fail the test the way it's
// supposed to. A plain for-loop keeps everything on the test's own
// goroutine.
func sendSIGHUPAndWaitReloaded(t *testing.T, client *http.Client, baseURL, wantAllowedDir string) {
	t.Helper()
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGHUP), "send SIGHUP to self")

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		res := postAuthZReq(t, client, baseURL, &dockerapi.AuthZReq{
			User:          "CN=alice,OU=eng",
			RequestMethod: http.MethodPost,
			RequestURI:    "/v1.43/containers/create",
			RequestBody:   containerCreateBody(t, wantAllowedDir),
		})
		if res.Allow {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Failf(t, "timed out waiting for SIGHUP reload to take effect", "mount %s still denied", wantAllowedDir)
}

var metricValueRe = `%s\{[^}]*\}\s+([0-9eE+\-.]+)`

func requireMetricPositive(t *testing.T, body, metricName string) {
	t.Helper()
	re := regexp.MustCompile(fmt.Sprintf(metricValueRe, regexp.QuoteMeta(metricName)))
	m := re.FindStringSubmatch(body)
	require.NotNil(t, m, "/metrics: no sample found for %s; body:\n%s", metricName, body)
	v, err := strconv.ParseFloat(m[1], 64)
	require.NoError(t, err, "/metrics: %s value %q did not parse as a number", metricName, m[1])
	require.Greater(t, v, 0.0, "/metrics: %s should reflect the decisions made in this test", metricName)
}

// # subprocess test: fatal SIGHUP-with-invalid-config

// buildBinary compiles this package (cmd/authzmtls) into a standalone
// executable under a temp directory. Building a real binary - rather than
// `go run`, which would itself fork a build+exec pair whose exit code isn't
// directly the program's own - is what lets the subprocess test below
// assert on the authzmtls process's actual exit code. This still obeys the
// project's "never install Go on the host" rule: this test only ever runs
// via `go test ./cmd/authzmtls/...` inside the golang:1.26.5 container
// itself, so the `go` this invokes is that same container's toolchain, not
// anything host-installed.
func buildBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "authzmtls-under-test")
	cmd := exec.Command("go", "build", "-o", out, ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "go build ./cmd/authzmtls: %s", stderr.String())
	return out
}

// TestRun_SubprocessSIGHUPWithInvalidConfigExitsNonZero proves the one
// os.Exit(1) path run itself can't cover in-process (see run's doc comment):
// a SIGHUP arriving while the on-disk config is invalid must kill the
// process, not leave it quietly serving the last-good config.
func TestRun_SubprocessSIGHUPWithInvalidConfigExitsNonZero(t *testing.T) {
	binPath := buildBinary(t)

	base := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, base)
	allowedDir := filepath.Join(base, "allowed")
	require.NoError(t, os.MkdirAll(allowedDir, 0o755), "mkdir %s", allowedDir)

	listenAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	configPath := filepath.Join(base, "config.yaml")
	writeFile(t, configPath, configYAML(listenAddr, certPath, keyPath, allowedDir, base))

	cmd := exec.Command(binPath, configPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start(), "start subprocess")
	t.Cleanup(func() {
		// Best-effort: if the assertions below fail before the process
		// exits on its own, don't leave it running past this test.
		_ = cmd.Process.Kill()
	})

	client := tlsClientTrusting(t, certPath)
	waitServing(t, client, "https://"+listenAddr)

	// Replace the config with one that fails Validate deterministically
	// (an unrecognized logging_level) - this exercises the same
	// LoadFull-fails-on-reload path as a typo'd field, without depending on
	// a YAML-syntax error's exact error shape.
	writeFile(t, configPath, "logging_level: not-a-real-level\nallowlist:\n  - /somewhere\n")

	require.NoError(t, cmd.Process.Signal(syscall.SIGHUP), "send SIGHUP to subprocess")

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	select {
	case err := <-waitErr:
		require.Error(t, err, "subprocess exited 0 after SIGHUP with an invalid config, want non-zero; stderr:\n%s", stderr.String())
	case <-time.After(10 * time.Second):
		require.Fail(t, "subprocess did not exit within 10s of SIGHUP with an invalid config (still serving stale config)",
			"stderr so far:\n%s", stderr.String())
	}

	require.Contains(t, stderr.String(), `"level":"ERROR"`, "subprocess stderr has no ERROR log line")
}
