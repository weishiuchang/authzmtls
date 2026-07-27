package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/weishiuchang/authzmtls/internal/config"
	"github.com/weishiuchang/authzmtls/internal/datasources"
	"github.com/weishiuchang/authzmtls/internal/dockerapi"
	"github.com/weishiuchang/authzmtls/internal/telemetry"
)

// waitDialable polls addr until a TCP dial succeeds or t fails, keeping
// tests robust to any future change in Start's synchronization.
func waitDialable(t *testing.T, addr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond, "timed out waiting for %s to accept connections", addr)
}

func addCertToPool(t *testing.T, pool *x509.CertPool, certPath string) {
	t.Helper()
	der, err := os.ReadFile(certPath)
	require.NoError(t, err, "read %s", certPath)
	ok := pool.AppendCertsFromPEM(der)
	require.True(t, ok, "AppendCertsFromPEM(%s): no certificates found", certPath)
}

// # New / Start / Addr

func TestNew_RejectsNilArgs(t *testing.T) {
	cfg := baseConfig(t)
	logger := discardLogger()

	_, err := New(nil, fixedDecider(true, ""), telemetry.Handler(), logger)
	require.Error(t, err, "New with nil cfg")
	_, err = New(cfg, nil, telemetry.Handler(), logger)
	require.Error(t, err, "New with nil decider")
	_, err = New(cfg, fixedDecider(true, ""), nil, logger)
	require.Error(t, err, "New with nil metrics handler")
}

func TestNew_RejectsOneOfCertKeySet(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Server.ServerCert = "/some/cert.pem"
	// ServerKey left unset.
	_, err := New(cfg, fixedDecider(true, ""), telemetry.Handler(), discardLogger())
	require.Error(t, err, "New with only server_cert set")
}

func TestPlainHTTP_ServesAndTLSClientFails(t *testing.T) {
	cfg := baseConfig(t)
	srv, err := New(cfg, fixedDecider(true, "ok"), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")
	require.False(t, srv.TLSEnabled(), "TLSEnabled: want false for a cert-less config")

	done, err := srv.Start()
	require.NoError(t, err, "Start")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})

	addr := srv.Addr()
	waitDialable(t, addr)

	resp, err := http.Get("http://" + addr + "/Plugin.Activate")
	require.NoError(t, err, "GET /Plugin.Activate")
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /Plugin.Activate")

	// Must fail as a genuine "not TLS at all" handshake error, not a
	// misconfigured-TLS false positive.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err, "dial")
	defer func() { _ = conn.Close() }()
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // deliberately testing handshake failure, not cert validation
	_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
	require.Error(t, tlsConn.Handshake(), "TLS handshake against plain-HTTP server")
}

func TestTLS_HandshakeSucceedsAgainstConfiguredCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateCertFiles(t, dir)

	cfg := baseConfig(t)
	cfg.Server.ServerCert = certPath
	cfg.Server.ServerKey = keyPath

	srv, err := New(cfg, fixedDecider(true, "ok"), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")
	require.True(t, srv.TLSEnabled(), "TLSEnabled: want true when server_cert/server_key are set")

	done, err := srv.Start()
	require.NoError(t, err, "Start")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})

	addr := srv.Addr()
	waitDialable(t, addr)

	pool := x509.NewCertPool()
	addCertToPool(t, pool, certPath)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
	}}
	resp, err := client.Get("https://" + addr + "/Plugin.Activate")
	require.NoError(t, err, "HTTPS GET /Plugin.Activate")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMetricsPath_ServesPrometheusOutput(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Server.MetricsPath = "/custom-metrics"

	srv, err := New(cfg, fixedDecider(true, ""), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")
	done, err := srv.Start()
	require.NoError(t, err, "Start")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})

	addr := srv.Addr()
	waitDialable(t, addr)

	resp, err := http.Get("http://" + addr + "/custom-metrics")
	require.NoError(t, err, "GET %s", cfg.Server.MetricsPath)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	ct := resp.Header.Get("Content-Type")
	require.Contains(t, ct, "text/plain", "want a Prometheus text/plain exposition type")

	// Confirms both routes are mounted - neither shadows the other.
	resp2, err := http.Get("http://" + addr + "/Plugin.Activate")
	require.NoError(t, err, "GET /Plugin.Activate")
	_ = resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "GET /Plugin.Activate")
}

func TestDecide_DecisionTimeoutBoundsSlowDecider(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Server.DecisionTimeout = config.Duration(50 * time.Millisecond)

	slow := newCtxAwareDecider()
	srv, err := New(cfg, slow, telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")

	start := time.Now()
	_, _, err = srv.Decide(context.Background(), authReq("cn=test", "POST", "/v1.40/containers/create", nil))
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	// 10x upper bound absorbs CPU scheduling jitter while still catching an
	// unbounded delay.
	require.LessOrEqual(t, elapsed, 500*time.Millisecond, "want roughly %v (decision_timeout)", cfg.Server.DecisionTimeout)
	require.GreaterOrEqual(t, elapsed, 40*time.Millisecond,
		"Decide returned suspiciously faster than the 50ms decision_timeout - ctx may not carry the deadline at all")
}

func TestAddr_EmptyBeforeStart(t *testing.T) {
	cfg := baseConfig(t)
	srv, err := New(cfg, fixedDecider(true, ""), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")
	require.Empty(t, srv.Addr(), "Addr() before Start")
}

func TestStart_SecondCallErrors(t *testing.T) {
	cfg := baseConfig(t)
	srv, err := New(cfg, fixedDecider(true, ""), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")
	done, err := srv.Start()
	require.NoError(t, err, "first Start")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})

	_, err = srv.Start()
	require.Error(t, err, "second Start")
}

// # TLS cert rotation (via Reload)

// persistentTLSConn wraps a hand-dialed *tls.Conn so cert-rotation tests
// can control exactly which connection a request reuses, which
// http.Client's pooling won't let them do.
type persistentTLSConn struct {
	conn *tls.Conn
	br   *bufio.Reader
}

func dialPersistentTLS(t *testing.T, addr string, tlsCfg *tls.Config) *persistentTLSConn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	require.NoError(t, err, "tls.Dial")
	return &persistentTLSConn{conn: conn, br: bufio.NewReader(conn)}
}

func (c *persistentTLSConn) get(t *testing.T, path string) *http.Response {
	t.Helper()
	_ = c.conn.SetDeadline(time.Now().Add(3 * time.Second))
	req, err := http.NewRequest(http.MethodGet, path, nil)
	require.NoError(t, err, "build request")
	req.Host = "localhost"
	require.NoError(t, req.Write(c.conn), "write request")
	resp, err := http.ReadResponse(c.br, req)
	require.NoError(t, err, "read response")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

func (c *persistentTLSConn) peerCertDER(t *testing.T) []byte {
	t.Helper()
	certs := c.conn.ConnectionState().PeerCertificates
	require.NotEmpty(t, certs, "no peer certificates on connection")
	return certs[0].Raw
}

func trustPool(t *testing.T, certPath string) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	addCertToPool(t, pool, certPath)
	return pool
}

// TestCertRotation_NewConnectionsGetNewCert_ExistingConnectionUnaffected
// proves live rotation: an already-open connection keeps its old cert
// across a Reload, while new connections get the new cert and old-cert
// trust pools are rejected.
func TestCertRotation_NewConnectionsGetNewCert_ExistingConnectionUnaffected(t *testing.T) {
	dir := t.TempDir()
	certA, keyA := generateCertFiles(t, dir)
	certB, keyB := generateCertFiles(t, dir)

	cfg := baseConfig(t)
	cfg.Server.ServerCert = certA
	cfg.Server.ServerKey = keyA

	srv, err := New(cfg, fixedDecider(true, "ok"), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")
	done, err := srv.Start()
	require.NoError(t, err, "Start")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})
	addr := srv.Addr()
	waitDialable(t, addr)

	poolA := trustPool(t, certA)
	poolB := trustPool(t, certB)

	// Establish and fully complete a handshake against certA before rotating.
	oldConn := dialPersistentTLS(t, addr, &tls.Config{RootCAs: poolA, ServerName: "localhost"})
	defer func() { _ = oldConn.conn.Close() }()
	certBeforeReload := oldConn.peerCertDER(t)
	resp := oldConn.get(t, "/Plugin.Activate")
	require.Equal(t, http.StatusOK, resp.StatusCode, "pre-reload request over oldConn")

	// Rotate to certB.
	cfg.Server.ServerCert = certB
	cfg.Server.ServerKey = keyB
	require.NoError(t, srv.Reload(cfg), "Reload")

	// A brand-new connection now negotiates certB.
	newConn := dialPersistentTLS(t, addr, &tls.Config{RootCAs: poolB, ServerName: "localhost"})
	defer func() { _ = newConn.conn.Close() }()
	certAfterReload := newConn.peerCertDER(t)
	resp = newConn.get(t, "/Plugin.Activate")
	require.Equal(t, http.StatusOK, resp.StatusCode, "post-reload request over newConn")
	require.NotEqual(t, certBeforeReload, certAfterReload,
		"new connection after Reload presented the same certificate as before - rotation did not take effect")

	// A connection trusting only the old cert must now fail: the server
	// presents certB.
	_, err = tls.Dial("tcp", addr, &tls.Config{RootCAs: poolA, ServerName: "localhost"})
	require.Error(t, err, "new TLS connection trusting only the old cert: want handshake error (server should now present the new cert)")

	// The pre-existing connection is unaffected: TLS doesn't re-run
	// certificate selection mid-connection.
	resp = oldConn.get(t, "/Plugin.Activate")
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"request over pre-existing oldConn after Reload (connection must survive rotation)")
	require.Equal(t, certBeforeReload, oldConn.peerCertDER(t),
		"oldConn's negotiated certificate changed after Reload - an already-open connection must be unaffected by rotation")
}

// TestReload_BadCertKeyPair_ReturnsErrorAndKeepsServingOldCert asserts a
// bad cert/key pair returns an error and leaves the old cert serving.
func TestReload_BadCertKeyPair_ReturnsErrorAndKeepsServingOldCert(t *testing.T) {
	dir := t.TempDir()
	certA, keyA := generateCertFiles(t, dir)
	_, keyB := generateCertFiles(t, dir) // mismatched key from a different pair

	cfg := baseConfig(t)
	cfg.Server.ServerCert = certA
	cfg.Server.ServerKey = keyA

	srv, err := New(cfg, fixedDecider(true, "ok"), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")
	done, err := srv.Start()
	require.NoError(t, err, "Start")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})
	addr := srv.Addr()
	waitDialable(t, addr)

	poolA := trustPool(t, certA)
	before := dialPersistentTLS(t, addr, &tls.Config{RootCAs: poolA, ServerName: "localhost"})
	certBefore := before.peerCertDER(t)
	_ = before.conn.Close()

	// certA paired with keyB: a mismatched, unusable pair.
	badCfg := baseConfig(t)
	badCfg.Server.ServerCert = certA
	badCfg.Server.ServerKey = keyB
	require.Error(t, srv.Reload(badCfg), "Reload with mismatched cert/key pair")

	after := dialPersistentTLS(t, addr, &tls.Config{RootCAs: poolA, ServerName: "localhost"})
	defer func() { _ = after.conn.Close() }()
	certAfter := after.peerCertDER(t)
	require.Equal(t, certBefore, certAfter,
		"certificate changed after a failed Reload - a bad cert/key pair must not disturb the previously serving certificate")
	resp := after.get(t, "/Plugin.Activate")
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"request after failed Reload: server must keep serving on the old cert")
}

// TestReload_PlainHTTPMode_NeverTouchesCertLogic confirms Reload on a
// plain-HTTP Server skips cert-rotation entirely, silently.
func TestReload_PlainHTTPMode_NeverTouchesCertLogic(t *testing.T) {
	cfg := baseConfig(t)
	srv, err := New(cfg, fixedDecider(true, "ok"), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")
	require.Nil(t, srv.cert.Load(), "plain-HTTP Server: cert pointer should never be set")

	require.NoError(t, srv.Reload(baseConfig(t)), "Reload")
	require.Nil(t, srv.cert.Load(), "Reload on a plain-HTTP Server must never populate the cert pointer")
}

// TestReload_CannotChangeTLSModeFromPlainHTTP asserts Reload rejects an
// attempt to switch TLS mode rather than silently ignoring it.
func TestReload_CannotChangeTLSModeFromPlainHTTP(t *testing.T) {
	dir := t.TempDir()
	certA, keyA := generateCertFiles(t, dir)

	cfg := baseConfig(t)
	srv, err := New(cfg, fixedDecider(true, "ok"), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")

	tlsCfg := baseConfig(t)
	tlsCfg.Server.ServerCert = certA
	tlsCfg.Server.ServerKey = keyA
	require.Error(t, srv.Reload(tlsCfg), "Reload switching plain-HTTP to TLS")
}

// # Reload: state-swap semantics, cache flush, error handling

func TestReload_NilConfigErrors(t *testing.T) {
	cfg := baseConfig(t)
	srv, err := New(cfg, fixedDecider(true, ""), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")
	require.Error(t, srv.Reload(nil), "Reload(nil)")
}

// TestReload_SwapsStateWithoutDroppingInFlightRequest proves the core
// atomic.Pointer[state] contract: an in-flight Decide call finishes against
// the old decider even when a Reload lands mid-call.
func TestReload_SwapsStateWithoutDroppingInFlightRequest(t *testing.T) {
	cfg := baseConfig(t)
	old := newBlockingDecider()
	old.allow = false
	old.msg = "old-decider-result"

	srv, err := New(cfg, old, telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")

	type result struct {
		allow bool
		msg   string
		err   error
	}
	inFlight := make(chan result, 1)
	go func() {
		allow, msg, err := srv.Decide(context.Background(), authReq("cn=alice", "POST", "/v1.40/containers/create", nil))
		inFlight <- result{allow, msg, err}
	}()

	// Wait for the in-flight call to actually enter the old decider, so the
	// race being tested is real, not accidental ordering.
	select {
	case <-old.started:
	case <-time.After(2 * time.Second):
		require.Fail(t, "timed out waiting for in-flight Decide to start")
	}

	// cfg2's chain abstains through to (allow=true, msg=""), deliberately
	// distinguishable from old's fixed (false, "old-decider-result") so the
	// result alone reveals which decider answered.
	cfg2 := baseConfig(t)
	require.NoError(t, srv.Reload(cfg2), "Reload")

	// Release the in-flight call now that Reload has completed.
	close(old.release)

	select {
	case r := <-inFlight:
		require.NoError(t, r.err, "in-flight Decide error")
		require.False(t, r.allow, "in-flight Decide must not be affected by a Reload after it started")
		require.Equal(t, "old-decider-result", r.msg, "in-flight Decide must not be affected by a Reload after it started")
	case <-time.After(2 * time.Second):
		require.Fail(t, "timed out waiting for in-flight Decide to return")
	}

	// A fresh call now uses the newly swapped-in chain.
	allow, msg, err := srv.Decide(context.Background(), authReq("cn=alice", "GET", "/v1.40/containers/json", nil))
	require.NoError(t, err, "post-reload Decide error")
	require.True(t, allow, "post-reload Decide should use the newly built abstain-through chain")
	require.Empty(t, msg, "post-reload Decide should use the newly built abstain-through chain")
}

// counterProvider returns GROUP=["g1"] on its first call and GROUP=["g2"]
// after, to prove Reload's unconditional-flush contract: a
// config-identical Reload must still trigger a fresh resolve, not serve a
// cached "g1" answer.
type counterProvider struct {
	n *int32
}

func (p *counterProvider) Resolve(ctx context.Context, vars map[string]string) (map[string][]string, error) {
	n := atomic.AddInt32(p.n, 1)
	group := "g1"
	if n > 1 {
		group = "g2"
	}
	return map[string][]string{"GROUP": {group}}, nil
}

func TestReload_FlushCalledEveryTimeEvenWhenConfigUnchanged(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "remote", "g1"), 0o755), "mkdir g1")
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "remote", "g2"), 0o755), "mkdir g2")

	typeName := "countertest_flush_" + t.Name()
	var calls int32
	datasources.Register(typeName, func(name string, raw yaml.Node) (datasources.Provider, error) {
		return &counterProvider{n: &calls}, nil
	})

	cfg := baseConfig(t)
	cfg.Allowlist = []string{filepath.Join(tmpDir, "remote", "$GROUP")}
	cfg.Datasources = []config.DatasourceConfig{
		{Name: "counter1", Type: typeName, CacheTTL: config.Duration(time.Hour)},
	}

	srv, err := New(cfg, fixedDecider(false, "unused-initial-decider"), telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")

	body := containerCreateBody(t, filepath.Join(tmpDir, "remote", "g1"))
	req := authReq("cn=alice", "POST", "/v1.40/containers/create", body)

	// First Reload activates a real chain over a fresh datasources.Set.
	require.NoError(t, srv.Reload(cfg), "first Reload")
	allow, _, err := srv.Decide(context.Background(), req)
	require.NoError(t, err, "Decide after first Reload")
	require.True(t, allow, "Decide after first Reload: identity resolves to GROUP=g1, mount path is .../remote/g1")

	// Repeating without a Reload must hit the cache and still see g1,
	// establishing that caching genuinely happens absent a Reload.
	allow, _, err = srv.Decide(context.Background(), req)
	require.NoError(t, err, "Decide (repeat, no reload)")
	require.True(t, allow, "Decide (repeat, no reload): want allow=true from the cached g1 resolution")

	// Second Reload with identical cfg: if flush were skipped when "nothing
	// changed," this would still see g1. It must see g2 instead.
	require.NoError(t, srv.Reload(cfg), "second Reload")
	allow, _, err = srv.Decide(context.Background(), req)
	require.NoError(t, err, "Decide after second Reload")
	require.False(t, allow,
		"Decide after second Reload: identical config must still flush the cache, revealing the now-current GROUP=g2 resolution")

	require.GreaterOrEqual(t, atomic.LoadInt32(&calls), int32(2),
		"counterProvider.Resolve should be called at least once per Reload")
}

func TestReload_UnknownDatasourceType_ReturnsErrorNoSwap(t *testing.T) {
	cfg := baseConfig(t)
	original := fixedDecider(true, "original")
	srv, err := New(cfg, original, telemetry.Handler(), discardLogger())
	require.NoError(t, err, "New")

	badCfg := baseConfig(t)
	badCfg.Datasources = []config.DatasourceConfig{
		{Name: "bad", Type: "no-such-type-registered-anywhere"},
	}
	require.Error(t, srv.Reload(badCfg), "Reload with unknown datasource type")

	allow, msg, err := srv.Decide(context.Background(), authReq("cn=alice", "GET", "/v1.40/containers/json", nil))
	require.NoError(t, err, "Decide after failed Reload")
	require.True(t, allow, "a failed Reload must not swap in any new state")
	require.Equal(t, "original", msg, "a failed Reload must not swap in any new state")
}

var _ dockerapi.Decider = (*Server)(nil)
