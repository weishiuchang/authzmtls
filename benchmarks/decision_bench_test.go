// Package benchmarks holds cross-package, end-to-end performance
// benchmarks that don't belong to any single package under internal/.
//
// This file benchmarks the full in-process decision path:
// dockerapi.Handler.Mux() -> httptest.NewRecorder -> rules.Chain.
package benchmarks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/weishiuchang/authzmtls/internal/config"
	"github.com/weishiuchang/authzmtls/internal/datasources"
	"github.com/weishiuchang/authzmtls/internal/dockerapi"
	"github.com/weishiuchang/authzmtls/internal/rules"
)

// discardLogger satisfies constructors that require a logger; log output
// isn't what's being measured.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newBenchMux builds a real Mux over a real rules.Chain allowlisting
// exactly allowedDir, with every other check gate left at CheckAllow, so
// the mount-allowlist rule is the one rule deciding these requests.
func newBenchMux(b *testing.B, allowedDir string) http.Handler {
	b.Helper()

	cfg := &config.Config{
		Allowlist: []string{allowedDir},
		Checks: config.ChecksConfig{
			HostNetwork: config.CheckAllow,
			Privileged:  config.CheckAllow,
			DockerCP:    config.CheckAllow,
			DockerExec:  config.CheckAllow,
		},
	}

	logger := discardLogger()
	dsSet, err := datasources.NewSet(nil, logger)
	require.NoError(b, err, "datasources.NewSet")
	chain, err := rules.NewBuiltinChain(cfg, dsSet, logger)
	require.NoError(b, err, "rules.NewBuiltinChain")

	return dockerapi.NewHandler(chain, logger).Mux()
}

// containerCreateBody renders a minimal container-create JSON body binding
// hostPath, the same shape dockerd sends and the mount-allowlist rule
// inspects.
func containerCreateBody(b *testing.B, hostPath string) []byte {
	b.Helper()
	body, err := json.Marshal(map[string]any{
		"Image":      "alpine",
		"HostConfig": map[string]any{"Binds": []string{hostPath + ":/mnt0"}},
	})
	require.NoError(b, err, "marshal container-create body")
	return body
}

// authZReqBody wraps body as a full AuthZReq envelope, matching the wire
// shape dockerapi.Handler.decodeRequest expects.
func authZReqBody(b *testing.B, containerCreate []byte) []byte {
	b.Helper()
	req := dockerapi.AuthZReq{
		User:          "CN=alice,OU=eng",
		RequestMethod: http.MethodPost,
		RequestURI:    "/v1.43/containers/create",
		RequestBody:   containerCreate,
	}
	out, err := json.Marshal(req)
	require.NoError(b, err, "marshal AuthZReq")
	return out
}

// BenchmarkAuthZReqDecision_Allow drives Mux() directly for a request whose
// mount matches the allowlist, exercising decode -> rule evaluation ->
// encode -> metric recording end to end.
func BenchmarkAuthZReqDecision_Allow(b *testing.B) {
	dir := b.TempDir()
	allowedDir := filepath.Join(dir, "allowed")
	require.NoError(b, os.MkdirAll(allowedDir, 0o755), "mkdir %s", allowedDir)

	mux := newBenchMux(b, allowedDir)
	reqBody := authZReqBody(b, containerCreateBody(b, allowedDir))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		httpReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/AuthZPlugin.AuthZReq", bytes.NewReader(reqBody))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httpReq)

		require.Equal(b, http.StatusOK, rec.Code, "status")
		var res dockerapi.AuthZRes
		require.NoError(b, json.Unmarshal(rec.Body.Bytes(), &res), "decode AuthZRes")
		require.True(b, res.Allow, "Allow = false, want true (Msg=%q Err=%q)", res.Msg, res.Err)
	}
}

// BenchmarkAuthZReqDecision_Deny is the same shape as
// BenchmarkAuthZReqDecision_Allow but for a mount outside the allowlist
// (a real, existing directory), so the cost measured is a deny, not a
// filesystem error.
func BenchmarkAuthZReqDecision_Deny(b *testing.B) {
	dir := b.TempDir()
	allowedDir := filepath.Join(dir, "allowed")
	disallowedDir := filepath.Join(dir, "disallowed")
	for _, d := range []string{allowedDir, disallowedDir} {
		require.NoError(b, os.MkdirAll(d, 0o755), "mkdir %s", d)
	}

	mux := newBenchMux(b, allowedDir)
	reqBody := authZReqBody(b, containerCreateBody(b, disallowedDir))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		httpReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/AuthZPlugin.AuthZReq", bytes.NewReader(reqBody))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httpReq)

		require.Equal(b, http.StatusOK, rec.Code, "status")
		var res dockerapi.AuthZRes
		require.NoError(b, json.Unmarshal(rec.Body.Bytes(), &res), "decode AuthZRes")
		require.False(b, res.Allow, "Allow = true, want false")
	}
}
