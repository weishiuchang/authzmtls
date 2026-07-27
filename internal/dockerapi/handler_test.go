package dockerapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/weishiuchang/authzmtls/internal/logging"
)

// newTestHandler builds a Handler wired to a local, in-process OTel SDK
// meter rather than going through internal/telemetry.Meter(), so this
// package's tests stay decoupled from internal/telemetry's own
// setup/initialization order. It exercises the same recording code path
// (Handler.latency.Record) NewHandler wires up in production.
func newTestHandler(t *testing.T, decider Decider, logger *slog.Logger) (*Handler, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := mp.Meter("github.com/weishiuchang/authzmtls")
	hist, err := meter.Float64Histogram(latencyHistogramName, otelmetric.WithUnit("ms"))
	require.NoError(t, err)
	return &Handler{decider: decider, logger: logger, latency: hist}, reader
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: logging.LevelInfo}))
}

// stderrMu serializes tests that redirect the process-wide os.Stderr.
var stderrMu sync.Mutex

// captureLoggerOutput builds a logger via logging.New(level) - the real,
// shared constructor dockerapi uses in production, TRACE-level-name
// rendering included - and returns whatever it writes to stderr while fn
// runs.
func captureLoggerOutput(t *testing.T, level string, fn func(logger *slog.Logger)) string {
	t.Helper()
	stderrMu.Lock()
	defer stderrMu.Unlock()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stderr
	os.Stderr = w
	logger := logging.New(level)

	fn(logger)

	os.Stderr = orig
	require.NoError(t, w.Close(), "close pipe writer")
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err, "read captured stderr")
	return buf.String()
}

// # /Plugin.Activate

func TestHandleActivate(t *testing.T) {
	h, _ := newTestHandler(t, DeciderFunc(func(context.Context, *AuthZReq) (bool, string, error) {
		require.Fail(t, "Decider must not be called for /Plugin.Activate")
		return false, "", nil
	}), discardLogger())

	req := httptest.NewRequest(http.MethodPost, "/Plugin.Activate", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `{"Implements":["authz"]}`, strings.TrimSpace(rec.Body.String()))
}

// # decode + dispatch, real-shaped /containers/create body

// containersCreateBody is a real-shaped `POST /containers/create` request
// body, used as the RequestBody payload of a handcrafted AuthZReq below.
const containersCreateBody = `{
  "Image": "alpine:3.19",
  "Cmd": ["sh", "-c", "sleep 1"],
  "HostConfig": {
    "Binds": ["/data/allowed:/data/allowed:rw"],
    "Mounts": [
      {"Type": "bind", "Source": "/data/allowed", "Target": "/mnt", "ReadOnly": false}
    ],
    "Privileged": false,
    "NetworkMode": "bridge"
  }
}`

// handcraftedAuthZReqJSON builds a literal (not struct-marshaled) AuthZReq
// wire payload, so decode correctness is checked against the protocol
// itself rather than round-tripped through our own encoder.
func handcraftedAuthZReqJSON(t *testing.T, uri, body string) string {
	t.Helper()
	encodedBody := base64.StdEncoding.EncodeToString([]byte(body))
	return fmt.Sprintf(`{
  "User": "CN=alice,OU=eng,O=example",
  "UserAuthNMethod": "TLS",
  "RequestMethod": "POST",
  "RequestURI": %q,
  "RequestBody": %q,
  "RequestHeaders": {"Content-Type": "application/json"}
}`, uri, encodedBody)
}

func TestHandleAuthZReq_DecodeAndDispatchAllow(t *testing.T) {
	var captured *AuthZReq
	decider := DeciderFunc(func(_ context.Context, req *AuthZReq) (bool, string, error) {
		captured = req
		return true, "", nil
	})
	h, reader := newTestHandler(t, decider, discardLogger())

	body := handcraftedAuthZReqJSON(t, "/v1.44/containers/create", containersCreateBody)
	req := httptest.NewRequest(http.MethodPost, "/AuthZPlugin.AuthZReq", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())

	require.NotNil(t, captured, "decider was not called")
	assert.Equal(t, "CN=alice,OU=eng,O=example", captured.User)
	assert.Equal(t, "TLS", captured.UserAuthNMethod)
	assert.Equal(t, "POST", captured.RequestMethod)
	assert.Equal(t, "/v1.44/containers/create", captured.RequestURI)
	assert.Equal(t, containersCreateBody, strings.TrimSpace(string(captured.RequestBody)), "RequestBody mismatch")
	assert.Equal(t, "application/json", captured.RequestHeaders["Content-Type"])
	assert.Contains(t, string(captured.RequestBody), `"NetworkMode": "bridge"`, "RequestBody missing expected HostConfig content")

	var res AuthZRes
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res), "response decode")
	assert.True(t, res.Allow, "want Allow=true")
	assert.Empty(t, res.Err, "want Err empty")

	assertLatencyRecorded(t, reader, 1)
}

func TestHandleAuthZReq_DecodeAndDispatchDeny(t *testing.T) {
	decider := DeciderFunc(func(_ context.Context, req *AuthZReq) (bool, string, error) {
		return false, "host path not in allowlist", nil
	})
	h, reader := newTestHandler(t, decider, discardLogger())

	body := handcraftedAuthZReqJSON(t, "/v1.44/containers/create", containersCreateBody)
	req := httptest.NewRequest(http.MethodPost, "/AuthZPlugin.AuthZReq", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	var res AuthZRes
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res), "response decode")
	assert.False(t, res.Allow)
	assert.Equal(t, "host path not in allowlist", res.Msg)

	assertLatencyRecorded(t, reader, 1)
}

func TestHandleAuthZReq_DeciderError(t *testing.T) {
	decider := DeciderFunc(func(_ context.Context, req *AuthZReq) (bool, string, error) {
		return false, "", fmt.Errorf("datasource unavailable")
	})
	h, reader := newTestHandler(t, decider, discardLogger())

	body := handcraftedAuthZReqJSON(t, "/v1.44/containers/create", containersCreateBody)
	req := httptest.NewRequest(http.MethodPost, "/AuthZPlugin.AuthZReq", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	var res AuthZRes
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res), "response decode")
	assert.False(t, res.Allow)
	assert.Equal(t, "datasource unavailable", res.Err)

	// Latency must still be recorded even on a Decider error.
	assertLatencyRecorded(t, reader, 1)
}

func TestHandleAuthZReq_MalformedJSON(t *testing.T) {
	h, _ := newTestHandler(t, DeciderFunc(func(context.Context, *AuthZReq) (bool, string, error) {
		require.Fail(t, "Decider must not be called on malformed JSON")
		return false, "", nil
	}), discardLogger())

	req := httptest.NewRequest(http.MethodPost, "/AuthZPlugin.AuthZReq", strings.NewReader(`{not valid json`))
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var res AuthZRes
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res), "response decode")
	assert.NotEmpty(t, res.Err, "want a decode error message")
}

// # /AuthZPlugin.AuthZRes

func TestHandleAuthZRes_DecodeAndDispatch(t *testing.T) {
	var captured *AuthZReq
	decider := DeciderFunc(func(_ context.Context, req *AuthZReq) (bool, string, error) {
		captured = req
		return true, "", nil
	})
	h, _ := newTestHandler(t, decider, discardLogger())

	payload := `{
  "User": "CN=bob,OU=eng,O=example",
  "UserAuthNMethod": "TLS",
  "RequestMethod": "POST",
  "RequestURI": "/v1.44/containers/create",
  "ResponseStatusCode": 201,
  "ResponseBody": "` + base64.StdEncoding.EncodeToString([]byte(`{"Id":"abc123"}`)) + `",
  "ResponseHeaders": {"Content-Type": "application/json"}
}`
	req := httptest.NewRequest(http.MethodPost, "/AuthZPlugin.AuthZRes", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	require.NotNil(t, captured, "decider was not called")
	assert.Equal(t, 201, captured.ResponseStatusCode)
	assert.Equal(t, `{"Id":"abc123"}`, string(captured.ResponseBody))
}

// # TRACE-level logging

func TestTraceLoggingCapturesRequestAndResponse(t *testing.T) {
	var rec *httptest.ResponseRecorder
	output := captureLoggerOutput(t, "trace", func(logger *slog.Logger) {
		decider := DeciderFunc(func(_ context.Context, req *AuthZReq) (bool, string, error) {
			return false, "denied for test", nil
		})
		h, _ := newTestHandler(t, decider, logger)

		body := handcraftedAuthZReqJSON(t, "/v1.44/containers/create", containersCreateBody)
		req := httptest.NewRequest(http.MethodPost, "/AuthZPlugin.AuthZReq", strings.NewReader(body))
		rec = httptest.NewRecorder()
		h.Mux().ServeHTTP(rec, req)
	})

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())

	lines := strings.Split(strings.TrimSpace(output), "\n")
	require.Lenf(t, lines, 2, "want 2 log lines (request + response):\n%s", output)

	var reqLine map[string]any
	require.NoErrorf(t, json.Unmarshal([]byte(lines[0]), &reqLine), "request log line not valid JSON:\n%s", lines[0])
	assert.Equal(t, "TRACE", reqLine["level"])
	reqField, ok := reqLine["request"].(map[string]any)
	require.Truef(t, ok, "request log line missing structured \"request\" object field: %s", lines[0])
	assert.Equal(t, "CN=alice,OU=eng,O=example", reqField["User"])
	assert.Equal(t, "/v1.44/containers/create", reqField["RequestURI"])

	var resLine map[string]any
	require.NoErrorf(t, json.Unmarshal([]byte(lines[1]), &resLine), "response log line not valid JSON:\n%s", lines[1])
	assert.Equal(t, "TRACE", resLine["level"])
	resField, ok := resLine["response"].(map[string]any)
	require.Truef(t, ok, "response log line missing structured \"response\" object field: %s", lines[1])
	assert.Equal(t, false, resField["Allow"])
	assert.Equal(t, "denied for test", resField["Msg"])
}

func TestNoTraceLoggingBelowTraceLevel(t *testing.T) {
	output := captureLoggerOutput(t, "info", func(logger *slog.Logger) {
		decider := DeciderFunc(func(context.Context, *AuthZReq) (bool, string, error) {
			return true, "", nil
		})
		h, _ := newTestHandler(t, decider, logger)

		body := handcraftedAuthZReqJSON(t, "/v1.44/containers/create", containersCreateBody)
		req := httptest.NewRequest(http.MethodPost, "/AuthZPlugin.AuthZReq", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.Mux().ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	assert.Empty(t, output, "expected no log output at INFO level")
}

// # authzmtls.latency

func assertLatencyRecorded(t *testing.T, reader *sdkmetric.ManualReader, wantAtLeast int) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	count := 0
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != latencyHistogramName {
				continue
			}
			hd, ok := m.Data.(metricdata.Histogram[float64])
			require.Truef(t, ok, "%s: unexpected data type %T", latencyHistogramName, m.Data)
			for _, dp := range hd.DataPoints {
				count += int(dp.Count)
			}
		}
	}
	assert.GreaterOrEqualf(t, count, wantAtLeast, "%s recorded observations", latencyHistogramName)
}

func TestLatencyRecordedForAllowAndDeny(t *testing.T) {
	for _, allow := range []bool{true, false} {
		allow := allow
		t.Run(fmt.Sprintf("allow=%v", allow), func(t *testing.T) {
			decider := DeciderFunc(func(context.Context, *AuthZReq) (bool, string, error) {
				return allow, "", nil
			})
			h, reader := newTestHandler(t, decider, discardLogger())

			body := handcraftedAuthZReqJSON(t, "/v1.44/containers/create", containersCreateBody)
			req := httptest.NewRequest(http.MethodPost, "/AuthZPlugin.AuthZReq", strings.NewReader(body))
			rec := httptest.NewRecorder()
			h.Mux().ServeHTTP(rec, req)

			require.Equal(t, http.StatusOK, rec.Code)
			assertLatencyRecorded(t, reader, 1)
		})
	}
}
