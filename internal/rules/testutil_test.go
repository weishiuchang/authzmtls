package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/require"

	"github.com/weishiuchang/authzmtls/internal/datasources"
	"github.com/weishiuchang/authzmtls/internal/dockerapi"
)

// # logging capture (same pattern internal/datasources' own tests use)

// capturingHandler is a minimal slog.Handler that records every emitted
// slog.Record so tests can assert on exactly what was logged.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *capturingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *capturingHandler) all() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(h.records))
	copy(out, h.records)
	return out
}

func (h *capturingHandler) recordsAtLevel(level slog.Level) []slog.Record {
	var out []slog.Record
	for _, r := range h.all() {
		if r.Level == level {
			out = append(out, r)
		}
	}
	return out
}

// attrString returns record r's attribute named key.
func attrString(r slog.Record, key string) (string, bool) {
	var (
		val   string
		found bool
	)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val = a.Value.String()
			found = true
			return false
		}
		return true
	})
	return val, found
}

// newTestLogger builds a logger over capturingHandler, unfiltered (Enabled
// always true) - level filtering is internal/logging's own concern, not
// duplicated here.
func newTestLogger(t *testing.T) (*slog.Logger, *capturingHandler) {
	t.Helper()
	h := &capturingHandler{}
	return slog.New(h), h
}

// # fake datasources.Provider

// fakeProvider is a controllable datasources.Provider for driving
// MountAllowlistRule/VolumeBindMountRule tests without a real backend.
type fakeProvider struct {
	resolve func(ctx context.Context, vars map[string]string) (map[string][]string, error)
}

func (f *fakeProvider) Resolve(ctx context.Context, vars map[string]string) (map[string][]string, error) {
	return f.resolve(ctx, vars)
}

// registerFakeProviderType registers p under a type name unique to the
// calling test, since datasources.Register is a process-wide registry a
// shared literal name could collide on.
func registerFakeProviderType(t *testing.T, p datasources.Provider) string {
	t.Helper()
	typeName := "rules-fake:" + t.Name()
	datasources.Register(typeName, func(name string, raw yaml.Node) (datasources.Provider, error) {
		return p, nil
	})
	return typeName
}

// newDatasourceSet builds a *datasources.Set from cfgs (empty/nil for the
// "zero datasources configured" contract test).
func newDatasourceSet(t *testing.T, cfgs ...datasources.Config) *datasources.Set {
	t.Helper()
	logger, _ := newTestLogger(t)
	set, err := datasources.NewSet(cfgs, logger)
	require.NoError(t, err)
	return set
}

// # request body fixtures

// containerCreateBody builds a /containers/create request body whose
// HostConfig carries paths as legacy "src:dst" Binds entries.
func containerCreateBody(t *testing.T, paths ...string) []byte {
	t.Helper()
	binds := make([]string, len(paths))
	for i, p := range paths {
		binds[i] = fmt.Sprintf("%s:/mnt%d", p, i)
	}
	return marshalJSON(t, map[string]any{
		"Image":      "alpine",
		"HostConfig": map[string]any{"Binds": binds},
	})
}

// hostConfigBody builds a /containers/create body with an arbitrary
// HostConfig subset.
func hostConfigBody(t *testing.T, hostConfig map[string]any) []byte {
	t.Helper()
	return marshalJSON(t, map[string]any{
		"Image":      "alpine",
		"HostConfig": hostConfig,
	})
}

// volumeCreateBindBody builds a /volumes/create body recognized as a
// local-driver bind-mount-passthrough.
func volumeCreateBindBody(t *testing.T, device string) []byte {
	t.Helper()
	return marshalJSON(t, map[string]any{
		"Name":       "leakvol",
		"DriverOpts": map[string]string{"type": "none", "o": "bind", "device": device},
	})
}

// volumeCreatePlainBody builds a plain named-volume body with no
// DriverOpts - not recognized as bind-style.
func volumeCreatePlainBody(t *testing.T) []byte {
	t.Helper()
	return marshalJSON(t, map[string]any{"Name": "myvol"})
}

func marshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err, "marshal fixture body")
	return b
}

const (
	containerCreateURI = "/v1.43/containers/create"
	volumeCreateURI    = "/v1.43/volumes/create"
	dockerCPURI        = "/v1.43/containers/abc123/archive"
	dockerExecURI      = "/v1.43/containers/abc123/exec"
	notAContainerURI   = "/v1.43/containers/json" // an irrelevant, unrelated endpoint
)

// # metrics: a Chain wired to an isolated in-memory OTel reader

// newTestChain builds a Chain like NewChain does, but with counters wired to
// an isolated ManualReader instead of internal/telemetry's process-wide
// singleton, so test runs don't accumulate onto one shared global counter.
func newTestChain(t *testing.T, logger *slog.Logger, rules ...Rule) (*Chain, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := mp.Meter("github.com/weishiuchang/authzmtls")

	requests, err := meter.Int64Counter(requestsInstrumentName, otelmetric.WithUnit("1"))
	require.NoError(t, err, "Int64Counter(%s)", requestsInstrumentName)
	denied, err := meter.Int64Counter(deniedInstrumentName, otelmetric.WithUnit("1"))
	require.NoError(t, err, "Int64Counter(%s)", deniedInstrumentName)

	return &Chain{rules: rules, logger: logger, requests: requests, denied: denied}, reader
}

// counterSum reads the current summed value of the Int64Counter named name.
func counterSum(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				return 0
			}
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			return total
		}
	}
	return 0
}

// req builds the recurring dockerapi.AuthZReq shape these tests need.
func req(user, method, uri string, body []byte) *dockerapi.AuthZReq {
	return &dockerapi.AuthZReq{
		User:          user,
		RequestMethod: method,
		RequestURI:    uri,
		RequestBody:   body,
	}
}
