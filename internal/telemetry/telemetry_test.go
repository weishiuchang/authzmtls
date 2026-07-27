package telemetry

import (
	"context"
	"io"
	"net/http/httptest"
	"reflect"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestSingletonAccessors verifies MeterProvider/Handler/Meter each return
// the same instance on every call.
func TestSingletonAccessors(t *testing.T) {
	mp1, mp2 := MeterProvider(), MeterProvider()
	assert.Same(t, mp1, mp2, "MeterProvider() returned different instances across calls")

	m1, m2 := Meter(), Meter()
	assert.Same(t, m1, m2, "Meter() returned different instances across calls")

	h1, h2 := Handler(), Handler()
	require.NotNil(t, h1, "Handler() returned nil")
	require.NotNil(t, h2, "Handler() returned nil")
	// promhttp's handler type may not be == comparable, so compare
	// identity via reflect.Value.Pointer instead.
	assert.Equal(t, reflect.ValueOf(h1).Pointer(), reflect.ValueOf(h2).Pointer(),
		"Handler() returned different instances across calls")
}

// buildInstruments creates the instrument set documented in doc.go against
// the given Meter, shared by TestInstrumentSet and
// TestHandlerServesPrometheusExposition so both exercise identical
// definitions.
type instrumentSet struct {
	requests        metric.Int64Counter
	denied          metric.Int64Counter
	latency         metric.Float64Histogram
	cacheHits       metric.Int64Counter
	cacheMisses     metric.Int64Counter
	inflight        metric.Int64UpDownCounter
	resolveDuration metric.Float64Histogram
}

func buildInstruments(t *testing.T, m metric.Meter) instrumentSet {
	t.Helper()

	requests, err := m.Int64Counter("authzmtls.requests", metric.WithUnit("1"))
	require.NoError(t, err, "Int64Counter(authzmtls.requests)")
	denied, err := m.Int64Counter("authzmtls.denied", metric.WithUnit("1"))
	require.NoError(t, err, "Int64Counter(authzmtls.denied)")
	latency, err := m.Float64Histogram("authzmtls.latency", metric.WithUnit("ms"))
	require.NoError(t, err, "Float64Histogram(authzmtls.latency)")
	cacheHits, err := m.Int64Counter("authzmtls.datasource.cache.hits", metric.WithUnit("1"))
	require.NoError(t, err, "Int64Counter(authzmtls.datasource.cache.hits)")
	cacheMisses, err := m.Int64Counter("authzmtls.datasource.cache.misses", metric.WithUnit("1"))
	require.NoError(t, err, "Int64Counter(authzmtls.datasource.cache.misses)")
	inflight, err := m.Int64UpDownCounter("authzmtls.datasource.inflight", metric.WithUnit("1"))
	require.NoError(t, err, "Int64UpDownCounter(authzmtls.datasource.inflight)")
	resolveDuration, err := m.Float64Histogram("authzmtls.datasource.resolve.duration", metric.WithUnit("ms"))
	require.NoError(t, err, "Float64Histogram(authzmtls.datasource.resolve.duration)")

	return instrumentSet{
		requests:        requests,
		denied:          denied,
		latency:         latency,
		cacheHits:       cacheHits,
		cacheMisses:     cacheMisses,
		inflight:        inflight,
		resolveDuration: resolveDuration,
	}
}

func (s instrumentSet) record(ctx context.Context) {
	dsAttrs := metric.WithAttributes(attribute.String("name", "ldap1"), attribute.String("type", "ldap"))
	s.requests.Add(ctx, 5)
	s.denied.Add(ctx, 2)
	s.latency.Record(ctx, 12.5)
	s.cacheHits.Add(ctx, 3, dsAttrs)
	s.cacheMisses.Add(ctx, 1, dsAttrs)
	s.inflight.Add(ctx, 4)
	s.inflight.Add(ctx, -1) // net 3
	s.resolveDuration.Record(ctx, 7.0, metric.WithAttributes(attribute.Bool("cache_hit", true)))
}

// TestInstrumentSet records against an in-memory ManualReader and asserts
// the collected metricdata matches, the OTel-native counterpart to
// TestHandlerServesPrometheusExposition.
func TestInstrumentSet(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := newMeterProvider(reader)
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	m := mp.Meter(scopeName)
	instruments := buildInstruments(t, m)
	ctx := context.Background()
	instruments.record(ctx)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &rm), "Collect")

	require.Len(t, rm.ScopeMetrics, 1, "expected 1 ScopeMetrics")
	sm := rm.ScopeMetrics[0]
	assert.Equal(t, scopeName, sm.Scope.Name, "scope name")

	byName := make(map[string]metricdata.Metrics, len(sm.Metrics))
	for _, dm := range sm.Metrics {
		byName[dm.Name] = dm
	}

	wantNames := []string{
		"authzmtls.requests",
		"authzmtls.denied",
		"authzmtls.latency",
		"authzmtls.datasource.cache.hits",
		"authzmtls.datasource.cache.misses",
		"authzmtls.datasource.inflight",
		"authzmtls.datasource.resolve.duration",
	}
	for _, name := range wantNames {
		assert.Contains(t, byName, name, "missing instrument in collected metrics")
	}

	assertInt64Sum := func(name string, want int64) {
		dm, ok := byName[name]
		if !ok {
			return
		}
		sum, ok := dm.Data.(metricdata.Sum[int64])
		if !assert.True(t, ok, "%s: data type = %T, want metricdata.Sum[int64]", name, dm.Data) {
			return
		}
		if !assert.NotEmpty(t, sum.DataPoints, "%s: no data points", name) {
			return
		}
		var got int64
		for _, dp := range sum.DataPoints {
			got += dp.Value
		}
		assert.Equal(t, want, got, "%s: sum", name)
	}

	assertInt64Sum("authzmtls.requests", 5)
	assertInt64Sum("authzmtls.denied", 2)
	assertInt64Sum("authzmtls.datasource.cache.hits", 3)
	assertInt64Sum("authzmtls.datasource.cache.misses", 1)
	assertInt64Sum("authzmtls.datasource.inflight", 3)

	if dm, ok := byName["authzmtls.latency"]; ok {
		hist, ok := dm.Data.(metricdata.Histogram[float64])
		if assert.True(t, ok, "authzmtls.latency: data type = %T, want metricdata.Histogram[float64]", dm.Data) {
			assert.True(t, len(hist.DataPoints) == 1 && hist.DataPoints[0].Count == 1 && hist.DataPoints[0].Sum == 12.5,
				"authzmtls.latency: unexpected histogram data points %+v", hist.DataPoints)
		}
		assert.Equal(t, "ms", dm.Unit, "authzmtls.latency: unit")
	}

	if dm, ok := byName["authzmtls.datasource.resolve.duration"]; ok {
		hist, ok := dm.Data.(metricdata.Histogram[float64])
		if assert.True(t, ok, "authzmtls.datasource.resolve.duration: data type = %T, want metricdata.Histogram[float64]", dm.Data) {
			assert.True(t, len(hist.DataPoints) == 1 && hist.DataPoints[0].Count == 1 && hist.DataPoints[0].Sum == 7.0,
				"authzmtls.datasource.resolve.duration: unexpected histogram data points %+v", hist.DataPoints)
		}
	}
}

// TestHandlerServesPrometheusExposition records the full instrument set
// through the real production singleton, scrapes Handler(), and asserts
// the recorded values appear. It also t.Logs the body so scraped names can
// be cross-checked against doc.go's canonical instrument table.
func TestHandlerServesPrometheusExposition(t *testing.T) {
	m := Meter()
	instruments := buildInstruments(t, m)
	instruments.record(context.Background())

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, 200, resp.StatusCode, "Handler() response status")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "reading response body")
	text := string(body)
	t.Logf("scraped Prometheus exposition:\n%s", text)

	// Every sample line carries extra labels, so match
	// "<metric>{...} <value>" rather than an exact substring.
	assertSample := func(metricName string, value string) {
		t.Helper()
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(metricName) + `\{[^}]*\} ` + regexp.QuoteMeta(value) + `$`)
		assert.Regexp(t, re, text, "exposition missing expected %s sample = %s", metricName, value)
	}

	assertSample("authzmtls_requests_total", "5")
	assertSample("authzmtls_denied_total", "2")
	assertSample("authzmtls_datasource_inflight", "3")
	assert.Contains(t, text, `name="ldap1"`, "exposition missing expected datasource cache labels")
	assert.Contains(t, text, `type="ldap"`, "exposition missing expected datasource cache labels")
}
