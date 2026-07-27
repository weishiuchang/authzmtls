// Package telemetry sets up authzmtls's OpenTelemetry metrics stack and
// serves it as a Prometheus-scrapeable /metrics endpoint
// (server.metrics_path).
//
// Every instrumented package (dockerapi, datasources, rules) codes against
// go.opentelemetry.io/otel's vendor-neutral API, never a Prometheus-specific
// package directly:
//
//   - go.opentelemetry.io/otel + otel/sdk/metric - the API/SDK
//     instrumentation is written against.
//   - go.opentelemetry.io/otel/exporters/prometheus - the Reader that turns
//     /metrics into a pull endpoint.
//   - go.opentelemetry.io/contrib/instrumentation/runtime (optional) -
//     standard Go runtime metrics registered on the same MeterProvider.
//
// # Public surface
//
//   - MeterProvider() metric.MeterProvider - the one process-wide
//     provider, built once via sync.Once and shared by every caller.
//   - Handler() http.Handler - the Prometheus-exposition handler; mounted
//     by internal/server at server.metrics_path.
//   - Meter() metric.Meter - the single shared Meter every instrumented
//     package pulls instruments from.
//   - Shutdown(ctx) error - flushes and releases the MeterProvider at
//     graceful shutdown; a no-op if telemetry was never used.
//
// # Instrument set (canonical reference - names, types, units)
//
// Every instrument is created by the package that records it, not by this
// package; telemetry only provides Meter(). Names are dot-namespaced with
// units carried via metric.WithUnit (never baked into the name), and
// monotonic increase is conveyed by using a Counter, never an
// UpDownCounter or a "_total" name hint.
//
//   - Meter().Int64Counter("authzmtls.requests", metric.WithUnit("1"))
//     (recorded by internal/rules) - every request the rule chain reaches
//     an explicit verdict on; abstained traffic does not increment this.
//   - Meter().Int64Counter("authzmtls.denied", metric.WithUnit("1"))
//     (recorded by internal/rules) - the subset of the above that were
//     denials. No labels for now.
//   - Meter().Float64Histogram("authzmtls.latency", metric.WithUnit("ms"))
//     (recorded by internal/dockerapi) - end-to-end latency for every
//     request regardless of outcome.
//   - Meter().Int64Counter("authzmtls.datasource.cache.hits",
//     metric.WithUnit("1")) / Meter().Int64Counter("authzmtls.datasource.cache.misses",
//     metric.WithUnit("1")) (recorded by internal/datasources, labeled by
//     datasource name/type).
//   - Meter().Int64UpDownCounter("authzmtls.datasource.inflight",
//     metric.WithUnit("1")) (recorded by internal/datasources) - a genuine
//     up/down count; the Prometheus exporter maps it to a gauge.
//   - Meter().Float64Histogram("authzmtls.datasource.resolve.duration",
//     metric.WithUnit("ms")) (recorded by internal/datasources, labeled
//     cache-hit/cache-miss) - a more granular latency metric alongside
//     authzmtls.latency.
//
// # Confirmed scraped Prometheus names
//
// Verified 2026-07-24 against the real exporter (see
// TestHandlerServesPrometheusExposition in telemetry_test.go; re-run that
// test if the exporter version changes):
//
//	OTel instrument name                    Type            Scraped Prometheus name(s)
//	authzmtls.requests                      Int64Counter    authzmtls_requests_total
//	authzmtls.denied                        Int64Counter    authzmtls_denied_total
//	authzmtls.latency                       Float64Histogram authzmtls_latency_milliseconds{_bucket,_sum,_count}
//	authzmtls.datasource.cache.hits         Int64Counter    authzmtls_datasource_cache_hits_total
//	authzmtls.datasource.cache.misses       Int64Counter    authzmtls_datasource_cache_misses_total
//	authzmtls.datasource.inflight           Int64UpDownCounter authzmtls_datasource_inflight (gauge; no _total suffix)
//	authzmtls.datasource.resolve.duration   Float64Histogram authzmtls_datasource_resolve_duration_milliseconds{_bucket,_sum,_count}
//
// Dots become underscores, Counters gain "_total", UpDownCounters (mapped
// to gauges) do not, and the "ms" unit is spelled "_milliseconds" on
// histogram names. Every sample also carries
// otel_scope_name/otel_scope_schema_url/otel_scope_version labels plus any
// instrument-specific attributes.
package telemetry

import (
	"context"
	"net/http"
	"sync"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	otelruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// scopeName identifies this codebase's own metrics in the OTel data
// model, analogous to a logger name.
const scopeName = "github.com/weishiuchang/authzmtls"

// Package-level state, built exactly once by initOnce (see ensureInit) and
// shared by every caller for the process lifetime. sync.Once (rather than
// init()) gets lazy, single construction without import-order assumptions.
var (
	initOnce      sync.Once
	meterProvider *sdkmetric.MeterProvider
	promHandler   http.Handler
	sharedMeter   metric.Meter
)

// ensureInit builds a fresh prometheus.Registry (never the global
// DefaultRegisterer, to avoid colliding with anything else in the
// binary/test process), the OTel Prometheus Reader/exporter, the shared
// MeterProvider/Handler/Meter, and best-effort Go runtime metrics.
//
// A failure from otelprometheus.New here is unreachable in practice (the
// registry is always empty) and would mean the wiring itself is broken, so
// this panics rather than threading an error through
// MeterProvider/Handler/Meter's signatures.
func ensureInit() {
	initOnce.Do(func() {
		reg := promclient.NewRegistry()

		exporter, err := otelprometheus.New(otelprometheus.WithRegisterer(reg))
		if err != nil {
			panic("telemetry: failed to construct prometheus exporter/reader: " + err.Error())
		}

		meterProvider = newMeterProvider(exporter)
		promHandler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
		sharedMeter = meterProvider.Meter(scopeName)

		// Best-effort: runtime metrics are a nice-to-have, so a failure
		// here must not block MeterProvider/Handler/Meter from becoming
		// usable.
		_ = otelruntime.Start(otelruntime.WithMeterProvider(meterProvider))
	})
}

// newMeterProvider builds a MeterProvider wired to the given Reader(s).
// Factored out of ensureInit so tests can reuse the exact construction
// path against an in-memory ManualReader.
func newMeterProvider(readers ...sdkmetric.Reader) *sdkmetric.MeterProvider {
	opts := make([]sdkmetric.Option, 0, len(readers))
	for _, r := range readers {
		opts = append(opts, sdkmetric.WithReader(r))
	}
	return sdkmetric.NewMeterProvider(opts...)
}

// MeterProvider returns the process-wide MeterProvider, constructing it on
// first call. Every call returns the same instance.
func MeterProvider() metric.MeterProvider {
	ensureInit()
	return meterProvider
}

// Handler returns the Prometheus-exposition handler for everything
// recorded through Meter(). internal/server mounts it at
// server.metrics_path; this package knows nothing about routing beyond
// producing the handler.
func Handler() http.Handler {
	ensureInit()
	return promHandler
}

// Meter returns the single shared Meter every package instruments through;
// every call returns the same instance. This package intentionally does
// not construct the instruments themselves - see doc.go's instrument list.
func Meter() metric.Meter {
	ensureInit()
	return sharedMeter
}

// Shutdown flushes and releases the MeterProvider, if one was ever
// constructed. Call it after Server.Shutdown drains in-flight requests, so
// their recorded metrics aren't dropped before process exit.
//
// A process that never touched telemetry has nothing to flush; Shutdown is
// then a safe no-op.
func Shutdown(ctx context.Context) error {
	if meterProvider == nil {
		return nil
	}
	return meterProvider.Shutdown(ctx)
}
