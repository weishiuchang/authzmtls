package datasources

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/weishiuchang/authzmtls/internal/telemetry"
)

// datasourceMetrics is the set of instruments every cache+singleflight
// decorator records into, constructed once per decorator. Per-datasource
// identity comes from attributes (name/type), not a separate instrument per
// provider - OTel instruments are long-lived handles safely shared across
// multiple Meter() calls with the same name/unit.
type datasourceMetrics struct {
	hits     metric.Int64Counter
	misses   metric.Int64Counter
	inflight metric.Int64UpDownCounter
	duration metric.Float64Histogram
}

// newDatasourceMetrics builds the four instruments using the exact
// names/units internal/telemetry's contract specifies, depending only on
// telemetry.Meter()'s public API.
func newDatasourceMetrics() (*datasourceMetrics, error) {
	meter := telemetry.Meter()

	hits, err := meter.Int64Counter("authzmtls.datasource.cache.hits", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	misses, err := meter.Int64Counter("authzmtls.datasource.cache.misses", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	inflight, err := meter.Int64UpDownCounter("authzmtls.datasource.inflight", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	duration, err := meter.Float64Histogram("authzmtls.datasource.resolve.duration", metric.WithUnit("ms"))
	if err != nil {
		return nil, err
	}

	return &datasourceMetrics{hits: hits, misses: misses, inflight: inflight, duration: duration}, nil
}

// labels builds the datasource/type attribute pair shared by every
// instrument below.
func labels(name, typ string) metric.MeasurementOption {
	return metric.WithAttributes(
		attribute.String("datasource", name),
		attribute.String("type", typ),
	)
}

func (m *datasourceMetrics) recordHit(ctx context.Context, name, typ string) {
	m.hits.Add(ctx, 1, labels(name, typ))
}

func (m *datasourceMetrics) recordMiss(ctx context.Context, name, typ string) {
	m.misses.Add(ctx, 1, labels(name, typ))
}

func (m *datasourceMetrics) addInflight(ctx context.Context, name, typ string, delta int64) {
	m.inflight.Add(ctx, delta, labels(name, typ))
}

// recordDuration records one Resolve call's duration, labeled by outcome
// ("hit"/"miss") so a dashboard can separate cache speed from live backend
// latency.
func (m *datasourceMetrics) recordDuration(ctx context.Context, name, typ, outcome string, ms float64) {
	m.duration.Record(ctx, ms,
		metric.WithAttributes(
			attribute.String("datasource", name),
			attribute.String("type", typ),
			attribute.String("result", outcome),
		),
	)
}
