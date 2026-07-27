# Metrics

authzmtls records metrics through [OpenTelemetry](https://opentelemetry.io/)
(`internal/telemetry`) and serves them at
`server.metrics_path` (default `/metrics`).

## Request/decision metrics

| Scraped name | OTel instrument | Type (scraped as) | Labels | What it measures |
|---|---|---|---|---|
| `authzmtls_requests_total` | `authzmtls.requests` (`Int64Counter`) | counter | none | Every allow/deny request. Pass-through does not count in this |
| `authzmtls_denied_total` | `authzmtls.denied` (`Int64Counter`) | counter | none | The subset of the above that were denials. |
| `authzmtls_latency_milliseconds_bucket` / `_sum` / `_count` | `authzmtls.latency` (`Float64Histogram`, unit `ms`) | histogram | none | End-to-end latency (request received -> response sent) for **every** request regardless of outcome, including pass-through. |

## Datasource metrics

Metrics as recorded by data sources (currently only ldap).

| Scraped name | OTel instrument | Type (scraped as) | Labels | What it measures |
|---|---|---|---|---|
| `authzmtls_datasource_cache_hits_total` | `authzmtls.datasource.cache.hits` (`Int64Counter`) | counter | `datasource` (config's `name`), `type` (e.g. `ldap`) | `$IDENTITY` resolutions served from the TTL cache without an upstream call. |
| `authzmtls_datasource_cache_misses_total` | `authzmtls.datasource.cache.misses` (`Int64Counter`) | counter | `datasource`, `type` | Lookups that required a sync backend call. |
| `authzmtls_datasource_inflight` | `authzmtls.datasource.inflight` (`Int64UpDownCounter`) | gauge (no `_total` suffix - UpDownCounters map to a Prometheus gauge, not a counter) | `datasource`, `type` | Live backend calls currently in flight for this datasource. |
| `authzmtls_datasource_resolve_duration_milliseconds_bucket` / `_sum` / `_count` | `authzmtls.datasource.resolve.duration` (`Float64Histogram`, unit `ms`) | histogram | `datasource`, `type`, `result` (`"hit"` or `"miss"`) | Wall-clock duration of one `Resolve` call, split by whether it was served from cache (`result="hit"`, should be near-zero) or required a live backend round-trip (`result="miss"`, tracks actual LDAP/directory latency). |
