package datasources

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/singleflight"
)

// identityVar is the only vars key the cache/singleflight decorator keys
// on; other entries ride along to a live call unchanged but don't affect
// caching.
const identityVar = "IDENTITY"

const (
	// defaultCacheTTL is Config.CacheTTL's default. It's a refresh
	// interval, not a hard expiration - see cachedProvider.Resolve.
	defaultCacheTTL = 10 * time.Minute

	// defaultNegativeCacheTTL bounds how long a never-resolved identity is
	// remembered as failed before retrying live. Deliberately short and
	// not operator-configurable - its only job is to stop a struggling
	// backend from being hammered, not to behave like a real cache entry.
	defaultNegativeCacheTTL = 30 * time.Second

	// defaultCacheSize bounds distinct identities held in memory at once,
	// evicting least-recently-used entries past this bound - large enough
	// for real use, small enough to bound a flood of fabricated identities.
	defaultCacheSize = 4096
)

// errUnresolved is returned whenever an identity has no value to offer
// (failed sanitization, a failed live fetch with nothing to fall back on,
// or still inside a negative-cache window). It carries no backend detail by
// construction - Set.Resolve only ever checks it for nilness.
var errUnresolved = errors.New("datasources: identity did not resolve")

// cacheEntry is immutable once published into the LRU: every update
// constructs a fresh *cacheEntry and swaps it in, rather than mutating one
// in place, so concurrent reads stay race-free without their own lock.
type cacheEntry struct {
	value     map[string][]string // last known-good value; meaningful only when hasValue
	hasValue  bool                // true once any live call has ever succeeded for this identity
	fetchedAt time.Time           // when value was last (re)confirmed by a successful live call
	negUntil  time.Time           // negative-cache expiry; zero means "not currently negative-cached"
}

// servedFresh reports whether e can answer without a live fetch: a fresh
// positive entry returns its value, a still-negative-cached entry returns
// errUnresolved, and anything else means the caller must go live.
func (e *cacheEntry) servedFresh(now time.Time, ttl time.Duration) (value map[string][]string, err error, served bool) {
	switch {
	case e.hasValue && now.Sub(e.fetchedAt) < ttl:
		return e.value, nil, true
	case !e.hasValue && !e.negUntil.IsZero() && now.Before(e.negUntil):
		return nil, errUnresolved, true
	default:
		return nil, nil, false
	}
}

// cachedProvider is the generic cache+singleflight decorator every
// registered Provider gets wrapped in, coalescing concurrent same-identity
// calls into one live Resolve.
//
// CacheTTL is a refresh interval, not a hard expiration: a failed refresh
// keeps serving a stale value if one exists, otherwise negative-caches
// briefly; there is no background refresh, only on-demand.
type cachedProvider struct {
	name, typ string
	ttl       time.Duration // refresh interval (Config.CacheTTL, defaulted)
	negTTL    time.Duration
	provider  Provider
	logger    *slog.Logger
	now       func() time.Time // injected for deterministic tests; time.Now in production
	cache     *expirable.LRU[string, *cacheEntry]
	group     singleflight.Group
	metrics   *datasourceMetrics
}

// newCachedProvider builds the production cache+singleflight wrapper NewSet
// calls for every configured datasource.
func newCachedProvider(name, typ string, cacheTTL time.Duration, provider Provider, logger *slog.Logger) (*cachedProvider, error) {
	return newCachedProviderWithClock(name, typ, cacheTTL, defaultNegativeCacheTTL, provider, logger, time.Now)
}

// newCachedProviderWithClock exposes negTTL and the clock as parameters so
// this package's tests can shrink the negative-cache window and fast-forward
// "now" without real sleeps; production always goes through
// newCachedProvider, which pins both to their real values.
func newCachedProviderWithClock(name, typ string, cacheTTL, negTTL time.Duration, provider Provider, logger *slog.Logger, now func() time.Time) (*cachedProvider, error) {
	if cacheTTL <= 0 {
		cacheTTL = defaultCacheTTL
	}
	if logger == nil {
		logger = slog.Default()
	}

	metrics, err := newDatasourceMetrics()
	if err != nil {
		return nil, err
	}

	return &cachedProvider{
		name:     name,
		typ:      typ,
		ttl:      cacheTTL,
		negTTL:   negTTL,
		provider: provider,
		logger:   logger,
		now:      now,
		// ttl=0 disables the LRU's own time-based eviction - CacheTTL must
		// NOT delete entries; "due for refresh" is tracked by hand in
		// servedFresh instead.
		cache:   expirable.NewLRU[string, *cacheEntry](defaultCacheSize, nil, 0),
		metrics: metrics,
	}, nil
}

// Resolve implements Provider; only vars[identityVar] participates in
// caching, other entries pass through to a live call unchanged. An empty
// identity is handled defensively here too, so cachedProvider stays correct
// when driven directly, outside a Set.
func (c *cachedProvider) Resolve(ctx context.Context, vars map[string]string) (map[string][]string, error) {
	identity := vars[identityVar]
	if identity == "" {
		return nil, errUnresolved
	}

	start := c.now()
	if e, ok := c.cache.Get(identity); ok {
		if value, err, served := e.servedFresh(c.now(), c.ttl); served {
			c.metrics.recordHit(ctx, c.name, c.typ)
			c.metrics.recordDuration(ctx, c.name, c.typ, "hit", msSince(start, c.now()))
			return value, err
		}
	}

	// Cache miss or due-for-refresh: singleflight collapses concurrent
	// callers for this identity into the one call below.
	c.metrics.recordMiss(ctx, c.name, c.typ)
	v, err, _ := c.group.Do(identity, func() (any, error) {
		return c.refresh(ctx, identity, vars)
	})
	c.metrics.recordDuration(ctx, c.name, c.typ, "miss", msSince(start, c.now()))

	if err != nil {
		return nil, err
	}
	return v.(map[string][]string), nil
}

// refresh performs the one live Provider.Resolve call singleflight
// coalesces concurrent callers into; only ever invoked from inside
// c.group.Do, so at most one refresh for a given identity runs at a time.
func (c *cachedProvider) refresh(ctx context.Context, identity string, vars map[string]string) (map[string][]string, error) {
	c.metrics.addInflight(ctx, c.name, c.typ, 1)
	defer c.metrics.addInflight(ctx, c.name, c.typ, -1)

	prev, _ := c.cache.Get(identity) // nil if this identity has never been seen
	result, err := c.provider.Resolve(ctx, vars)
	now := c.now()

	if err == nil {
		c.cache.Add(identity, &cacheEntry{value: result, hasValue: true, fetchedAt: now})
		return result, nil
	}

	// This WARN fires exactly once per real backend failure (coalesced
	// callers included), never for a cached negative/stale read - those
	// never reach refresh.
	c.logger.WarnContext(ctx, "datasource resolution attempt failed",
		"datasource", c.name,
		"datasource_type", c.typ,
		"identity", identity,
		"error", err,
	)

	if prev != nil && prev.hasValue {
		// Stale-while-revalidate: keep serving the last known-good value.
		// fetchedAt is deliberately not updated, so the entry stays due
		// for refresh and the very next request retries immediately.
		return prev.value, nil
	}

	// Negative caching: no prior value to fall back to, so this is the one
	// case where a failure actually produces "unresolved" rather than a
	// stale-but-usable answer.
	c.cache.Add(identity, &cacheEntry{negUntil: now.Add(c.negTTL)})
	return nil, errUnresolved
}

// Flush discards every cached entry immediately, for SIGHUP's cache-flush
// behavior. It never touches c.provider's own connection/pool state.
func (c *cachedProvider) Flush() {
	c.cache.Purge()
}

func msSince(start, end time.Time) float64 {
	return float64(end.Sub(start)) / float64(time.Millisecond)
}
