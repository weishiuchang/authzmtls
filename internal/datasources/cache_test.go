package datasources

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachedProvider_CacheHitAvoidsSecondResolve(t *testing.T) {
	fp := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"USER": {"alice"}}, nil
	}}
	cp, err := newCachedProviderWithClock("ds1", "fake", time.Minute, 5*time.Second, fp, testLoggerSimple(t), time.Now)
	require.NoError(t, err, "newCachedProviderWithClock")

	vars := map[string]string{"IDENTITY": "cn=alice"}
	want := map[string][]string{"USER": {"alice"}}
	for i := 0; i < 3; i++ {
		got, err := cp.Resolve(context.Background(), vars)
		require.NoError(t, err, "call %d", i)
		require.Equal(t, want, got, "call %d", i)
	}
	assert.Equal(t, 1, fp.callCount(), "expected exactly 1 live Resolve call across 3 requests (cache hit avoiding the rest)")
}

func TestCachedProvider_SingleflightCoalescing(t *testing.T) {
	gate := make(chan struct{})
	fp := &fakeProvider{
		gate: gate,
		resolve: func(context.Context, map[string]string) (map[string][]string, error) {
			return map[string][]string{"USER": {"bob"}}, nil
		},
	}
	cp, err := newCachedProviderWithClock("ds", "fake", time.Minute, time.Second, fp, testLoggerSimple(t), time.Now)
	require.NoError(t, err, "newCachedProviderWithClock")

	const n = 25
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, errs[i] = cp.Resolve(context.Background(), map[string]string{"IDENTITY": "cn=bob"})
		}()
	}

	// Give every goroutine time to reach the blocked call, so this proves
	// real concurrent coalescing, not lucky sequential timing.
	time.Sleep(100 * time.Millisecond)
	close(gate)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d", i)
	}
	assert.Equal(t, 1, fp.callCount(), "expected singleflight to coalesce %d concurrent same-identity requests into exactly 1 live call", n)
}

func TestCachedProvider_ContextDeadlineExceededTreatedAsFailure(t *testing.T) {
	fp := &fakeProvider{
		delay: 100 * time.Millisecond,
		resolve: func(context.Context, map[string]string) (map[string][]string, error) {
			return map[string][]string{"USER": {"slow"}}, nil
		},
	}
	logger, handler := newTestLogger(t)
	cp, err := newCachedProviderWithClock("ds", "fake", time.Minute, time.Second, fp, logger, time.Now)
	require.NoError(t, err, "newCachedProviderWithClock")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = cp.Resolve(ctx, map[string]string{"IDENTITY": "cn=deadline"})
	require.Error(t, err, "expected a deadline-exceeded live call to be treated as an ordinary resolution failure, not succeed")
	require.ErrorIs(t, err, errUnresolved, "expected the no-prior-value/negative-cache path (errUnresolved)")
	// Confirms deadline-exceeded gets the same WARN path as any other
	// backend failure, no special-casing.
	assert.True(t, handler.hasRecordWithMessage("datasource resolution attempt failed"), "expected the deadline-exceeded live attempt to log the standard live-resolution-failure WARN")
}

func TestCachedProvider_NegativeCacheTTL(t *testing.T) {
	var succeed int32
	fp := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		if atomic.LoadInt32(&succeed) == 1 {
			return map[string][]string{"USER": {"z"}}, nil
		}
		return nil, errors.New("backend unavailable")
	}}
	clock := newFakeClock(time.Now())
	cp, err := newCachedProviderWithClock("ds", "fake", time.Hour, 100*time.Millisecond, fp, testLoggerSimple(t), clock.Now)
	require.NoError(t, err, "newCachedProviderWithClock")

	vars := map[string]string{"IDENTITY": "cn=neg"}

	_, err = cp.Resolve(context.Background(), vars)
	require.Error(t, err, "expected the first resolve to fail")
	assert.Equal(t, 1, fp.callCount(), "expected 1 live call after the first failure")

	// Still inside the negative-cache window: must not trigger another live call.
	_, err = cp.Resolve(context.Background(), vars)
	require.Error(t, err, "expected the negative-cached identity to still read as unresolved")
	assert.Equal(t, 1, fp.callCount(), "expected the negative-cache hit to avoid a second live call")

	// Cross the negative-cache TTL: the next request must go live again.
	clock.Advance(200 * time.Millisecond)
	atomic.StoreInt32(&succeed, 1)
	got, err := cp.Resolve(context.Background(), vars)
	require.NoError(t, err, "expected resolution to succeed once the negative-cache window expires")
	require.Equal(t, map[string][]string{"USER": {"z"}}, got, "unexpected result after negative-cache expiry")
	assert.Equal(t, 2, fp.callCount(), "expected exactly 2 live calls total (initial failure + post-expiry retry)")
}

func TestCachedProvider_StaleWhileRevalidate(t *testing.T) {
	var fail int32
	fp := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		if atomic.LoadInt32(&fail) == 1 {
			return nil, errors.New("backend down")
		}
		return map[string][]string{"GROUP": {"eng"}}, nil
	}}
	clock := newFakeClock(time.Now())
	cp, err := newCachedProviderWithClock("ds", "fake", 10*time.Millisecond, time.Second, fp, testLoggerSimple(t), clock.Now)
	require.NoError(t, err, "newCachedProviderWithClock")

	vars := map[string]string{"IDENTITY": "cn=stale"}
	first, err := cp.Resolve(context.Background(), vars)
	require.NoError(t, err, "expected initial resolve to succeed")
	require.Equal(t, map[string][]string{"GROUP": {"eng"}}, first, "unexpected initial value")

	// Age past CacheTTL so the next call is due for refresh, then make the
	// refresh itself fail.
	clock.Advance(20 * time.Millisecond)
	atomic.StoreInt32(&fail, 1)
	second, err := cp.Resolve(context.Background(), vars)
	require.NoError(t, err, "stale-while-revalidate: expected the previous value on a failed refresh")
	require.Equal(t, map[string][]string{"GROUP": {"eng"}}, second, "expected the stale value to be preserved")
	assert.Equal(t, 2, fp.callCount(), "expected the due-for-refresh call to actually attempt a live fetch")
}

func TestCachedProvider_NegativeCachingWhenNoPriorValue(t *testing.T) {
	fp := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return nil, errors.New("this identity never resolves")
	}}
	cp, err := newCachedProviderWithClock("ds", "fake", time.Minute, time.Second, fp, testLoggerSimple(t), time.Now)
	require.NoError(t, err, "newCachedProviderWithClock")

	_, err = cp.Resolve(context.Background(), map[string]string{"IDENTITY": "cn=neverfound"})
	require.Error(t, err, "expected an identity with no prior successful value to come back unresolved on a failed fetch (negative caching, distinct from stale-while-revalidate)")
}

func TestCachedProvider_FlushForcesReresolveWithoutTouchingProviderState(t *testing.T) {
	fp := &fakeProvider{
		poolOpen: true,
		resolve: func(context.Context, map[string]string) (map[string][]string, error) {
			return map[string][]string{"USER": {"f"}}, nil
		},
	}
	cp, err := newCachedProviderWithClock("ds", "fake", time.Hour, time.Second, fp, testLoggerSimple(t), time.Now)
	require.NoError(t, err, "newCachedProviderWithClock")

	vars := map[string]string{"IDENTITY": "cn=flush"}
	_, err = cp.Resolve(context.Background(), vars)
	require.NoError(t, err, "first resolve")
	_, err = cp.Resolve(context.Background(), vars)
	require.NoError(t, err, "second resolve (should be a cache hit)")
	assert.Equal(t, 1, fp.callCount(), "expected 1 live call before Flush")

	cp.Flush()

	assert.True(t, fp.poolOpen, "Flush must not touch the underlying provider's own connection/pool state")

	_, err = cp.Resolve(context.Background(), vars)
	require.NoError(t, err, "resolve after flush")
	assert.Equal(t, 2, fp.callCount(), "expected Flush to force a fresh live call on the next request")
}

func TestCachedProvider_EmptyIdentityNeverReachesProvider(t *testing.T) {
	fp := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"USER": {"unreachable"}}, nil
	}}
	cp, err := newCachedProviderWithClock("ds", "fake", time.Minute, time.Second, fp, testLoggerSimple(t), time.Now)
	require.NoError(t, err, "newCachedProviderWithClock")

	_, err = cp.Resolve(context.Background(), map[string]string{})
	require.Error(t, err, "expected a missing/empty IDENTITY to fail defensively, even called directly outside a Set")
	assert.Equal(t, 0, fp.callCount(), "expected the wrapped provider to never be invoked for an empty identity")
}

// # benchmarks: cachedProvider.Resolve's cache-hit vs cache-miss paths
//
// Both use fakeProvider (not a real backend) so they measure this package's
// own overhead, not network latency.

// benchLogger returns a discard logger - testutils_test.go's loggers take
// *testing.T, so benchmarks (*testing.B) can't reuse them directly.
func benchLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// BenchmarkCachedProviderResolve_CacheHit warms the cache once, then every
// iteration is served from cacheEntry without reaching fakeProvider.Resolve.
func BenchmarkCachedProviderResolve_CacheHit(b *testing.B) {
	fp := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"USER": {"alice"}, "GROUP": {"eng", "ops"}}, nil
	}}
	cp, err := newCachedProviderWithClock("bench-hit", "fake", time.Minute, 30*time.Second, fp, benchLogger(), time.Now)
	require.NoError(b, err, "newCachedProviderWithClock")

	vars := map[string]string{"IDENTITY": "cn=alice,ou=eng"}
	ctx := context.Background()
	_, err = cp.Resolve(ctx, vars)
	require.NoError(b, err, "warm-up Resolve")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cp.Resolve(ctx, vars)
		require.NoError(b, err, "Resolve")
	}
}

// BenchmarkCachedProviderResolve_CacheMiss uses a fresh identity every
// iteration, so every call is a genuine miss - LRU eviction of older
// identities doesn't matter here.
func BenchmarkCachedProviderResolve_CacheMiss(b *testing.B) {
	fp := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"USER": {"someone"}}, nil
	}}
	cp, err := newCachedProviderWithClock("bench-miss", "fake", time.Minute, 30*time.Second, fp, benchLogger(), time.Now)
	require.NoError(b, err, "newCachedProviderWithClock")

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		identity := "cn=bench-user-" + strconv.Itoa(i)
		_, err := cp.Resolve(ctx, map[string]string{"IDENTITY": identity})
		require.NoError(b, err, "Resolve")
	}
}
