package datasources

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// fakeProvider is a fully-controllable Provider for exercising the
// cache+singleflight decorator and Set without a real backend: calls counts
// invocations (a cache hit or coalesced waiter must not increment it), gate
// blocks Resolve to prove real concurrent coalescing, delay simulates
// latency, and poolOpen stands in for connection state Flush must not touch.
type fakeProvider struct {
	resolve  func(ctx context.Context, vars map[string]string) (map[string][]string, error)
	calls    int32
	delay    time.Duration
	gate     chan struct{}
	poolOpen bool
}

func (f *fakeProvider) Resolve(ctx context.Context, vars map[string]string) (map[string][]string, error) {
	atomic.AddInt32(&f.calls, 1)

	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.resolve(ctx, vars)
}

func (f *fakeProvider) callCount() int {
	return int(atomic.LoadInt32(&f.calls))
}

// registerFakeType registers p under typeName for Set-level tests. Register
// has no per-test isolation (it's a process-wide registry), so callers must
// use unique type names.
func registerFakeType(t *testing.T, typeName string, p Provider) {
	t.Helper()
	Register(typeName, func(name string, raw yaml.Node) (Provider, error) {
		return p, nil
	})
}

// fakeClock lets tests fast-forward "now" deterministically instead of
// sleeping real time to cross CacheTTL/negative-cache windows.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// capturingHandler is a minimal slog.Handler that records every emitted
// slog.Record, so tests can assert on WARNs without reparsing JSON output.
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

func (h *capturingHandler) recordsWithMessage(msg string) []slog.Record {
	var out []slog.Record
	for _, r := range h.all() {
		if r.Message == msg {
			out = append(out, r)
		}
	}
	return out
}

func (h *capturingHandler) hasRecordWithMessage(msg string) bool {
	return len(h.recordsWithMessage(msg)) > 0
}

// attrString returns the string form of record r's attribute named key.
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

// newTestLogger builds a logger over capturingHandler for tests that need
// to inspect logged output; testLoggerSimple is for tests that just need a
// logger to satisfy a constructor.
func newTestLogger(t *testing.T) (*slog.Logger, *capturingHandler) {
	t.Helper()
	h := &capturingHandler{}
	return slog.New(h), h
}

func testLoggerSimple(t *testing.T) *slog.Logger {
	t.Helper()
	logger, _ := newTestLogger(t)
	return logger
}
