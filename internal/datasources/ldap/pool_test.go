package ldap

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePoolConn is a minimal Conn double for pool.go's own tests; it only
// tracks whether it's closed or reports itself as broken.
type fakePoolConn struct {
	id      int
	closed  bool
	closing bool
}

func (c *fakePoolConn) Search(*goldap.SearchRequest) (*goldap.SearchResult, error) {
	return &goldap.SearchResult{}, nil
}
func (c *fakePoolConn) Close() error    { c.closed = true; return nil }
func (c *fakePoolConn) IsClosing() bool { return c.closing }

// countingDialer returns a dialFunc that hands out numbered fakePoolConns
// and counts invocations, so tests can prove dialing is lazy and reuse
// works.
func countingDialer(fail bool) (dialFunc, *int32) {
	var calls int32
	return func(ctx context.Context) (Conn, error) {
		n := atomic.AddInt32(&calls, 1)
		if fail {
			return nil, errors.New("dial failed")
		}
		return &fakePoolConn{id: int(n)}, nil
	}, &calls
}

func TestPoolDialsLazily(t *testing.T) {
	dial, calls := countingDialer(false)
	_ = newPool(4, dial)
	require.Equal(t, int32(0), atomic.LoadInt32(calls), "newPool dialed connections upfront, want 0 (dialing must be lazy)")
}

func TestPoolGetPutReusesHealthyConnection(t *testing.T) {
	// Size 1 avoids FIFO ambiguity from other untouched nil slots, so reuse
	// is deterministically provable.
	dial, calls := countingDialer(false)
	p := newPool(1, dial)

	ctx := context.Background()
	c1, err := p.get(ctx)
	require.NoError(t, err, "get")
	require.Equal(t, int32(1), atomic.LoadInt32(calls), "first get dialed")
	p.put(c1, true)

	c2, err := p.get(ctx)
	require.NoError(t, err, "get")
	assert.Same(t, c1, c2, "second get returned a different connection than the healthy one just put back")
	assert.Equal(t, int32(1), atomic.LoadInt32(calls), "reusing a healthy connection dialed again, want 1 call")
}

func TestPoolRedialsOnUnhealthyPut(t *testing.T) {
	dial, calls := countingDialer(false)
	p := newPool(1, dial)

	c1, err := p.get(context.Background())
	require.NoError(t, err, "get")
	fc := c1.(*fakePoolConn)
	p.put(c1, false) // caller observed a broken connection
	require.True(t, fc.closed, "put(healthy=false) did not close the discarded connection")

	c2, err := p.get(context.Background())
	require.NoError(t, err, "get")
	assert.NotSame(t, c1, c2, "get returned the connection just discarded as unhealthy")
	assert.Equal(t, int32(2), atomic.LoadInt32(calls), "redial after an unhealthy put, want 2 dial calls")
}

func TestPoolRedialsOnClosingConnection(t *testing.T) {
	dial, calls := countingDialer(false)
	p := newPool(1, dial)

	c1, err := p.get(context.Background())
	require.NoError(t, err, "get")
	c1.(*fakePoolConn).closing = true // connection went bad while checked out
	p.put(c1, true)                   // caller didn't know yet - pool must still notice

	c2, err := p.get(context.Background())
	require.NoError(t, err, "get")
	assert.NotSame(t, c1, c2, "get handed out a connection reporting IsClosing() == true")
	assert.Equal(t, int32(2), atomic.LoadInt32(calls), "redial for a closing connection, want 2 dial calls")
}

func TestPoolFailedDialDoesNotLeakCapacity(t *testing.T) {
	dial, calls := countingDialer(true)
	p := newPool(1, dial)

	_, err := p.get(context.Background())
	require.Error(t, err, "get: want error from a failing dialer")
	// The failed dial must return its slot, so the next get() tries again
	// instead of blocking forever.
	_, err = p.get(context.Background())
	require.Error(t, err, "second get: want error from a failing dialer")
	assert.Equal(t, int32(2), atomic.LoadInt32(calls), "want 2 dial attempts (capacity must survive a failed dial)")
}

func TestPoolGetBlocksUntilContextDeadline(t *testing.T) {
	dial, _ := countingDialer(false)
	p := newPool(1, dial)

	// Exhaust the only slot and never put it back.
	_, err := p.get(context.Background())
	require.NoError(t, err, "get")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = p.get(ctx)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.DeadlineExceeded, "get on an exhausted pool")
	assert.GreaterOrEqual(t, elapsed, 40*time.Millisecond, "get returned too early, expected it to block roughly until the deadline")
}

func TestConnHealthyAfterError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, true},
		{"ldap protocol error", &goldap.Error{ResultCode: goldap.LDAPResultSizeLimitExceeded, Err: errors.New("size limit")}, true},
		{"wrapped ldap protocol error", errWrap{&goldap.Error{ResultCode: goldap.LDAPResultNoSuchObject, Err: errors.New("no such object")}}, true},
		{"raw network error", errors.New("connection reset by peer"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := connHealthyAfterError(tt.err)
			require.Equal(t, tt.want, got, "connHealthyAfterError(%v)", tt.err)
		})
	}
}

// errWrap wraps an error the way fmt.Errorf("...: %w", err) would, without
// pulling in fmt just for this one test case.
type errWrap struct{ err error }

func (e errWrap) Error() string { return "wrapped: " + e.err.Error() }
func (e errWrap) Unwrap() error { return e.err }
