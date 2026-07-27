// Connection pooler.
package ldap

import (
	"context"
	"errors"
	"net"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// Conn is the subset of *goldap.Conn that user.go and group.go need,
// defined as an interface so tests can substitute a fake LDAP backend.
type Conn interface {
	Search(*goldap.SearchRequest) (*goldap.SearchResult, error)
	Close() error
	IsClosing() bool
}

// dialFunc opens and binds a single fresh connection; pool.go always goes
// through this seam so tests can substitute a fake dialer.
type dialFunc func(ctx context.Context) (Conn, error)

// pool is a bounded, channel-based pool of at most `size` LDAP connections,
// shared by user.go's and group.go's searches.
//
// slots starts pre-filled with `size` nil placeholders, not live
// connections: dialing is lazy, on first need. This keeps the channel's
// occupancy always equal to "slots not checked out", so get/put's single
// channel operation apiece is correct without a separate mutex/counter.
type pool struct {
	slots chan Conn
	dial  dialFunc
}

// newPool constructs a pool of the given size. size <= 0 produces a pool
// that can never hand out a connection - ldap.go's New defaults pool_size
// before calling this.
func newPool(size int, dial dialFunc) *pool {
	p := &pool{slots: make(chan Conn, size), dial: dial}
	for i := 0; i < size; i++ {
		p.slots <- nil
	}
	return p
}

// get returns a connection, dialing lazily if the slot is empty or
// unhealthy. It blocks until a slot frees or ctx's deadline passes,
// deliberately never dialing an unbounded extra connection when exhausted.
func (p *pool) get(ctx context.Context) (Conn, error) {
	select {
	case c := <-p.slots:
		if c != nil && !c.IsClosing() {
			return c, nil
		}
		if c != nil {
			_ = c.Close() // already broken; best-effort close before redial
		}
		fresh, err := p.dial(ctx)
		if err != nil {
			// A failed dial must not shrink pool capacity - hand the slot
			// back empty so the next get() tries again.
			p.slots <- nil
			return nil, err
		}
		return fresh, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// put returns a connection to the pool; if healthy is false, it closes the
// connection and returns an empty slot so the next get redials instead.
func (p *pool) put(c Conn, healthy bool) {
	if !healthy {
		_ = c.Close()
		p.slots <- nil
		return
	}
	p.slots <- c
}

// connHealthyAfterError reports whether a connection is still safe to
// reuse. A *goldap.Error means the server responded, so the connection
// itself is fine; any other error means it's suspect and must be discarded.
func connHealthyAfterError(err error) bool {
	if err == nil {
		return true
	}
	var ldapErr *goldap.Error
	return errors.As(err, &ldapErr)
}

// dialAndBind is the production dialFunc: opens a fresh connection to addr
// and simple-binds as bindDN/bindPW.
func dialAndBind(addr, bindDN, bindPW string) dialFunc {
	return func(ctx context.Context) (Conn, error) {
		dialer := &net.Dialer{Timeout: goldap.DefaultTimeout}
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining > 0 {
				dialer.Timeout = remaining
			}
		}
		conn, err := goldap.DialURL(addr, goldap.DialWithDialer(dialer))
		if err != nil {
			return nil, err
		}
		if err := conn.Bind(bindDN, bindPW); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}
