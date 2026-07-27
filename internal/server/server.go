// Build a HTTP(S) listener for endpoints:
// - internal/dockerapi's authorization-plugin
// - internal/telemetry's /metrics
//
// TLS is decided once at New and never changes for a Server's lifetime;
// Reload atomically swaps in a rebuilt decider, rule chain, and (TLS mode)
// certificate, and always flushes the datasource cache on success - which
// is what lets SIGHUP double as README's emergency-revocation lever.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/weishiuchang/authzmtls/internal/config"
	"github.com/weishiuchang/authzmtls/internal/datasources"
	"github.com/weishiuchang/authzmtls/internal/dockerapi"
	"github.com/weishiuchang/authzmtls/internal/rules"
)

const (
	// Slow-client protections for http.Server; deliberately not
	// operator-configurable since they bound HTTP transport, not decision
	// latency (unlike server.decision_timeout).
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 1 << 20 // 1 MiB
)

// state groups everything Reload swaps atomically as one unit - the active
// decider and its decision_timeout - so a single Decide call never sees a
// mix from two different Reloads. A *state is never mutated after
// construction, so an in-flight Decide call (which loads the pointer once)
// is immune to a concurrent Reload replacing Server.active.
type state struct {
	decider         dockerapi.Decider
	decisionTimeout time.Duration
}

// Server is the TLS-optional HTTP(S) listener described in this package's
// doc comment above. Every exported method is safe for concurrent use,
// including Reload racing in-flight Decide calls.
type Server struct {
	logger *slog.Logger

	httpServer *http.Server

	// tlsEnabled is fixed at New; Reload rejects any attempt to change it.
	tlsEnabled bool
	// cert is only written when tlsEnabled; nil for plain-HTTP servers.
	cert atomic.Pointer[tls.Certificate]

	// active is swapped as a whole by Reload; each Decide call loads it once.
	active atomic.Pointer[state]

	started  atomic.Bool
	listener net.Listener
}

// Server itself implements dockerapi.Decider (see Decide).
var _ dockerapi.Decider = (*Server)(nil)

// New constructs a Server from an already-validated cfg, the initial
// decider, and the metrics handler to mount at cfg.Server.MetricsPath.
// TLS is enabled only if both ServerCert and ServerKey are set; New does
// not start listening - call Start for that.
func New(cfg *config.Config, decider dockerapi.Decider, metrics http.Handler, logger *slog.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("server: cfg must not be nil")
	}
	if decider == nil {
		return nil, errors.New("server: decider must not be nil")
	}
	if metrics == nil {
		return nil, errors.New("server: metrics handler must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	certSet := cfg.Server.ServerCert != ""
	keySet := cfg.Server.ServerKey != ""
	if certSet != keySet {
		return nil, errors.New("server: server_cert and server_key must both be set (TLS) or both unset (plain HTTP)")
	}

	s := &Server{
		logger:     logger,
		tlsEnabled: certSet && keySet,
	}
	s.active.Store(&state{
		decider:         decider,
		decisionTimeout: time.Duration(cfg.Server.DecisionTimeout),
	})

	mux := http.NewServeMux()
	// net/http.ServeMux prefers the more specific pattern over "/"
	// regardless of registration order.
	mux.Handle(cfg.Server.MetricsPath, metrics)
	mux.Handle("/", dockerapi.NewHandler(s, logger).Mux())

	s.httpServer = &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		// Keep-alives stay on (the http.Server default): nothing here calls
		// SetKeepAlivesEnabled(false).
	}

	if s.tlsEnabled {
		cert, err := loadCertificate(cfg.Server.ServerCert, cfg.Server.ServerKey)
		if err != nil {
			return nil, fmt.Errorf("server: loading initial TLS certificate: %w", err)
		}
		s.cert.Store(cert)
		s.httpServer.TLSConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: s.getCertificate,
		}
	}

	return s, nil
}

// Start binds ListenAddr and serves on a background goroutine, returning
// once the listener is bound so Addr() is immediately valid. The returned
// channel receives the goroutine's terminal error exactly once (nil after
// a graceful Shutdown); Start must be called at most once per Server.
func (s *Server) Start() (<-chan error, error) {
	if !s.started.CompareAndSwap(false, true) {
		return nil, errors.New("server: Start called more than once")
	}

	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return nil, fmt.Errorf("server: listening on %s: %w", s.httpServer.Addr, err)
	}
	s.listener = ln

	done := make(chan error, 1)
	go func() {
		var serveErr error
		if s.tlsEnabled {
			// certFile/keyFile are empty: TLSConfig.GetCertificate is already
			// populated (see New), and ServeTLS only needs file arguments
			// when neither GetCertificate nor TLSConfig.Certificates is set.
			serveErr = s.httpServer.ServeTLS(ln, "", "")
		} else {
			serveErr = s.httpServer.Serve(ln)
		}
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		done <- serveErr
	}()

	return done, nil
}

// Addr returns the address Start bound (useful when ListenAddr uses port
// 0), or "" before Start is called.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// TLSEnabled reports whether this Server is serving TLS (true) or plain
// HTTP (false), as decided once at New and fixed for the Server's lifetime.
func (s *Server) TLSEnabled() bool {
	return s.tlsEnabled
}

// Shutdown gracefully drains in-flight requests per
// net/http.Server.Shutdown semantics; catching SIGINT/SIGTERM is
// cmd/authzmtls/main.go's job, not this package's.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Decide implements dockerapi.Decider: it loads the active state once (so
// a concurrent Reload can't change decider/timeout mid-call), then applies
// decision_timeout and delegates to the active decider.
func (s *Server) Decide(ctx context.Context, req *dockerapi.AuthZReq) (allow bool, msg string, err error) {
	st := s.active.Load()
	ctx, cancel := context.WithTimeout(ctx, st.decisionTimeout)
	defer cancel()
	return st.decider.Decide(ctx, req)
}

// getCertificate backs live TLS cert rotation: invoked on every new
// handshake, it loads whatever certificate is currently active, so a
// Reload takes effect on the next handshake without affecting existing
// connections.
func (s *Server) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := s.cert.Load()
	if cert == nil {
		// Unreachable in practice - New always stores a cert before
		// enabling TLS - but guarded rather than trusted blindly.
		return nil, errors.New("server: no TLS certificate loaded")
	}
	return cert, nil
}

// loadCertificate reads and parses a certificate/key pair from disk,
// returning a pointer suitable for atomic.Pointer[tls.Certificate] storage.
func loadCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// Reload rebuilds the datasources.Set, rule chain, and (TLS mode) the
// cert/key pair from cfg, and only if every rebuild step succeeds,
// atomically swaps all of it into what live requests use. On any failure it
// returns the error and leaves the previously active state serving
// unchanged - it never falls back silently or exits the process itself.
//
// Every datasource is rebuilt from scratch on every call, and on success
// Reload unconditionally flushes the new Set's cache regardless of whether
// cfg actually changed - this is what lets a successful SIGHUP double as
// README's emergency-revocation lever.
//
// Switching between TLS and plain-HTTP mode via Reload is unsupported and
// rejected with an error; restart the process to change TLS mode.
func (s *Server) Reload(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("server: cfg must not be nil")
	}

	certSet := cfg.Server.ServerCert != ""
	keySet := cfg.Server.ServerKey != ""
	if certSet != keySet {
		return errors.New("server: server_cert and server_key must both be set (TLS) or both unset (plain HTTP)")
	}
	if (certSet && keySet) != s.tlsEnabled {
		return errors.New("server: cannot change TLS mode (plain HTTP <-> TLS) via Reload; restart the process instead")
	}

	dsSet, err := datasources.NewSet(convertDatasources(cfg.Datasources), s.logger)
	if err != nil {
		return fmt.Errorf("server: rebuilding datasources: %w", err)
	}

	chain, err := rules.NewBuiltinChain(cfg, dsSet, s.logger)
	if err != nil {
		return fmt.Errorf("server: rebuilding rule chain: %w", err)
	}

	// Validate the cert/key pair before mutating any shared state, so a bad
	// pair leaves the previous certificate serving.
	var newCert *tls.Certificate
	if s.tlsEnabled {
		newCert, err = loadCertificate(cfg.Server.ServerCert, cfg.Server.ServerKey)
		if err != nil {
			return fmt.Errorf("server: reloading TLS certificate: %w", err)
		}
	}

	// Nothing above this point mutated s, so any earlier failure leaves
	// prior state serving unchanged.
	if newCert != nil {
		s.cert.Store(newCert)
	}
	s.active.Store(&state{
		decider:         chain,
		decisionTimeout: time.Duration(cfg.Server.DecisionTimeout),
	})

	// Unconditional, every successful call - see doc comment above.
	dsSet.Flush()

	return nil
}

// convertDatasources adapts config.DatasourceConfig into
// datasources.Config; the two shapes mirror each other, so this is a plain
// field-by-field copy.
func convertDatasources(cfgs []config.DatasourceConfig) []datasources.Config {
	out := make([]datasources.Config, len(cfgs))
	for i, c := range cfgs {
		out[i] = datasources.Config{
			Name:     c.Name,
			Type:     c.Type,
			CacheTTL: time.Duration(c.CacheTTL),
			Raw:      c.Raw,
		}
	}
	return out
}
