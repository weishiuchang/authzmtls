// Package datasources defines the Provider interface, the type registry
// providers register into, a generic size+TTL-bounded cache +
// singleflight-coalescing decorator every provider gets automatically
// (cache.go), and Set, the merged view over every configured datasource
// that internal/rules actually talks to.
package datasources

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"
	"unicode"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

// Provider resolves request-derived variables (at minimum
// vars["IDENTITY"]) into named allowlist variables - e.g. the ldap provider
// turns $IDENTITY into $USER/$GROUP; ctx carries the per-decision deadline
// and implementations must respect it. A Provider only needs to answer one
// (ctx, vars) call correctly - caching, coalescing, and negative caching
// are handled generically by cache.go's decorator.
type Provider interface {
	Resolve(ctx context.Context, vars map[string]string) (map[string][]string, error)
}

// Config is the common shape every datasource entry has, mirroring
// internal/config's DatasourceConfig field-for-field. Raw carries every
// provider-specific field as an undecoded YAML node - only the Factory
// registered for Type knows what's in it.
type Config struct {
	Name     string
	Type     string
	CacheTTL time.Duration // refresh interval, not a hard expiration - see cache.go. Zero means "use the default" (10m).
	Raw      yaml.Node
}

// Factory constructs a Provider from one datasource config entry; raw is
// Config.Raw, decoded by the factory into whatever struct that provider
// type expects.
type Factory func(name string, raw yaml.Node) (Provider, error)

// registry lets a provider package register itself via Register from its
// own init(), so this package never imports specific provider packages.
var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register associates typeName with the Factory that builds its Provider,
// intended to be called from a provider package's init(). Registering the
// same typeName twice silently replaces the earlier factory.
func Register(typeName string, factory Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[typeName] = factory
}

// lookup returns the Factory registered for typeName, if any. Unexported -
// NewSet is the only caller, matching how this dispatch is reached in
// production.
func lookup(typeName string) (Factory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[typeName]
	return f, ok
}

// errUnknownType reports a config referencing an unregistered Type. In
// production internal/config's validation should already reject this, but
// NewSet checks anyway so a caller that skips validation still fails loudly.
func errUnknownType(name, typeName string) error {
	return fmt.Errorf("datasources: datasource %q: unknown type %q (no Factory registered)", name, typeName)
}

// maxVarValueLen bounds any single vars entry's length - a worst-case
// query/log-size guard, not a correctness boundary.
const maxVarValueLen = 4 * 1024

// Set is the merged view of every configured datasource, each wrapped in
// the cache+singleflight decorator (cache.go) automatically.
type Set struct {
	providers []*cachedProvider
	logger    *slog.Logger
}

// NewSet builds a Set from cfgs, dispatching each entry's Type through the
// registry. A nil logger falls back to slog.Default(); an unknown Type
// fails NewSet outright, so a successfully-constructed Set never has to
// handle "provider doesn't exist" at request time, only "provider's live
// call failed."
func NewSet(cfgs []Config, logger *slog.Logger) (*Set, error) {
	if logger == nil {
		logger = slog.Default()
	}

	providers := make([]*cachedProvider, 0, len(cfgs))
	for _, cfg := range cfgs {
		factory, ok := lookup(cfg.Type)
		if !ok {
			return nil, errUnknownType(cfg.Name, cfg.Type)
		}

		p, err := factory(cfg.Name, cfg.Raw)
		if err != nil {
			return nil, fmt.Errorf("datasources: constructing datasource %q (type %q): %w", cfg.Name, cfg.Type, err)
		}

		cached, err := newCachedProvider(cfg.Name, cfg.Type, cfg.CacheTTL, p, logger)
		if err != nil {
			return nil, fmt.Errorf("datasources: wiring cache for datasource %q: %w", cfg.Name, err)
		}
		providers = append(providers, cached)
	}

	return &Set{providers: providers, logger: logger}, nil
}

// Flush clears every configured provider's cache - the SIGHUP-triggered
// flush - without touching any provider's own connection/pool state.
func (s *Set) Flush() {
	for _, p := range s.providers {
		p.Flush()
	}
}

// Resolve asks every configured provider to contribute variables for vars
// and unions their results per variable name, deduplicated; a provider
// failing only narrows the union by its own contribution, never fails the
// whole call, and an empty/all-failing Set returns an empty map, never an
// error.
//
// Every provider is queried concurrently (bounded by len(s.providers)
// goroutines via errgroup), so cold-path latency tracks the slowest single
// datasource, not their sum.
func (s *Set) Resolve(ctx context.Context, vars map[string]string) map[string][]string {
	clean, ok := s.sanitize(ctx, vars)
	if !ok || len(s.providers) == 0 {
		return map[string][]string{}
	}

	results := make([]map[string][]string, len(s.providers))

	var g errgroup.Group
	g.SetLimit(len(s.providers)) // exactly one goroutine per configured datasource

	for i, p := range s.providers {
		g.Go(func() error {
			// Error swallowed deliberately (not propagated via errgroup) so
			// one provider failing or being slow never cuts short another's
			// still-in-flight call; cache.go already logs it server-side.
			if v, err := p.Resolve(ctx, clean); err == nil {
				results[i] = v
			}
			return nil
		})
	}
	_ = g.Wait() // always nil: every Go func above unconditionally returns nil

	merged := make(map[string][]string)
	seen := make(map[string]map[string]struct{})
	for _, r := range results {
		unionInto(merged, seen, r)
	}
	return merged
}

// unionInto merges src into dst, deduplicating per variable name via seen.
// Providers are merged in configured order, so dedup ordering is
// deterministic, not goroutine-scheduling dependent.
func unionInto(dst map[string][]string, seen map[string]map[string]struct{}, src map[string][]string) {
	for name, values := range src {
		set, ok := seen[name]
		if !ok {
			set = make(map[string]struct{}, len(values))
			seen[name] = set
		}
		for _, v := range values {
			if _, dup := set[v]; dup {
				continue
			}
			set[v] = struct{}{}
			dst[name] = append(dst[name], v)
		}
	}
}

// sanitize is the one chokepoint every vars entry passes through before any
// Provider sees it - every entry is treated as untrusted external input,
// since the dockerd->authzmtls hop is unauthenticated.
//
// A bad identityVar short-circuits the whole call to ok=false; any other
// bad entry is simply dropped from the returned map without blocking the
// rest.
func (s *Set) sanitize(ctx context.Context, vars map[string]string) (clean map[string]string, ok bool) {
	identity := vars[identityVar]
	if reason, valid := validVarValue(identity); !valid {
		s.warnRejected(ctx, identityVar, identity, reason)
		return nil, false
	}

	clean = make(map[string]string, len(vars))
	for name, value := range vars {
		if name == identityVar {
			clean[name] = value
			continue
		}
		if reason, valid := validVarValue(value); !valid {
			s.warnRejected(ctx, name, value, reason)
			continue
		}
		clean[name] = value
	}
	return clean, true
}

// validVarValue reports whether v is non-empty, within maxVarValueLen, and
// free of control characters. reason names which rule failed; meaningless
// when ok is true.
func validVarValue(v string) (reason string, ok bool) {
	switch {
	case v == "":
		return "empty", false
	case len(v) > maxVarValueLen:
		return "too long", false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return "contains control characters", false
		}
	}
	return "", true
}

// warnRejected logs the one WARN a sanitization rejection produces - a
// possible-attack signal, not routine noise. value is always rendered
// through sanitizeForLog, never verbatim.
func (s *Set) warnRejected(ctx context.Context, name, value, reason string) {
	args := []any{
		"variable", name,
		"reason", reason,
		"value", sanitizeForLog(value),
	}
	if info, ok := requestInfoFrom(ctx); ok {
		args = append(args, "request_method", info.method, "request_uri", info.uri)
	}
	s.logger.WarnContext(ctx, "rejected untrusted datasource input variable", args...)
}

// maxLoggedRunes caps how much of a rejected value reaches the log - a
// too-long value shouldn't recreate the size problem sanitization bounds.
const maxLoggedRunes = 80

// sanitizeForLog truncates v to maxLoggedRunes and strconv.Quote's it, so
// every control/non-printable byte becomes a visible Go-syntax escape
// rather than reaching the log raw.
func sanitizeForLog(v string) string {
	runes := []rune(v)
	truncated := len(runes) > maxLoggedRunes
	if truncated {
		runes = runes[:maxLoggedRunes]
	}
	quoted := strconv.Quote(string(runes))
	if truncated {
		quoted += "...(truncated)"
	}
	return quoted
}

// requestContextKey/requestInfo let a caller optionally attach the inbound
// request's method/URI to ctx, so warnRejected can include it for operator
// correlation. Omitted from the WARN if never attached.
type requestContextKey struct{}

type requestInfo struct {
	method string
	uri    string
}

// WithRequestContext attaches method/uri to ctx for Set.Resolve's
// sanitization-failure WARN logs to pick up. Optional.
func WithRequestContext(ctx context.Context, method, uri string) context.Context {
	return context.WithValue(ctx, requestContextKey{}, requestInfo{method: method, uri: uri})
}

func requestInfoFrom(ctx context.Context) (requestInfo, bool) {
	info, ok := ctx.Value(requestContextKey{}).(requestInfo)
	return info, ok
}
