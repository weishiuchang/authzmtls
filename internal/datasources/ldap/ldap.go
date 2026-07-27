// Package ldap is the reference internal/datasources Provider
// implementation, backing the Active Directory datasource type.
package ldap

import (
	"context"
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"gopkg.in/yaml.v3"

	"github.com/weishiuchang/authzmtls/internal/datasources"
)

// defaultPoolSize is pool_size's default when omitted.
const defaultPoolSize = 8

// Config is this provider's own view of a datasources entry's
// provider-specific fields, decoded once from
// internal/datasources.Config.Raw.
type Config struct {
	URL      string `yaml:"url"`
	BindDN   string `yaml:"bind_dn"`
	BindPW   string `yaml:"bind_pw"`
	PoolSize int    `yaml:"pool_size"`

	UserSearch  userSearchConfig  `yaml:"user_search"`
	GroupSearch groupSearchConfig `yaml:"group_search"`
}

// Provider is the `ldap` datasources.Provider: it borrows connections from
// pool.go's pool and sequences user/group searches - see Resolve.
type Provider struct {
	pool        *pool
	userSearch  userSearchConfig
	groupSearch groupSearchConfig
}

// New decodes raw (internal/datasources.Config.Raw, the provider-specific
// portion of a config.yaml entry) into Config and builds a *Provider.
func New(name string, raw yaml.Node) (datasources.Provider, error) {
	var cfg Config
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("ldap: datasource %q: decoding config: %w", name, err)
	}

	// Both are required - no memberOf fallback for a partial config - so
	// New never hands back a Provider that can only return an empty map.
	if cfg.UserSearch.BaseDN == "" || cfg.UserSearch.Filter == "" {
		return nil, fmt.Errorf("ldap: datasource %q: user_search is required", name)
	}
	if cfg.GroupSearch.BaseDN == "" || cfg.GroupSearch.Filter == "" {
		return nil, fmt.Errorf("ldap: datasource %q: group_search is required", name)
	}
	if cfg.GroupSearch.Attribute == "" {
		cfg.GroupSearch.Attribute = "cn"
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = defaultPoolSize
	}

	return &Provider{
		pool:        newPool(cfg.PoolSize, dialAndBind(cfg.URL, cfg.BindDN, cfg.BindPW)),
		userSearch:  cfg.UserSearch,
		groupSearch: cfg.GroupSearch,
	}, nil
}

func init() {
	datasources.Register("ldap", New)
}

// Resolve sequences $USER then $GROUP as a plain two-step call, deliberately
// not a loop over an arbitrary variable list.
//
// user_search matching more than one account is valid, not an error (see
// resolveUser): every matched account contributes its username to $USER and
// its own group_search results to $GROUP, unioned and deduplicated across
// accounts exactly like datasources.Set unions results across datasources -
// mount-path validation then allows the request if any resulting $VAR
// expansion matches.
//
// Only configured attribute values ever reach the returned map - never a DN
// or raw LDAP result - and any returned error must stay a fixed, generic
// phrase, never wrap sensitive detail (query text, bind DN, hostname),
// since it's for server-side logging only.
func (p *Provider) Resolve(ctx context.Context, vars map[string]string) (map[string][]string, error) {
	// Done once here, not per-variable: $IDENTITY is deliberately not named
	// $USER, since $USER is this provider's output.
	escapedIdentity := escapeFilterValue(normalizeSubjectDN(vars["IDENTITY"]))

	matches, ok, err := resolveUser(ctx, p.pool, p.userSearch, escapedIdentity)
	if err != nil {
		return map[string][]string{}, fmt.Errorf("ldap: resolving user: %w", err)
	}
	if !ok {
		// GROUP can't resolve either without at least one matched account's DN.
		return map[string][]string{}, nil
	}

	usernames := make([]string, 0, len(matches))
	var groups []string
	seenGroups := make(map[string]struct{})
	for _, m := range matches {
		usernames = append(usernames, m.username)

		matchGroups, err := resolveGroups(ctx, p.pool, p.groupSearch, m.dn)
		if err != nil {
			return map[string][]string{}, fmt.Errorf("ldap: resolving groups: %w", err)
		}
		for _, g := range matchGroups {
			if _, dup := seenGroups[g]; dup {
				continue
			}
			seenGroups[g] = struct{}{}
			groups = append(groups, g)
		}
	}

	return map[string][]string{
		"USER":  usernames,
		"GROUP": groups,
	}, nil
}

// # user_search

// userSearchConfig is user_search's own config shape.
type userSearchConfig struct {
	BaseDN    string `yaml:"base_dn"`
	Filter    string `yaml:"filter"`
	Attribute string `yaml:"attribute"` // e.g. "sAMAccountName" - a plain string attribute, its value becomes $USER verbatim
}

// userSearchSizeLimit bounds query cost as a backstop against $IDENTITY (an
// unauthenticated hop) driving an expensive query - this search normally
// matches 0 or 1 entries by filter construction alone, but multiple matches
// are valid (see resolveUser) and all count toward this limit.
const userSearchSizeLimit = 200

// userMatch is one user_search result: the configured attribute's value
// (this account's contribution to $USER) paired with its DN (needed to run
// group_search for this account).
type userMatch struct {
	username string
	dn       string
}

// resolveUser runs user_search for escapedIdentity (already normalized and
// escaped once, centrally, by Resolve above) and returns every matching
// account. Multiple matches are a valid outcome, not ambiguity: Resolve
// treats every one of them as a distinct identity to fan out $USER/$GROUP
// over, mount-path validation then allows the request if any resulting
// expansion matches (see README's "Allowlist matching").
//
// The reference filter excludes disabled/locked accounts itself via AD's
// userAccountControl bitwise-AND match; accountExpires is NOT checked here
// - a known gap, since it needs a live-time comparison a static filter
// can't express.
//
// ok is false only when zero entries matched, or every matched entry's
// configured attribute was empty. A search error collapses to ok=false too,
// not err - err is reserved for failing to even acquire a connection.
func resolveUser(ctx context.Context, p *pool, cfg userSearchConfig, escapedIdentity string) (matches []userMatch, ok bool, err error) {
	// Plain substitution, not substituteFilterToken: escapedIdentity is
	// already escaped upstream, so escaping again here would double-escape
	// it.
	filter := strings.ReplaceAll(cfg.Filter, "$IDENTITY", escapedIdentity)

	conn, acquireErr := p.get(ctx)
	if acquireErr != nil {
		return nil, false, fmt.Errorf("ldap: user search: acquiring connection: %w", acquireErr)
	}

	req := goldap.NewSearchRequest(
		cfg.BaseDN,
		goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, userSearchSizeLimit, 0, false,
		filter,
		[]string{cfg.Attribute},
		nil,
	)
	result, searchErr := conn.Search(req)
	p.put(conn, connHealthyAfterError(searchErr))
	if searchErr != nil {
		return nil, false, nil
	}

	for _, entry := range result.Entries {
		name := entry.GetAttributeValue(cfg.Attribute)
		if name == "" {
			// An empty/absent attribute is a directory-side data problem
			// for this one entry - skip it, don't fail the whole search.
			continue
		}
		// distinguishedName comes free on the search result, no need to
		// request it as an attribute.
		matches = append(matches, userMatch{username: name, dn: entry.DN})
	}
	return matches, len(matches) > 0, nil
}

// # group_search

// groupSearchConfig is group_search's own config shape.
type groupSearchConfig struct {
	BaseDN    string `yaml:"base_dn"`
	Filter    string `yaml:"filter"`
	Attribute string `yaml:"attribute"` // defaults to "cn" - see New
}

// groupSearchSizeLimit bounds result size - an uncapped $GROUP set is a
// real perf/DoS multiplier through internal/rules' Expand, not just an
// LDAP-side cost.
const groupSearchSizeLimit = 500

// resolveGroups runs group_search with $IDENTITY_DN substituted for
// identityDN and collects cfg.Attribute from every matching entry.
//
// Zero results is valid (no memberships), and hitting groupSearchSizeLimit
// is deliberately swallowed too - a truncated list is safer than failing -
// so only other search/connection errors propagate.
func resolveGroups(ctx context.Context, p *pool, cfg groupSearchConfig, identityDN string) ([]string, error) {
	filter := substituteFilterToken(cfg.Filter, "$IDENTITY_DN", identityDN)

	conn, err := p.get(ctx)
	if err != nil {
		return nil, fmt.Errorf("ldap: group search: acquiring connection: %w", err)
	}

	req := goldap.NewSearchRequest(
		cfg.BaseDN,
		goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, groupSearchSizeLimit, 0, false,
		filter,
		[]string{cfg.Attribute},
		nil,
	)
	result, searchErr := conn.Search(req)
	p.put(conn, connHealthyAfterError(searchErr))

	if searchErr != nil && !goldap.IsErrorWithCode(searchErr, goldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("ldap: group search failed: %w", searchErr)
	}

	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if v := entry.GetAttributeValue(cfg.Attribute); v != "" {
			groups = append(groups, v)
		}
	}
	return groups, nil
}
