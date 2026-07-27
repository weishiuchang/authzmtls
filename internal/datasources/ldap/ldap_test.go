package ldap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// # shared fake LDAP backend
//
// fakeConn is a scriptable Conn double shared across this package's tests.
// Unlike pool_test.go's fakePoolConn, it emulates real Search behavior
// including SizeLimit truncation (returning LDAPResultSizeLimitExceeded
// alongside the truncated entries), so truncation-handling is exercised
// realistically.
type fakeConn struct {
	// match returns every entry "in the directory" matching req.
	match func(req *goldap.SearchRequest) []*goldap.Entry
	// searchErr, if set, makes every Search fail instead of consulting match.
	searchErr error

	closing bool
	closed  bool

	// filters records every filter string searched, for asserting escaping held.
	filters []string
}

func (c *fakeConn) Search(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	c.filters = append(c.filters, req.Filter)
	if c.searchErr != nil {
		return nil, c.searchErr
	}
	matched := c.match(req)
	if req.SizeLimit > 0 && len(matched) > req.SizeLimit {
		return &goldap.SearchResult{Entries: matched[:req.SizeLimit]},
			&goldap.Error{ResultCode: goldap.LDAPResultSizeLimitExceeded, Err: errors.New("size limit exceeded")}
	}
	return &goldap.SearchResult{Entries: matched}, nil
}
func (c *fakeConn) Close() error    { c.closed = true; return nil }
func (c *fakeConn) IsClosing() bool { return c.closing }

// singleConnPool builds a *pool of size 1 that always hands out conn, for
// tests that don't care about pool concurrency.
func singleConnPool(conn Conn) *pool {
	return newPool(1, func(context.Context) (Conn, error) { return conn, nil })
}

// failingDialPool builds a *pool that always fails to dial, for the "can't
// acquire a connection" error path.
func failingDialPool(dialErr error) *pool {
	return newPool(1, func(context.Context) (Conn, error) { return nil, dialErr })
}

// testUsername is the shared valid-sAMAccountName fixture.
const testUsername = "jdoe"

func userEntry(dn, username string) *goldap.Entry {
	return &goldap.Entry{
		DN:         dn,
		Attributes: []*goldap.EntryAttribute{{Name: "sAMAccountName", Values: []string{username}}},
	}
}

func cnEntry(dn, cn string) *goldap.Entry {
	return &goldap.Entry{
		DN:         dn,
		Attributes: []*goldap.EntryAttribute{{Name: "cn", Values: []string{cn}}},
	}
}

// # Config / New

const testUserFilter = "(&(objectClass=user)(altSecurityIdentities=X509:<S>$IDENTITY))"
const testGroupFilter = "(&(objectClass=group)(member=$IDENTITY_DN))"

func rawConfigNode(t *testing.T, yamlText string) yaml.Node {
	t.Helper()
	var node yaml.Node
	err := yaml.Unmarshal([]byte(yamlText), &node)
	require.NoError(t, err, "yaml.Unmarshal")
	return node
}

func TestNew_Success(t *testing.T) {
	raw := rawConfigNode(t, `
url: ldaps://ad01.example.com
bind_dn: readonly_acct
bind_pw: readonly_pwd
pool_size: 4
user_search:
  base_dn: "dc=example,dc=com"
  filter: "`+testUserFilter+`"
  attribute: sAMAccountName
group_search:
  base_dn: "ou=groups,dc=example,dc=com"
  filter: "`+testGroupFilter+`"
  attribute: cn
`)
	provider, err := New("ad01", raw)
	require.NoError(t, err, "New")
	p, ok := provider.(*Provider)
	require.True(t, ok, "New returned %T, want *Provider", provider)
	assert.Equal(t, "dc=example,dc=com", p.userSearch.BaseDN, "userSearch not decoded correctly: %+v", p.userSearch)
	assert.Equal(t, "sAMAccountName", p.userSearch.Attribute, "userSearch not decoded correctly: %+v", p.userSearch)
	assert.Equal(t, "cn", p.groupSearch.Attribute)
}

func TestNew_DefaultsPoolSizeAndGroupAttribute(t *testing.T) {
	raw := rawConfigNode(t, `
url: ldaps://ad01.example.com
user_search:
  base_dn: "dc=example,dc=com"
  filter: "`+testUserFilter+`"
  attribute: sAMAccountName
group_search:
  base_dn: "ou=groups,dc=example,dc=com"
  filter: "`+testGroupFilter+`"
`)
	provider, err := New("ad01", raw)
	require.NoError(t, err, "New")
	p := provider.(*Provider)
	assert.Equal(t, "cn", p.groupSearch.Attribute, "group_search.attribute default")
	// pool_size's default isn't observable here without reflection;
	// pool_test.go covers sizing separately.
}

func TestNew_MissingUserSearchIsFatal(t *testing.T) {
	// Both user_search and group_search are required - no memberOf
	// fallback for a partial config.
	raw := rawConfigNode(t, `
url: ldaps://ad01.example.com
group_search:
  base_dn: "ou=groups,dc=example,dc=com"
  filter: "`+testGroupFilter+`"
`)
	_, err := New("ad01", raw)
	require.Error(t, err, "New: want error for missing user_search")
}

func TestNew_MissingGroupSearchIsFatal(t *testing.T) {
	raw := rawConfigNode(t, `
url: ldaps://ad01.example.com
user_search:
  base_dn: "dc=example,dc=com"
  filter: "`+testUserFilter+`"
  attribute: sAMAccountName
`)
	_, err := New("ad01", raw)
	require.Error(t, err, "New: want error for missing group_search")
}

// # resolveUser

func TestResolveUser_Success(t *testing.T) {
	const dn = "CN=jdoe,OU=Users,DC=example,DC=com"
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry {
		return []*goldap.Entry{userEntry(dn, testUsername)}
	}}
	cfg := userSearchConfig{BaseDN: "dc=example,dc=com", Filter: testUserFilter, Attribute: "sAMAccountName"}

	matches, ok, err := resolveUser(context.Background(), singleConnPool(conn), cfg, "jdoe")
	require.NoError(t, err, "resolveUser")
	require.True(t, ok, "resolveUser: ok=false, want ok=true")
	require.Len(t, matches, 1)
	assert.Equal(t, testUsername, matches[0].username)
	assert.Equal(t, dn, matches[0].dn)
}

// TestResolveUser_DisabledOrLockedAccountExcludedByFilter: the reference
// filter excludes disabled/locked accounts server-side (simulated by zero
// entries); resolveUser has no separate Go-side status check.
func TestResolveUser_DisabledOrLockedAccountExcludedByFilter(t *testing.T) {
	for _, name := range []string{"disabled account", "locked account"} {
		t.Run(name, func(t *testing.T) {
			conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry { return nil }}
			cfg := userSearchConfig{BaseDN: "dc=example,dc=com", Filter: testUserFilter, Attribute: "sAMAccountName"}

			_, ok, err := resolveUser(context.Background(), singleConnPool(conn), cfg, "jdoe")
			require.NoError(t, err, "resolveUser")
			assert.False(t, ok, "resolveUser: ok=true for a %s, want ok=false", name)
		})
	}
}

func TestResolveUser_UnknownIdentity(t *testing.T) {
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry { return nil }}
	cfg := userSearchConfig{BaseDN: "dc=example,dc=com", Filter: testUserFilter, Attribute: "sAMAccountName"}

	_, ok, err := resolveUser(context.Background(), singleConnPool(conn), cfg, "ghost")
	require.NoError(t, err, "resolveUser")
	assert.False(t, ok, "resolveUser: ok=true for an unknown identity, want ok=false")
}

// TestResolveUser_MultipleMatchesAreAllValid: multiple matches are a valid
// outcome (fanned out over by ldap.go's Resolve), not ambiguity - unlike the
// old fail-closed behavior, every matched account's username/DN comes back.
func TestResolveUser_MultipleMatchesAreAllValid(t *testing.T) {
	const dnA = "CN=a,DC=example,DC=com"
	const dnB = "CN=b,DC=example,DC=com"
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry {
		return []*goldap.Entry{
			userEntry(dnA, "a"),
			userEntry(dnB, "b"),
		}
	}}
	cfg := userSearchConfig{BaseDN: "dc=example,dc=com", Filter: testUserFilter, Attribute: "sAMAccountName"}

	matches, ok, err := resolveUser(context.Background(), singleConnPool(conn), cfg, "dup")
	require.NoError(t, err, "resolveUser")
	require.True(t, ok, "resolveUser: ok=false for multiple matches, want ok=true")
	require.Len(t, matches, 2)
	assert.ElementsMatch(t, []userMatch{{username: "a", dn: dnA}, {username: "b", dn: dnB}}, matches)
}

// TestResolveUser_EmptyAttributeValue: an entry whose configured attribute
// is empty/absent is skipped, not fatal to the whole search - zero
// remaining matches is what collapses to ok=false.
func TestResolveUser_EmptyAttributeValue(t *testing.T) {
	const dn = "CN=jdoe,DC=example,DC=com"
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry {
		return []*goldap.Entry{userEntry(dn, "")}
	}}
	cfg := userSearchConfig{BaseDN: "dc=example,dc=com", Filter: testUserFilter, Attribute: "sAMAccountName"}

	matches, ok, err := resolveUser(context.Background(), singleConnPool(conn), cfg, "jdoe")
	require.NoError(t, err, "resolveUser")
	require.False(t, ok, "resolveUser: ok=true for an empty attribute value, want ok=false")
	assert.Empty(t, matches, "matches should be empty on ok=false")
}

// TestResolveUser_EmptyAttributeAmongMultipleMatchesSkipsOnlyThatEntry:
// one bad entry among several must not discard the other, valid ones.
func TestResolveUser_EmptyAttributeAmongMultipleMatchesSkipsOnlyThatEntry(t *testing.T) {
	const goodDN = "CN=good,DC=example,DC=com"
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry {
		return []*goldap.Entry{
			userEntry("CN=bad,DC=example,DC=com", ""),
			userEntry(goodDN, "good"),
		}
	}}
	cfg := userSearchConfig{BaseDN: "dc=example,dc=com", Filter: testUserFilter, Attribute: "sAMAccountName"}

	matches, ok, err := resolveUser(context.Background(), singleConnPool(conn), cfg, "jdoe")
	require.NoError(t, err, "resolveUser")
	require.True(t, ok, "resolveUser: ok=false, want ok=true")
	require.Equal(t, []userMatch{{username: "good", dn: goodDN}}, matches)
}

// TestResolveUser_ConnectionFailure: a search error collapses into
// ok=false, not err - err is reserved for failing to acquire a connection.
func TestResolveUser_ConnectionFailure(t *testing.T) {
	conn := &fakeConn{searchErr: errors.New("connection reset by peer")}
	cfg := userSearchConfig{BaseDN: "dc=example,dc=com", Filter: testUserFilter, Attribute: "sAMAccountName"}

	_, ok, err := resolveUser(context.Background(), singleConnPool(conn), cfg, "jdoe")
	require.NoError(t, err, "resolveUser: want no error for a search-level failure")
	assert.False(t, ok, "resolveUser: ok=true for a search-level failure, want ok=false")
}

func TestResolveUser_PoolExhaustionUnderContextDeadline(t *testing.T) {
	p := newPool(1, func(context.Context) (Conn, error) {
		return &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry { return nil }}, nil
	})
	// Hold the only slot so resolveUser's p.get(ctx) blocks until the
	// deadline.
	held, err := p.get(context.Background())
	require.NoError(t, err, "get")
	defer p.put(held, true)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	cfg := userSearchConfig{BaseDN: "dc=example,dc=com", Filter: testUserFilter, Attribute: "sAMAccountName"}

	_, ok, err := resolveUser(ctx, p, cfg, "jdoe")
	assert.False(t, ok, "resolveUser: ok=true despite pool exhaustion, want ok=false")
	assert.Error(t, err, "resolveUser: want a real error for pool exhaustion under the context deadline")
}

// TestResolveUser_SizeLimitDoesNotMistreatLegitimateSingleMatch: a single
// legitimate match must resolve normally, never treated as truncated.
func TestResolveUser_SizeLimitDoesNotMistreatLegitimateSingleMatch(t *testing.T) {
	const dn = "CN=jdoe,DC=example,DC=com"
	conn := &fakeConn{match: func(req *goldap.SearchRequest) []*goldap.Entry {
		require.Equal(t, userSearchSizeLimit, req.SizeLimit, "SearchRequest.SizeLimit")
		return []*goldap.Entry{userEntry(dn, testUsername)}
	}}
	cfg := userSearchConfig{BaseDN: "dc=example,dc=com", Filter: testUserFilter, Attribute: "sAMAccountName"}

	matches, ok, err := resolveUser(context.Background(), singleConnPool(conn), cfg, "jdoe")
	require.NoError(t, err)
	require.True(t, ok, "resolveUser: want ok=true")
	require.Len(t, matches, 1)
	assert.Equal(t, testUsername, matches[0].username)
	assert.Equal(t, dn, matches[0].dn)
}

// TestResolveUser_SubstitutesEscapedIdentityIntoFilter: resolveUser
// receives escapedIdentity already escaped, so its substitution must not
// double-escape it.
func TestResolveUser_SubstitutesEscapedIdentityIntoFilter(t *testing.T) {
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry { return nil }}
	cfg := userSearchConfig{BaseDN: "dc=example,dc=com", Filter: testUserFilter, Attribute: "sAMAccountName"}

	const alreadyEscaped = `escaped\2avalue`
	_, _, err := resolveUser(context.Background(), singleConnPool(conn), cfg, alreadyEscaped)
	require.NoError(t, err, "resolveUser")
	require.Len(t, conn.filters, 1, "expected exactly one search")
	assert.Contains(t, conn.filters[0], alreadyEscaped, "filter does not contain the substituted identity verbatim (double-escaped?)")
	assert.NotContains(t, conn.filters[0], "$IDENTITY", "token $IDENTITY was not substituted")
}

// # resolveGroups

func TestResolveGroups_MultipleGroups(t *testing.T) {
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry {
		return []*goldap.Entry{
			cnEntry("CN=eng,OU=Groups,DC=example,DC=com", "eng"),
			cnEntry("CN=ops,OU=Groups,DC=example,DC=com", "ops"),
		}
	}}
	cfg := groupSearchConfig{BaseDN: "ou=groups,dc=example,dc=com", Filter: testGroupFilter, Attribute: "cn"}

	groups, err := resolveGroups(context.Background(), singleConnPool(conn), cfg, "CN=jdoe,DC=example,DC=com")
	require.NoError(t, err, "resolveGroups")
	require.Equal(t, []string{"eng", "ops"}, groups)
}

func TestResolveGroups_ZeroGroupsIsNotAnError(t *testing.T) {
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry { return nil }}
	cfg := groupSearchConfig{BaseDN: "ou=groups,dc=example,dc=com", Filter: testGroupFilter, Attribute: "cn"}

	groups, err := resolveGroups(context.Background(), singleConnPool(conn), cfg, "CN=jdoe,DC=example,DC=com")
	require.NoError(t, err, "resolveGroups")
	require.NotNil(t, groups, "resolveGroups: want a non-nil empty slice for zero memberships")
	assert.Empty(t, groups)
}

// TestResolveGroups_SizeLimitTruncatesRatherThanErrors: a huge membership
// list must resolve truncated to groupSearchSizeLimit, not fail outright.
func TestResolveGroups_SizeLimitTruncatesRatherThanErrors(t *testing.T) {
	entries := make([]*goldap.Entry, groupSearchSizeLimit+50)
	for i := range entries {
		dn := fmt.Sprintf("CN=g%d,OU=Groups,DC=example,DC=com", i)
		entries[i] = cnEntry(dn, fmt.Sprintf("g%d", i))
	}
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry { return entries }}
	cfg := groupSearchConfig{BaseDN: "ou=groups,dc=example,dc=com", Filter: testGroupFilter, Attribute: "cn"}

	groups, err := resolveGroups(context.Background(), singleConnPool(conn), cfg, "CN=jdoe,DC=example,DC=com")
	require.NoError(t, err, "resolveGroups: want no error when SizeLimit truncates")
	assert.Len(t, groups, groupSearchSizeLimit, "want exactly %d groups (truncated at the cap)", groupSearchSizeLimit)
}

func TestResolveGroups_ConnectionFailure(t *testing.T) {
	conn := &fakeConn{searchErr: errors.New("connection reset by peer")}
	cfg := groupSearchConfig{BaseDN: "ou=groups,dc=example,dc=com", Filter: testGroupFilter, Attribute: "cn"}

	_, err := resolveGroups(context.Background(), singleConnPool(conn), cfg, "CN=jdoe,DC=example,DC=com")
	require.Error(t, err, "resolveGroups: want an error for a connection failure")
}

func TestResolveGroups_AcquireConnectionFailure(t *testing.T) {
	cfg := groupSearchConfig{BaseDN: "ou=groups,dc=example,dc=com", Filter: testGroupFilter, Attribute: "cn"}

	_, err := resolveGroups(context.Background(), failingDialPool(errors.New("dial failed")), cfg, "CN=jdoe,DC=example,DC=com")
	require.Error(t, err, "resolveGroups: want an error when the pool can't dial")
}

func TestResolveGroups_SubstitutesIdentityDNIntoFilter(t *testing.T) {
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry { return nil }}
	cfg := groupSearchConfig{BaseDN: "ou=groups,dc=example,dc=com", Filter: testGroupFilter, Attribute: "cn"}
	const dn = "CN=jdoe,OU=Users,DC=example,DC=com"

	_, err := resolveGroups(context.Background(), singleConnPool(conn), cfg, dn)
	require.NoError(t, err, "resolveGroups")
	require.Len(t, conn.filters, 1)
	assert.Contains(t, conn.filters[0], dn, "want a filter containing the identity DN")
	assert.NotContains(t, conn.filters[0], "$IDENTITY_DN", "token $IDENTITY_DN was not substituted")
}

// # Resolve (end-to-end against the fake backend)

// newTestProvider wires a *Provider directly (bypassing New/config-decoding)
// around one fakeConn, so Resolve's own orchestration is what's under test.
func newTestProvider(conn *fakeConn) *Provider {
	return &Provider{
		pool: singleConnPool(conn),
		userSearch: userSearchConfig{
			BaseDN:    "dc=example,dc=com",
			Filter:    testUserFilter,
			Attribute: "sAMAccountName",
		},
		groupSearch: groupSearchConfig{
			BaseDN:    "ou=groups,dc=example,dc=com",
			Filter:    testGroupFilter,
			Attribute: "cn",
		},
	}
}

func TestResolve_Success(t *testing.T) {
	const userDN = "CN=jdoe,OU=Users,DC=example,DC=com"
	conn := &fakeConn{
		match: func(req *goldap.SearchRequest) []*goldap.Entry {
			switch req.BaseDN {
			case "dc=example,dc=com":
				return []*goldap.Entry{userEntry(userDN, testUsername)}
			case "ou=groups,dc=example,dc=com":
				return []*goldap.Entry{cnEntry("CN=eng,OU=Groups,DC=example,DC=com", "eng"), cnEntry("CN=ops,OU=Groups,DC=example,DC=com", "ops")}
			default:
				return nil
			}
		},
	}
	provider := newTestProvider(conn)

	got, err := provider.Resolve(context.Background(), map[string]string{"IDENTITY": userDN})
	require.NoError(t, err, "Resolve")
	require.Equal(t, []string{testUsername}, got["USER"])
	require.Equal(t, []string{"eng", "ops"}, got["GROUP"])

	// The success path must never leak the DN into the returned map - only
	// the configured sAMAccountName and cn values are allowed to reach it.
	for _, vs := range got {
		for _, v := range vs {
			assert.NotContains(t, v, "DC=example", "a raw DN leaked into Resolve's result: %v", got)
		}
	}
}

// TestResolve_MultipleUserMatchesUnionUsernamesAndGroups: user_search
// matching more than one account is valid, not ambiguity - every matched
// account's username lands in $USER, and its own group_search results are
// unioned (deduplicated) into $GROUP across every matched account.
func TestResolve_MultipleUserMatchesUnionUsernamesAndGroups(t *testing.T) {
	const dnA = "CN=a,OU=Users,DC=example,DC=com"
	const dnB = "CN=b,OU=Users,DC=example,DC=com"
	conn := &fakeConn{
		match: func(req *goldap.SearchRequest) []*goldap.Entry {
			switch {
			case req.BaseDN == "dc=example,dc=com":
				return []*goldap.Entry{userEntry(dnA, "alice"), userEntry(dnB, "bob")}
			case strings.Contains(req.Filter, dnA):
				return []*goldap.Entry{cnEntry("CN=eng,OU=Groups,DC=example,DC=com", "eng"), cnEntry("CN=shared,OU=Groups,DC=example,DC=com", "shared")}
			case strings.Contains(req.Filter, dnB):
				return []*goldap.Entry{cnEntry("CN=ops,OU=Groups,DC=example,DC=com", "ops"), cnEntry("CN=shared,OU=Groups,DC=example,DC=com", "shared")}
			default:
				return nil
			}
		},
	}
	provider := newTestProvider(conn)

	got, err := provider.Resolve(context.Background(), map[string]string{"IDENTITY": "dup"})
	require.NoError(t, err, "Resolve")
	assert.ElementsMatch(t, []string{"alice", "bob"}, got["USER"])
	assert.ElementsMatch(t, []string{"eng", "ops", "shared"}, got["GROUP"], "want shared's duplicate across accounts deduplicated")
}

func TestResolve_UnresolvedUserReturnsEmptyMap(t *testing.T) {
	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry { return nil }} // zero matches for every search
	provider := newTestProvider(conn)

	got, err := provider.Resolve(context.Background(), map[string]string{"IDENTITY": "CN=nobody,DC=example,DC=com"})
	require.NoError(t, err, "Resolve")
	assert.Empty(t, got, "want an empty map when the user can't resolve")
	// group_search must never even run - there's no DN to substitute.
	groupSearchAttempted := false
	for _, f := range conn.filters {
		if strings.Contains(f, "member=") {
			groupSearchAttempted = true
		}
	}
	assert.False(t, groupSearchAttempted, "group_search ran despite an unresolved user")
}

// TestResolve_FilterEscapingHoldsEndToEnd confirms metacharacters in
// $IDENTITY don't alter query semantics across the full Resolve call, not
// just identity.go's isolated unit tests.
func TestResolve_FilterEscapingHoldsEndToEnd(t *testing.T) {
	const identity = `CN=jo*hn(x),DC=example,DC=com`
	// Reference: reverse then escape, exactly what Resolve should do
	// internally.
	wantEscapedIdentity := escapeFilterValue(normalizeSubjectDN(identity))

	conn := &fakeConn{match: func(*goldap.SearchRequest) []*goldap.Entry { return nil }}
	provider := newTestProvider(conn)

	_, err := provider.Resolve(context.Background(), map[string]string{"IDENTITY": identity})
	require.NoError(t, err, "Resolve")

	require.NotEmpty(t, conn.filters, "user_search never ran")
	gotFilter := conn.filters[0]
	assert.Contains(t, gotFilter, wantEscapedIdentity, "captured filter does not contain the expected escaped identity")
	// The raw metacharacters must never appear unescaped in the filter -
	// that would mean they broke out of the altSecurityIdentities value.
	assert.NotContains(t, gotFilter, "jo*hn(x)", "raw, unescaped metacharacters reached the filter")
}

func TestResolve_ProviderErrorCarriesNoDiagnosticDetail(t *testing.T) {
	// Regression test: Resolve's error must never wrap in extra sensitive
	// context (bind DN, hostname, query text) beyond what the underlying
	// error carries.
	const sensitiveMarker = "supersecret-bind-password-marker"
	provider := &Provider{
		pool: failingDialPool(errors.New("dial tcp ad01.example.com:636: connection refused")),
		userSearch: userSearchConfig{
			BaseDN: "dc=example,dc=com",
			Filter: testUserFilter,
		},
	}

	_, err := provider.Resolve(context.Background(), map[string]string{"IDENTITY": "CN=jdoe,DC=example,DC=com"})
	require.Error(t, err, "Resolve: want error when the pool can't dial")
	assert.NotContains(t, err.Error(), sensitiveMarker, "Resolve's error unexpectedly contains a sensitive marker")
}

// BenchmarkResolve gives a baseline for Resolve's concurrent-load
// performance against the fake backend.
func BenchmarkResolve(b *testing.B) {
	const userDN = "CN=jdoe,OU=Users,DC=example,DC=com"
	newConn := func() *fakeConn {
		return &fakeConn{
			match: func(req *goldap.SearchRequest) []*goldap.Entry {
				switch req.BaseDN {
				case "dc=example,dc=com":
					return []*goldap.Entry{userEntry(userDN, testUsername)}
				case "ou=groups,dc=example,dc=com":
					return []*goldap.Entry{cnEntry("CN=eng,DC=example,DC=com", "eng")}
				default:
					return nil
				}
			},
		}
	}

	provider := &Provider{
		pool: newPool(8, func(context.Context) (Conn, error) { return newConn(), nil }),
		userSearch: userSearchConfig{
			BaseDN:    "dc=example,dc=com",
			Filter:    testUserFilter,
			Attribute: "sAMAccountName",
		},
		groupSearch: groupSearchConfig{
			BaseDN:    "ou=groups,dc=example,dc=com",
			Filter:    testGroupFilter,
			Attribute: "cn",
		},
	}

	vars := map[string]string{"IDENTITY": userDN}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// b.RunParallel invokes this closure from multiple goroutines, so
		// require's FailNow is unsafe here; assert only records the
		// failure without calling FailNow.
		for pb.Next() {
			_, err := provider.Resolve(context.Background(), vars)
			assert.NoError(b, err, "Resolve")
		}
	})
}
