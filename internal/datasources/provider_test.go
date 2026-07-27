package datasources

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// # Register / lookup / NewSet dispatch

// TestRegisterAndLookupDispatch proves Register/lookup wire a Type name to
// the right Factory, receiving the Config's Name/Raw.
func TestRegisterAndLookupDispatch(t *testing.T) {
	var gotName string
	var gotRaw yaml.Node

	Register("provider-test-dispatch", func(name string, raw yaml.Node) (Provider, error) {
		gotName = name
		gotRaw = raw
		return &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
			return map[string][]string{"OK": {"1"}}, nil
		}}, nil
	})

	raw := yaml.Node{Kind: yaml.ScalarNode, Value: "marker"}
	s, err := NewSet([]Config{{Name: "my-datasource", Type: "provider-test-dispatch", Raw: raw, CacheTTL: time.Minute}}, testLoggerSimple(t))
	require.NoError(t, err, "NewSet")
	require.Equal(t, "my-datasource", gotName, "Factory received unexpected name")
	require.Equal(t, "marker", gotRaw.Value, "Factory received unexpected raw node value")

	got := s.Resolve(context.Background(), map[string]string{"IDENTITY": "cn=dispatch"})
	if assert.Len(t, got["OK"], 1, "expected the registered provider to actually be wired in, got %v", got) {
		assert.Equal(t, "1", got["OK"][0])
	}
}

// TestNewSet_UnknownTypeErrors: a Config referencing an unregistered Type
// must fail NewSet outright, not silently produce a no-op provider.
func TestNewSet_UnknownTypeErrors(t *testing.T) {
	_, err := NewSet([]Config{{Name: "ds", Type: "no-such-type-registered", CacheTTL: time.Minute}}, testLoggerSimple(t))
	require.Error(t, err, "expected NewSet to error on an unregistered datasource type")
}

// # Set.Resolve: union, partial failure, concurrency

func TestSet_ZeroProvidersReturnsEmptyMap(t *testing.T) {
	s, err := NewSet(nil, testLoggerSimple(t))
	require.NoError(t, err, "NewSet")
	got := s.Resolve(context.Background(), map[string]string{"IDENTITY": "cn=nobody"})
	assert.Empty(t, got, "expected an empty map with zero providers configured (no hidden built-in variable)")
}

func TestSet_UnionAndDeduplication(t *testing.T) {
	p1 := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"GROUP": {"A", "B"}}, nil
	}}
	p2 := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"GROUP": {"B", "C"}}, nil
	}}
	registerFakeType(t, "fake-union-1", p1)
	registerFakeType(t, "fake-union-2", p2)

	s, err := NewSet([]Config{
		{Name: "ds1", Type: "fake-union-1", CacheTTL: time.Minute},
		{Name: "ds2", Type: "fake-union-2", CacheTTL: time.Minute},
	}, testLoggerSimple(t))
	require.NoError(t, err, "NewSet")

	got := s.Resolve(context.Background(), map[string]string{"IDENTITY": "cn=union"})
	want := []string{"A", "B", "C"}
	assert.ElementsMatch(t, want, got["GROUP"], "expected deduplicated union")
}

func TestSet_OneProviderFailsOtherSucceeds(t *testing.T) {
	good := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"GROUP": {"eng"}}, nil
	}}
	bad := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return nil, errors.New("ldap01 down")
	}}
	registerFakeType(t, "fake-good", good)
	registerFakeType(t, "fake-bad", bad)

	s, err := NewSet([]Config{
		{Name: "good", Type: "fake-good", CacheTTL: time.Minute},
		{Name: "bad", Type: "fake-bad", CacheTTL: time.Minute},
	}, testLoggerSimple(t))
	require.NoError(t, err, "NewSet")

	got := s.Resolve(context.Background(), map[string]string{"IDENTITY": "cn=partial"})
	want := map[string][]string{"GROUP": {"eng"}}
	require.Equal(t, want, got, "expected the failing provider to simply be absent from the union (not empty/failed result)")
}

func TestSet_AllProvidersFail(t *testing.T) {
	bad1 := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return nil, errors.New("down1")
	}}
	bad2 := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return nil, errors.New("down2")
	}}
	registerFakeType(t, "fake-allfail-1", bad1)
	registerFakeType(t, "fake-allfail-2", bad2)

	s, err := NewSet([]Config{
		{Name: "b1", Type: "fake-allfail-1", CacheTTL: time.Minute},
		{Name: "b2", Type: "fake-allfail-2", CacheTTL: time.Minute},
	}, testLoggerSimple(t))
	require.NoError(t, err, "NewSet")

	// Deliberately its own test: 2+ providers all failing must produce the
	// same empty result as zero providers configured.
	got := s.Resolve(context.Background(), map[string]string{"IDENTITY": "cn=allfail"})
	assert.Empty(t, got, "expected an empty map when every configured provider fails")
}

// TestSet_ResolveFansOutConcurrently: two delayed providers must be queried
// concurrently - wall time should track the slowest one, not their sum.
func TestSet_ResolveFansOutConcurrently(t *testing.T) {
	const delay = 150 * time.Millisecond
	p1 := &fakeProvider{delay: delay, resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"A": {"1"}}, nil
	}}
	p2 := &fakeProvider{delay: delay, resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"B": {"2"}}, nil
	}}
	registerFakeType(t, "fake-timing-1", p1)
	registerFakeType(t, "fake-timing-2", p2)

	s, err := NewSet([]Config{
		{Name: "t1", Type: "fake-timing-1", CacheTTL: time.Minute},
		{Name: "t2", Type: "fake-timing-2", CacheTTL: time.Minute},
	}, testLoggerSimple(t))
	require.NoError(t, err, "NewSet")

	start := time.Now()
	got := s.Resolve(context.Background(), map[string]string{"IDENTITY": "cn=timing"})
	elapsed := time.Since(start)

	assert.NotEmpty(t, got["A"], "expected both providers to contribute, got %v", got)
	assert.NotEmpty(t, got["B"], "expected both providers to contribute, got %v", got)

	sum := 2 * delay
	assert.Less(t, elapsed, sum, "Set.Resolve took %v, expected well under the sequential sum %v - providers are not being queried concurrently", elapsed, sum)
	// Generous slack for scheduling jitter in a container; the point is
	// "closer to max than sum", not a tight bound.
	assert.LessOrEqual(t, elapsed, delay+200*time.Millisecond, "Set.Resolve took %v, expected close to the slowest single provider's delay (%v)", elapsed, delay)
}

// TestSet_ProviderErrorsNeverLeakBackendDetail is a leakage-regression test:
// a sensitive marker in a provider's error must never reach Set.Resolve's
// return value, only its server-side log.
func TestSet_ProviderErrorsNeverLeakBackendDetail(t *testing.T) {
	const marker = "supersecret-ldap-bind-pw-hunter2@ad01.internal.example.com"

	p := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return nil, fmt.Errorf("bind to ldaps://ad01.internal.example.com failed: invalid credentials for %s", marker)
	}}
	registerFakeType(t, "fake-leak", p)

	logger, handler := newTestLogger(t)
	s, err := NewSet([]Config{{Name: "ds", Type: "fake-leak", CacheTTL: time.Minute}}, logger)
	require.NoError(t, err, "NewSet")

	got := s.Resolve(context.Background(), map[string]string{"IDENTITY": "cn=leak,dc=example,dc=com"})

	require.Empty(t, got, "expected an empty result from a failing provider")
	for name, values := range got {
		for _, v := range values {
			assert.False(t, strings.Contains(v, marker) || strings.Contains(name, marker), "marker leaked into Set.Resolve's return value via %s=%s", name, v)
		}
	}

	// Sanity check the marker really was logged server-side, so this isn't
	// a vacuous test.
	foundServerSide := false
	for _, r := range handler.all() {
		if strings.Contains(r.Message, marker) {
			foundServerSide = true
		}
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Value.String(), marker) {
				foundServerSide = true
			}
			return true
		})
	}
	assert.True(t, foundServerSide, "expected the full provider error (including the marker) to be logged server-side, per the 'log full error, never return it' contract")
}

// # sanitize / validVarValue

func TestValidVarValue(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantOK     bool
		wantReason string
	}{
		{"empty", "", false, "empty"},
		{"ordinary DN", "cn=alice,dc=example,dc=com", true, ""},
		{"too long", strings.Repeat("a", maxVarValueLen+1), false, "too long"},
		{"control char (bell)", "cn=al\x07ice", false, "contains control characters"},
		{"NUL byte", "cn=al\x00ice", false, "contains control characters"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := validVarValue(tc.value)
			require.Equal(t, tc.wantOK, ok, "reason %q", reason)
			if !ok {
				assert.Equal(t, tc.wantReason, reason)
			}
		})
	}
}

// TestSet_SanitizeIdentityFailureShortCircuits: a failing IDENTITY must
// block every provider, log exactly one WARN, and never log the raw value.
func TestSet_SanitizeIdentityFailureShortCircuits(t *testing.T) {
	p := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"USER": {"unreachable"}}, nil
	}}
	registerFakeType(t, "fake-sanitize-identity", p)

	logger, handler := newTestLogger(t)
	s, err := NewSet([]Config{{Name: "ds", Type: "fake-sanitize-identity", CacheTTL: time.Minute}}, logger)
	require.NoError(t, err, "NewSet")

	const badIdentity = "cn=bad\x00null,dc=example,dc=com"
	got := s.Resolve(context.Background(), map[string]string{"IDENTITY": badIdentity})

	assert.Empty(t, got, "expected an empty/unresolved result")
	assert.Equal(t, 0, p.callCount(), "expected the provider to never be called when IDENTITY fails sanitization")

	recs := handler.recordsWithMessage("rejected untrusted datasource input variable")
	require.Len(t, recs, 1, "expected exactly one WARN for the rejection")
	assert.Equal(t, slog.LevelWarn, recs[0].Level, "expected the rejection to log at WARN")

	varName, _ := attrString(recs[0], "variable")
	assert.Equal(t, "IDENTITY", varName, "expected the WARN to name IDENTITY")
	reason, _ := attrString(recs[0], "reason")
	assert.NotEmpty(t, reason, "expected the WARN to include why the value was rejected")
	loggedValue, _ := attrString(recs[0], "value")
	assert.False(t, loggedValue == badIdentity || strings.Contains(loggedValue, "\x00"), "rejected value must not appear verbatim (or with raw control bytes) in the log, got %q", loggedValue)
}

// TestSet_SanitizeNonIdentityFailureDropsButProceeds: a failing
// non-IDENTITY variable is dropped and logged, but must not block the call.
func TestSet_SanitizeNonIdentityFailureDropsButProceeds(t *testing.T) {
	var seenVars map[string]string
	p := &fakeProvider{resolve: func(_ context.Context, vars map[string]string) (map[string][]string, error) {
		seenVars = vars
		return map[string][]string{"USER": {"ok"}}, nil
	}}
	registerFakeType(t, "fake-sanitize-other", p)

	logger, handler := newTestLogger(t)
	s, err := NewSet([]Config{{Name: "ds", Type: "fake-sanitize-other", CacheTTL: time.Minute}}, logger)
	require.NoError(t, err, "NewSet")

	vars := map[string]string{
		"IDENTITY": "cn=good,dc=example,dc=com",
		"EXTRA":    "bad\x01value",
	}
	got := s.Resolve(context.Background(), vars)

	assert.NotEmpty(t, got, "expected the call to proceed despite the dropped variable")
	assert.Equal(t, 1, p.callCount(), "expected the provider to still be called once")
	require.NotNil(t, seenVars, "provider was never invoked")
	_, present := seenVars["EXTRA"]
	assert.False(t, present, "expected the failing non-IDENTITY variable to be dropped before reaching the provider, got %v", seenVars)
	assert.Equal(t, "cn=good,dc=example,dc=com", seenVars["IDENTITY"], "expected IDENTITY to still reach the provider unchanged")

	recs := handler.recordsWithMessage("rejected untrusted datasource input variable")
	require.Len(t, recs, 1, "expected exactly one WARN for the dropped variable")
	varName, _ := attrString(recs[0], "variable")
	assert.Equal(t, "EXTRA", varName, "expected the WARN to name EXTRA")
}

func TestSet_SanitizeWarnIncludesRequestContext(t *testing.T) {
	p := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{}, nil
	}}
	registerFakeType(t, "fake-sanitize-reqctx", p)

	logger, handler := newTestLogger(t)
	s, err := NewSet([]Config{{Name: "ds", Type: "fake-sanitize-reqctx", CacheTTL: time.Minute}}, logger)
	require.NoError(t, err, "NewSet")

	ctx := WithRequestContext(context.Background(), "POST", "/v1.43/containers/create")
	s.Resolve(ctx, map[string]string{"IDENTITY": ""})

	recs := handler.recordsWithMessage("rejected untrusted datasource input variable")
	require.Len(t, recs, 1, "expected exactly one WARN")
	method, _ := attrString(recs[0], "request_method")
	uri, _ := attrString(recs[0], "request_uri")
	assert.Equal(t, "POST", method, "expected request context on the WARN log")
	assert.Equal(t, "/v1.43/containers/create", uri, "expected request context on the WARN log")
}

// # Set.Flush

// TestSet_FlushClearsEveryProvider proves Flush reaches every provider's
// cache, not just the first.
func TestSet_FlushClearsEveryProvider(t *testing.T) {
	p1 := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"A": {"1"}}, nil
	}}
	p2 := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"B": {"2"}}, nil
	}}
	registerFakeType(t, "fake-flush-1", p1)
	registerFakeType(t, "fake-flush-2", p2)

	s, err := NewSet([]Config{
		{Name: "f1", Type: "fake-flush-1", CacheTTL: time.Hour},
		{Name: "f2", Type: "fake-flush-2", CacheTTL: time.Hour},
	}, testLoggerSimple(t))
	require.NoError(t, err, "NewSet")

	vars := map[string]string{"IDENTITY": "cn=flushall"}
	s.Resolve(context.Background(), vars)
	s.Resolve(context.Background(), vars)
	require.Equal(t, 1, p1.callCount(), "expected 1 call before Flush")
	require.Equal(t, 1, p2.callCount(), "expected 1 call before Flush")

	s.Flush()
	s.Resolve(context.Background(), vars)
	assert.Equal(t, 2, p1.callCount(), "expected Flush to force both providers to re-resolve")
	assert.Equal(t, 2, p2.callCount(), "expected Flush to force both providers to re-resolve")
}
