// This file also covers Matcher.Allowed's documented contract (see
// mounts.go's "Prefix matching" section), restated here verbatim:
//
// a canonicalized request path P matches a configured prefix Q
// (post-expansion, post-filepath.Clean) if and only if P == Q, or P begins
// with Q followed immediately by "/". No other condition ever produces a
// match.
package rules

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/weishiuchang/authzmtls/internal/datasources"
)

// mkdir creates dir under t's temp dir and returns its path, since
// Canonicalize requires the path to actually exist.
func mkdir(t *testing.T, elem ...string) string {
	t.Helper()
	p := filepath.Join(elem...)
	require.NoError(t, os.MkdirAll(p, 0o755), "MkdirAll(%s)", p)
	return p
}

// # Docker request-shape parsing

const containerCreateLegacyBinds = `{
	"Image": "alpine",
	"HostConfig": {
		"Binds": ["/data/app1:/mnt:rw", "/data/app2:/mnt2"]
	}
}`

const containerCreateModernMounts = `{
	"Image": "alpine",
	"HostConfig": {
		"Mounts": [
			{"Type": "bind", "Source": "/data/app1", "Target": "/mnt", "ReadOnly": false},
			{"Type": "bind", "Source": "/data/app2", "Target": "/mnt2", "ReadOnly": true}
		]
	}
}`

const containerCreateNoMounts = `{
	"Image": "alpine",
	"HostConfig": {}
}`

const containerCreateHostNetwork = `{
	"Image": "alpine",
	"HostConfig": {"NetworkMode": "host"}
}`

const containerCreateOtherNetwork = `{
	"Image": "alpine",
	"HostConfig": {"NetworkMode": "bridge"}
}`

const containerCreatePrivilegedTrue = `{
	"Image": "alpine",
	"HostConfig": {"Privileged": true}
}`

const containerCreatePrivilegedFalse = `{
	"Image": "alpine",
	"HostConfig": {"Privileged": false}
}`

const containerCreateCombined = `{
	"Image": "alpine",
	"HostConfig": {
		"Binds": ["/data/app1:/mnt:rw"],
		"Mounts": [{"Type": "bind", "Source": "/data/app2", "Target": "/mnt2", "ReadOnly": false}],
		"NetworkMode": "host",
		"Privileged": true
	}
}`

func TestBinds(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		body string
		want []string
	}{
		{"legacy binds", "/v1.43/containers/create", containerCreateLegacyBinds, []string{"/data/app1", "/data/app2"}},
		{"modern mounts", "/v1.43/containers/create", containerCreateModernMounts, []string{"/data/app1", "/data/app2"}},
		{"no mounts", "/v1.43/containers/create", containerCreateNoMounts, []string{}},
		{"combined", "/v1.43/containers/create", containerCreateCombined, []string{"/data/app1", "/data/app2"}},
		{"non-matching uri", "/v1.43/containers/1234/start", containerCreateLegacyBinds, []string{}},
		{"no version prefix", "/containers/create", containerCreateLegacyBinds, []string{"/data/app1", "/data/app2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Binds(tt.uri, []byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNetworkMode(t *testing.T) {
	cases := []struct {
		name     string
		uri      string
		body     string
		wantMode string
		wantOK   bool
	}{
		{"host", "/v1.43/containers/create", containerCreateHostNetwork, "host", true},
		{"other", "/v1.43/containers/create", containerCreateOtherNetwork, "bridge", true},
		{"absent", "/v1.43/containers/create", containerCreateNoMounts, "", false},
		{"combined", "/v1.43/containers/create", containerCreateCombined, "host", true},
		{"non-matching uri", "/v1.43/containers/1234/start", containerCreateHostNetwork, "", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			gotMode, gotOK := NetworkMode(tt.uri, []byte(tt.body))
			assert.Equal(t, tt.wantMode, gotMode)
			assert.Equal(t, tt.wantOK, gotOK)
		})
	}
}

func TestPrivileged(t *testing.T) {
	cases := []struct {
		name    string
		uri     string
		body    string
		wantVal bool
		wantOK  bool
	}{
		{"true", "/v1.43/containers/create", containerCreatePrivilegedTrue, true, true},
		{"false", "/v1.43/containers/create", containerCreatePrivilegedFalse, false, true},
		{"absent", "/v1.43/containers/create", containerCreateNoMounts, false, false},
		{"combined", "/v1.43/containers/create", containerCreateCombined, true, true},
		{"non-matching uri", "/v1.43/containers/1234/start", containerCreatePrivilegedTrue, false, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			gotVal, gotOK := Privileged(tt.uri, []byte(tt.body))
			assert.Equal(t, tt.wantVal, gotVal)
			assert.Equal(t, tt.wantOK, gotOK)
		})
	}
}

// TestCombinedSingleDecode confirms all three accessors read correctly from
// one request body carrying mounts, host networking, and privileged mode at once.
func TestCombinedSingleDecode(t *testing.T) {
	uri := "/v1.43/containers/create"
	body := []byte(containerCreateCombined)

	wantBinds := []string{"/data/app1", "/data/app2"}
	assert.Equal(t, wantBinds, Binds(uri, body))

	mode, ok := NetworkMode(uri, body)
	assert.Equal(t, "host", mode)
	assert.True(t, ok)

	priv, ok := Privileged(uri, body)
	assert.True(t, priv)
	assert.True(t, ok)
}

const volumeCreateBindDevice = `{
	"Name": "myvol",
	"Driver": "local",
	"DriverOpts": {"type": "none", "o": "bind", "device": "/etc"}
}`

const volumeCreateDriverAbsent = `{
	"Name": "myvol",
	"DriverOpts": {"type": "none", "o": "bind", "device": "/etc"}
}`

const volumeCreateDriverEmpty = `{
	"Name": "myvol",
	"Driver": "",
	"DriverOpts": {"type": "none", "o": "bind", "device": "/etc"}
}`

const volumeCreateORwBind = `{
	"Name": "myvol",
	"Driver": "local",
	"DriverOpts": {"o": "rw,bind", "device": "/etc"}
}`

const volumeCreateOBindRw = `{
	"Name": "myvol",
	"Driver": "local",
	"DriverOpts": {"o": "bind,rw", "device": "/etc"}
}`

const volumeCreateORbind = `{
	"Name": "myvol",
	"Driver": "local",
	"DriverOpts": {"o": "rbind", "device": "/etc"}
}`

const volumeCreatePlain = `{
	"Name": "myvol"
}`

const volumeCreateNonLocalDriver = `{
	"Name": "myvol",
	"Driver": "nfs",
	"DriverOpts": {"type": "none", "o": "bind", "device": "/etc"}
}`

const volumeCreateNoDevice = `{
	"Name": "myvol",
	"Driver": "local",
	"DriverOpts": {"o": "bind"}
}`

func TestVolumeBindDevice(t *testing.T) {
	cases := []struct {
		name     string
		uri      string
		body     string
		wantPath string
		wantOK   bool
	}{
		{"type=none,o=bind,device recognized", "/v1.43/volumes/create", volumeCreateBindDevice, "/etc", true},
		{"driver absent defaults to local", "/v1.43/volumes/create", volumeCreateDriverAbsent, "/etc", true},
		{"driver empty string defaults to local", "/v1.43/volumes/create", volumeCreateDriverEmpty, "/etc", true},
		{"o=rw,bind recognized", "/v1.43/volumes/create", volumeCreateORwBind, "/etc", true},
		{"o=bind,rw recognized", "/v1.43/volumes/create", volumeCreateOBindRw, "/etc", true},
		{"o=rbind not recognized (substring)", "/v1.43/volumes/create", volumeCreateORbind, "", false},
		{"plain volume create not recognized", "/v1.43/volumes/create", volumeCreatePlain, "", false},
		{"non-local driver not recognized", "/v1.43/volumes/create", volumeCreateNonLocalDriver, "", false},
		{"missing device not recognized", "/v1.43/volumes/create", volumeCreateNoDevice, "", false},
		{"non-volume-create request", "/v1.43/containers/create", volumeCreateBindDevice, "", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotOK := VolumeBindDevice(tt.uri, []byte(tt.body))
			assert.Equal(t, tt.wantPath, gotPath)
			assert.Equal(t, tt.wantOK, gotOK)
		})
	}
}

func TestIsDockerCP(t *testing.T) {
	cases := []struct {
		name   string
		method string
		uri    string
		want   bool
	}{
		{"GET with v1.43 prefix", "GET", "/v1.43/containers/abc123/archive", true},
		{"PUT with v1.24 prefix", "PUT", "/v1.24/containers/mycontainer/archive", true},
		{"GET no version prefix", "GET", "/containers/abc123/archive", true},
		{"GET with query string", "GET", "/v1.43/containers/abc123/archive?path=%2Fetc", true},
		{"wrong method", "POST", "/v1.43/containers/abc123/archive", false},
		{"DELETE wrong method", "DELETE", "/v1.43/containers/abc123/archive", false},
		{"wrong subresource logs", "GET", "/v1.43/containers/abc123/logs", false},
		{"exec create not archive", "POST", "/v1.43/containers/abc123/exec", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDockerCP(tt.method, tt.uri)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsDockerExecCreate(t *testing.T) {
	cases := []struct {
		name   string
		method string
		uri    string
		want   bool
	}{
		{"POST with v1.43 prefix", "POST", "/v1.43/containers/abc123/exec", true},
		{"POST with v1.24 prefix", "POST", "/v1.24/containers/mycontainer/exec", true},
		{"POST no version prefix", "POST", "/containers/abc123/exec", true},
		{"wrong method GET", "GET", "/v1.43/containers/abc123/exec", false},
		{"wrong subresource logs", "POST", "/v1.43/containers/abc123/logs", false},
		{"does not match exec start", "POST", "/v1.43/exec/abc123/start", false},
		{"does not match archive", "GET", "/v1.43/containers/abc123/archive", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDockerExecCreate(tt.method, tt.uri)
			assert.Equal(t, tt.want, got)
		})
	}
}

// # MountAllowlistRule

func TestMountAllowlistRule_Allow(t *testing.T) {
	base := t.TempDir()
	allowed := mkdir(t, base, "data", "allowed")

	rule := NewMountAllowlistRule([]string{allowed}, newDatasourceSet(t))
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, allowed)))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict, "detail: %s", d.Detail)
	assert.Contains(t, d.Detail, allowed)
}

func TestMountAllowlistRule_Deny(t *testing.T) {
	base := t.TempDir()
	allowed := mkdir(t, base, "data", "allowed")
	other := mkdir(t, base, "etc")

	rule := NewMountAllowlistRule([]string{allowed}, newDatasourceSet(t))
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, other)))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict)
	assert.Contains(t, d.Msg, other, "want Msg to name the offending path")
}

func TestMountAllowlistRule_AbstainNonContainerCreate(t *testing.T) {
	rule := NewMountAllowlistRule([]string{"/data"}, newDatasourceSet(t))
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "GET", notAContainerURI, nil))
	require.NoError(t, err)
	require.Equal(t, Abstain, d.Verdict)
}

func TestMountAllowlistRule_AbstainNoMounts(t *testing.T) {
	rule := NewMountAllowlistRule([]string{"/data"}, newDatasourceSet(t))
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t)))
	require.NoError(t, err)
	require.Equal(t, Abstain, d.Verdict)
}

func TestMountAllowlistRule_MultipleMountsOnlyOneDisallowed(t *testing.T) {
	base := t.TempDir()
	allowed := mkdir(t, base, "data", "allowed")
	allowedChild := mkdir(t, allowed, "child")
	disallowed := mkdir(t, base, "etc")

	rule := NewMountAllowlistRule([]string{allowed}, newDatasourceSet(t))
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI,
		containerCreateBody(t, allowedChild, disallowed)))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict)
	assert.Contains(t, d.Msg, disallowed, "want Msg to name the disallowed path, not the allowed one")
}

func TestMountAllowlistRule_VariableExpansionAllows(t *testing.T) {
	base := t.TempDir()
	aliceDir := mkdir(t, base, "home", "alice")
	pattern := filepath.Join(base, "home", "$USER")

	provider := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"USER": {"alice"}}, nil
	}}
	typeName := registerFakeProviderType(t, provider)
	ds := newDatasourceSet(t, datasources.Config{Name: "ds", Type: typeName})

	rule := NewMountAllowlistRule([]string{pattern}, ds)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, aliceDir)))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict, "only reachable after $USER expansion - detail: %s", d.Detail)
}

// TestMountAllowlistRule_UnresolvedVariableSkipped proves an allowlist entry
// referencing a never-resolving variable is silently skipped, not treated
// as an error, and doesn't block a sibling literal entry.
func TestMountAllowlistRule_UnresolvedVariableSkipped(t *testing.T) {
	base := t.TempDir()
	allowed := mkdir(t, base, "data", "allowed")
	unreachablePattern := filepath.Join(base, "remote", "$GROUP") // $GROUP never resolves: zero datasources

	rule := NewMountAllowlistRule([]string{unreachablePattern, allowed}, newDatasourceSet(t))
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, allowed)))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict, "an unresolved $VAR entry must not error out or block a sibling literal entry")
}

// TestMountAllowlistRule_LeakageRegression proves a Provider error
// containing a sensitive marker string never reaches Decision.Msg/Detail.
func TestMountAllowlistRule_LeakageRegression(t *testing.T) {
	const marker = "supersecret-ldap-bind-pw-hunter2@ad01.internal.example.com"

	base := t.TempDir()
	requested := mkdir(t, base, "remote", "x") // only reachable via the never-resolving $GROUP entry below
	pattern := filepath.Join(base, "remote", "$GROUP")

	provider := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return nil, fmt.Errorf("bind to ldaps://ad01.internal.example.com failed: invalid credentials for %s", marker)
	}}
	typeName := registerFakeProviderType(t, provider)
	ds := newDatasourceSet(t, datasources.Config{Name: "ds", Type: typeName})

	rule := NewMountAllowlistRule([]string{pattern}, ds)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, requested)))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict, "the datasource never resolves $GROUP")
	require.NotContains(t, d.Msg, marker, "marker leaked into Decision.Msg")
	require.NotContains(t, d.Detail, marker, "marker leaked into Decision.Detail")
}

// # VolumeBindMountRule

func TestVolumeBindMountRule_Allow(t *testing.T) {
	base := t.TempDir()
	allowed := mkdir(t, base, "data", "allowed")

	rule := NewVolumeBindMountRule([]string{allowed}, newDatasourceSet(t))
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", volumeCreateURI, volumeCreateBindBody(t, allowed)))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict, "detail: %s", d.Detail)
}

func TestVolumeBindMountRule_Deny(t *testing.T) {
	base := t.TempDir()
	allowed := mkdir(t, base, "data", "allowed")
	device := mkdir(t, base, "etc")

	rule := NewVolumeBindMountRule([]string{allowed}, newDatasourceSet(t))
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", volumeCreateURI, volumeCreateBindBody(t, device)))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict)
	assert.Contains(t, d.Msg, device, "want Msg to name the offending device path")
	assert.Contains(t, strings.ToLower(d.Msg), "volume", "want Msg to identify this as a volume-create request (not container-create)")
}

func TestVolumeBindMountRule_AbstainNonVolumeCreate(t *testing.T) {
	rule := NewVolumeBindMountRule([]string{"/data"}, newDatasourceSet(t))
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "GET", notAContainerURI, nil))
	require.NoError(t, err)
	require.Equal(t, Abstain, d.Verdict)
}

// TestVolumeBindMountRule_AbstainNotBindStyle proves an "unrecognized"
// result from VolumeBindDevice drives Abstain; recognition itself is
// tested above (TestVolumeBindDevice).
func TestVolumeBindMountRule_AbstainNotBindStyle(t *testing.T) {
	rule := NewVolumeBindMountRule([]string{"/data"}, newDatasourceSet(t))
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", volumeCreateURI, volumeCreatePlainBody(t)))
	require.NoError(t, err)
	require.Equal(t, Abstain, d.Verdict, "plain named volume, no bind-style DriverOpts")
}

// TestVolumeBindMountRule_VariableExpansionAllows proves this rule shares
// MountAllowlistRule's resolveMatcher path by exercising $USER expansion
// here too.
func TestVolumeBindMountRule_VariableExpansionAllows(t *testing.T) {
	base := t.TempDir()
	aliceDir := mkdir(t, base, "home", "alice")
	pattern := filepath.Join(base, "home", "$USER")

	provider := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return map[string][]string{"USER": {"alice"}}, nil
	}}
	typeName := registerFakeProviderType(t, provider)
	ds := newDatasourceSet(t, datasources.Config{Name: "ds", Type: typeName})

	rule := NewVolumeBindMountRule([]string{pattern}, ds)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", volumeCreateURI, volumeCreateBindBody(t, aliceDir)))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict, "only reachable after $USER expansion - detail: %s", d.Detail)
}

// # no datasource available (zero configured / all failing) contract

// TestNoDatasourceAvailable_ZeroDatasources covers a datasources.Set built
// from an empty config: a mount request matching only a $VAR-referencing
// allowlist entry must be denied, since $GROUP can never resolve.
func TestNoDatasourceAvailable_ZeroDatasources(t *testing.T) {
	base := t.TempDir()
	remoteX := mkdir(t, base, "remote", "x")
	pattern := filepath.Join(base, "remote", "$GROUP")

	rule := NewMountAllowlistRule([]string{pattern}, newDatasourceSet(t)) // zero datasources.Config entries

	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, remoteX)))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict, "$GROUP can never resolve with zero datasources configured")
}

// TestNoDatasourceAvailable_AllConfiguredFail covers the other way to reach
// the same Deny outcome: a configured datasource that fails, for an
// identity with no prior successfully-resolved value.
func TestNoDatasourceAvailable_AllConfiguredFail(t *testing.T) {
	base := t.TempDir()
	remoteX := mkdir(t, base, "remote", "x")
	pattern := filepath.Join(base, "remote", "$GROUP")

	provider := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return nil, errors.New("backend unreachable")
	}}
	typeName := registerFakeProviderType(t, provider)
	ds := newDatasourceSet(t, datasources.Config{Name: "ds", Type: typeName})

	rule := NewMountAllowlistRule([]string{pattern}, ds)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, remoteX)))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict, "every configured datasource is failing and this identity has never resolved")
}

// TestNoDatasourceAvailable_MixedAllowlist proves a datasource outage only
// narrows the $VAR-dependent part of an allowlist: a sibling literal entry
// must still allow.
func TestNoDatasourceAvailable_MixedAllowlist(t *testing.T) {
	base := t.TempDir()
	allowed := mkdir(t, base, "data", "allowed")
	remoteX := mkdir(t, base, "remote", "x")
	patterns := []string{filepath.Join(base, "remote", "$GROUP"), allowed}

	provider := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		return nil, errors.New("backend unreachable")
	}}
	typeName := registerFakeProviderType(t, provider)
	ds := newDatasourceSet(t, datasources.Config{Name: "ds", Type: typeName})

	rule := NewMountAllowlistRule(patterns, ds)

	literalDecision, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, allowed)))
	require.NoError(t, err)
	require.Equal(t, Allow, literalDecision.Verdict, "a down datasource must not narrow an allowlist entry that never depended on it")

	varDecision, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, remoteX)))
	require.NoError(t, err)
	require.Equal(t, Deny, varDecision.Verdict)
}

// TestNoDatasourceAvailable_DoesNotOverrideStaleWhileRevalidate proves the
// "no datasource => deny" contract doesn't apply once an identity has
// resolved successfully before: stale-while-revalidate keeps serving the
// last known-good value through an outage instead.
//
// This uses a real, short CacheTTL and a real sleep to push the seeded
// cache entry past its refresh window, since datasources' clock hook is
// package-private.
func TestNoDatasourceAvailable_DoesNotOverrideStaleWhileRevalidate(t *testing.T) {
	base := t.TempDir()
	remoteX := mkdir(t, base, "remote", "x")
	pattern := filepath.Join(base, "remote", "$GROUP")

	succeeding := true
	provider := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) {
		if succeeding {
			return map[string][]string{"GROUP": {"x"}}, nil
		}
		return nil, errors.New("backend unreachable")
	}}
	typeName := registerFakeProviderType(t, provider)
	ds := newDatasourceSet(t, datasources.Config{Name: "ds", Type: typeName, CacheTTL: 20 * time.Millisecond})

	rule := NewMountAllowlistRule([]string{pattern}, ds)
	request := req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, remoteX))

	// Seeds the cache with GROUP=x.
	first, err := rule.Evaluate(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, Allow, first.Verdict)

	// Pushes past the refresh window so the next call must fall back to the
	// still-cached GROUP=x rather than the now-failing live fetch.
	succeeding = false
	time.Sleep(50 * time.Millisecond)

	second, err := rule.Evaluate(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, Allow, second.Verdict, "must keep serving the last known-good value, not fall back to deny")
}

// # multi-datasource union (MountAllowlistRule side)

// twoProviderSet builds a *datasources.Set over exactly two fake providers,
// resolving independently of each other (and independently of the request's
// vars) - enough to prove how Set.Resolve unions their two contributions,
// which is what every test using it is actually about.
func twoProviderSet(t *testing.T, a, b map[string][]string) *datasources.Set {
	t.Helper()
	providerA := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) { return a, nil }}
	providerB := &fakeProvider{resolve: func(context.Context, map[string]string) (map[string][]string, error) { return b, nil }}

	typeA := "multi-ds-a:" + t.Name()
	typeB := "multi-ds-b:" + t.Name()
	datasources.Register(typeA, func(string, yaml.Node) (datasources.Provider, error) { return providerA, nil })
	datasources.Register(typeB, func(string, yaml.Node) (datasources.Provider, error) { return providerB, nil })

	set, err := datasources.NewSet([]datasources.Config{{Name: "a", Type: typeA}, {Name: "b", Type: typeB}}, nil)
	require.NoError(t, err)
	return set
}

// TestMultiDatasource_OnlyOneSourceResolvesStillValidatesAgainstAllowlist
// confirms claim 1: with two datasources configured, only one of which
// actually resolves this subject DN (the other contributes nothing, e.g.
// "not found in that directory"), the resolved $USER still validates
// normally against the allowlist.
func TestMultiDatasource_OnlyOneSourceResolvesStillValidatesAgainstAllowlist(t *testing.T) {
	base := t.TempDir()
	aliceDir := mkdir(t, base, "home", "alice")
	otherDir := mkdir(t, base, "home", "mallory") // not $USER-derived - must stay denied

	ds := twoProviderSet(t,
		map[string][]string{"USER": {"alice"}}, // datasource a: resolves
		map[string][]string{},                  // datasource b: unresolved in this directory
	)
	rule := NewMountAllowlistRule([]string{filepath.Join(base, "home", "$USER")}, ds)

	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, aliceDir)))
	require.NoError(t, err)
	assert.Equal(t, Allow, d.Verdict, "detail=%q", d.Detail)

	d, err = rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, otherDir)))
	require.NoError(t, err)
	assert.Equal(t, Deny, d.Verdict, "a path for a different, unresolved user must still be denied")
}

// TestMultiDatasource_BothSourcesResolveUnionsAccessAcrossBoth confirms
// claim 2: when the subject DN resolves in *every* configured datasource
// (here, to two different $USER/$GROUP values - e.g. a different account
// per AD forest), access is the union of what either identity's values
// expand to, not just one datasource's contribution.
func TestMultiDatasource_BothSourcesResolveUnionsAccessAcrossBoth(t *testing.T) {
	base := t.TempDir()
	aliceDir := mkdir(t, base, "home", "alice")
	alice2Dir := mkdir(t, base, "home", "alice2")
	engDir := mkdir(t, base, "remote", "eng")
	opsDir := mkdir(t, base, "remote", "ops")
	malloryDir := mkdir(t, base, "home", "mallory")

	ds := twoProviderSet(t,
		map[string][]string{"USER": {"alice"}, "GROUP": {"eng"}},
		map[string][]string{"USER": {"alice2"}, "GROUP": {"ops"}},
	)
	rule := NewMountAllowlistRule([]string{
		filepath.Join(base, "home", "$USER"),
		filepath.Join(base, "remote", "$GROUP"),
	}, ds)

	for _, dir := range []string{aliceDir, alice2Dir, engDir, opsDir} {
		d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, dir)))
		require.NoError(t, err)
		assert.Equal(t, Allow, d.Verdict, "path %q (formed from one of the two datasources) should be allowed: detail=%q", dir, d.Detail)
	}

	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, malloryDir)))
	require.NoError(t, err)
	assert.Equal(t, Deny, d.Verdict, "a path matching neither datasource's contribution must still be denied")
}

// # Matcher.Allowed: table-driven contract tests

func TestMatcherAllowed(t *testing.T) {
	longSeg := strings.Repeat("a", 4000)
	longPrefix := "/data/" + longSeg
	longPath := longPrefix + "/sub"

	tests := []struct {
		name     string
		prefixes []string
		path     string
		want     bool
	}{
		{"exact match", []string{"/data/app1"}, "/data/app1", true},
		{"descendant one level", []string{"/data/app1"}, "/data/app1/x", true},
		{"descendant two levels", []string{"/data/app1"}, "/data/app1/x/y", true},
		{"descendant five levels", []string{"/data/app1"}, "/data/app1/a/b/c/d/e", true},

		// The false-positive case, both flavors, both directions.
		{"app1 vs app12, no match", []string{"/data/app1"}, "/data/app12", false},
		{"app1 vs app1x, no match", []string{"/data/app1"}, "/data/app1x", false},
		{"app12 configured, app1 requested, no match", []string{"/data/app12"}, "/data/app1", false},
		{"app1x configured, app1 requested, no match", []string{"/data/app1x"}, "/data/app1", false},
		{"app1 vs app12 descendant, no match", []string{"/data/app1"}, "/data/app12/x", false},

		// Trailing slash, all four combinations, same logical directory.
		{"no trailing slash either side", []string{"/data/app1"}, "/data/app1", true},
		{"trailing slash on prefix only", []string{"/data/app1/"}, "/data/app1", true},
		{"trailing slash on path only", []string{"/data/app1"}, "/data/app1/", true},
		{"trailing slash on both", []string{"/data/app1/"}, "/data/app1/", true},
		{"trailing slash on prefix, descendant path", []string{"/data/app1/"}, "/data/app1/sub", true},

		// Root.
		{"root matches an arbitrary path", []string{"/"}, "/anything/at/all", true},
		{"root matches root itself", []string{"/"}, "/", true},
		{"root matches a one-level path", []string{"/"}, "/x", true},
		{"non-root prefix does not match root path", []string{"/data/app1"}, "/", false},

		// Case sensitivity.
		{"case sensitive, no match", []string{"/data/app1"}, "/Data/app1", false},
		{"case sensitive, exact case matches", []string{"/data/app1"}, "/data/app1", true},

		// Overlapping / redundant prefixes.
		{"overlapping prefixes, matches broader", []string{"/data", "/data/app1"}, "/data/other", true},
		{"overlapping prefixes, matches narrower", []string{"/data", "/data/app1"}, "/data/app1/x", true},
		{"overlapping prefixes, neither matches", []string{"/data", "/data/app1"}, "/other", false},

		// Empty allowlist.
		{"empty allowlist denies", nil, "/data/app1", false},
		{"empty allowlist denies root", []string{}, "/", false},

		// Literal * / ** are ordinary characters, never wildcards.
		{"literal star, exact", []string{"/data/*"}, "/data/*", true},
		{"literal star, descendant", []string{"/data/*"}, "/data/*/sub", true},
		{"literal star does not match unrelated dir", []string{"/data/*"}, "/data/x", false},
		{"literal double star, exact", []string{"/data/**"}, "/data/**", true},
		{"literal double star, descendant", []string{"/data/**"}, "/data/**/sub", true},
		{"literal double star does not match unrelated dir", []string{"/data/**"}, "/data/anything", false},

		// Long paths: no panic, sane result.
		{"long path exact match", []string{longPrefix}, longPrefix, true},
		{"long path descendant match", []string{longPrefix}, longPath, true},
		{"long path no match", []string{longPrefix}, "/data/" + strings.Repeat("b", 4000), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMatcher(tc.prefixes)
			assert.Equal(t, tc.want, m.Allowed(tc.path), "NewMatcher(%v).Allowed(%q)", tc.prefixes, tc.path)
		})
	}
}

// # Canonicalize

func TestCanonicalizeResolvesDotDotWithinAllowedDir(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	sub := filepath.Join(allowed, "x")
	other := filepath.Join(allowed, "y")
	for _, dir := range []string{allowed, sub, other} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}

	canonAllowed, err := Canonicalize(allowed)
	require.NoError(t, err)
	m := NewMatcher([]string{canonAllowed})

	// /allowed/x/../y resolves to /allowed/y, which stays within the
	// allowed directory, and must still be allowed.
	requested := filepath.Join(allowed, "x", "..", "y")
	got, err := Canonicalize(requested)
	require.NoError(t, err)
	wantCanon, err := Canonicalize(other)
	require.NoError(t, err)
	require.Equal(t, wantCanon, got)
	assert.True(t, m.Allowed(got), "expected %q (resolved from %q) to be allowed under %q", got, requested, canonAllowed)
}

func TestCanonicalizeDotDotEscapingIsDenied(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{allowed, outside} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}

	canonAllowed, err := Canonicalize(allowed)
	require.NoError(t, err)
	m := NewMatcher([]string{canonAllowed})

	// /allowed/../outside escapes the allowed directory entirely.
	requested := filepath.Join(allowed, "..", "outside")
	got, err := Canonicalize(requested)
	require.NoError(t, err)
	assert.False(t, m.Allowed(got), "expected %q (resolved from %q) to be denied, escapes %q", got, requested, canonAllowed)
}

func TestCanonicalizeResolvesSymlinkOutsideAllowedDir(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{allowed, outside} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	secret := filepath.Join(outside, "secret")
	require.NoError(t, os.MkdirAll(secret, 0o755))

	link := filepath.Join(allowed, "link")
	require.NoError(t, os.Symlink(secret, link))

	canonAllowed, err := Canonicalize(allowed)
	require.NoError(t, err)
	m := NewMatcher([]string{canonAllowed})

	// The raw requested string looks like it's under the allowed dir, but
	// it's a symlink whose real target is outside it.
	resolved, err := Canonicalize(link)
	require.NoError(t, err)
	canonSecret, err := Canonicalize(secret)
	require.NoError(t, err)
	require.Equal(t, canonSecret, resolved)
	assert.False(t, m.Allowed(resolved), "expected symlink target %q (raw path %q, superficially under %q) to be denied", resolved, link, canonAllowed)
}

func TestCanonicalizeSymlinkStayingWithinAllowedDirIsAllowed(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	real := filepath.Join(allowed, "real")
	for _, dir := range []string{allowed, real} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	link := filepath.Join(allowed, "link")
	require.NoError(t, os.Symlink(real, link))

	canonAllowed, err := Canonicalize(allowed)
	require.NoError(t, err)
	m := NewMatcher([]string{canonAllowed})

	resolved, err := Canonicalize(link)
	require.NoError(t, err)
	assert.True(t, m.Allowed(resolved), "expected symlink target %q (stays within %q) to be allowed", resolved, canonAllowed)
}

func TestCanonicalizeRejectsControlCharacters(t *testing.T) {
	cases := []string{
		"/tmp/foo\x00bar",
		"/tmp/foo\x01bar",
		"/tmp/foo\x1bbar",
		"/tmp/foo\x7fbar",
		"\x00",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			_, err := Canonicalize(path)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrControlChar)
		})
	}
}

func TestCanonicalizeLongNonexistentPathFailsCleanly(t *testing.T) {
	// No panic, no pathological slowdown, just a clean error for a very
	// long path that doesn't exist on disk.
	long := "/" + strings.Repeat("a/", 5000) + "does-not-exist"
	_, err := Canonicalize(long)
	require.Error(t, err)
}

func TestCanonicalizeAbsoluteSymlinkFreePathIsClean(t *testing.T) {
	dir := t.TempDir()
	got, err := Canonicalize(dir)
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(got), "want an absolute path")
	assert.Equal(t, got, filepath.Clean(got), "want an already filepath.Clean-idempotent path")
}

// # Expand

func TestExpand(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		vars    map[string][]string
		want    []string
	}{
		{
			name:    "no placeholders",
			pattern: "/data/app1",
			vars:    nil,
			want:    []string{"/data/app1"},
		},
		{
			name:    "single value substitution",
			pattern: "/home/$USER/projects",
			vars:    map[string][]string{"USER": {"alice"}},
			want:    []string{"/home/alice/projects"},
		},
		{
			name:    "multi-value fan-out",
			pattern: "/remote/$GROUP",
			vars:    map[string][]string{"GROUP": {"eng", "ops"}},
			want:    []string{"/remote/eng", "/remote/ops"},
		},
		{
			name:    "multiple placeholders cartesian product",
			pattern: "/home/$USER/$GROUP",
			vars: map[string][]string{
				"USER":  {"alice", "bob"},
				"GROUP": {"eng", "ops"},
			},
			want: []string{
				"/home/alice/eng",
				"/home/alice/ops",
				"/home/bob/eng",
				"/home/bob/ops",
			},
		},
		{
			name:    "repeated placeholder uses same value per expansion",
			pattern: "/home/$USER/$USER-backups",
			vars:    map[string][]string{"USER": {"alice", "bob"}},
			want: []string{
				"/home/alice/alice-backups",
				"/home/bob/bob-backups",
			},
		},
		{
			name:    "missing variable drops the pattern",
			pattern: "/home/$USER",
			vars:    map[string][]string{},
			want:    nil,
		},
		{
			name:    "missing variable (nil vars) drops the pattern",
			pattern: "/home/$USER",
			vars:    nil,
			want:    nil,
		},
		{
			name:    "one placeholder resolved, another missing: whole pattern dropped",
			pattern: "/home/$USER/$GROUP",
			vars:    map[string][]string{"USER": {"alice"}},
			want:    nil,
		},
		{
			name:    "hardening: slash-containing value dropped, sibling kept",
			pattern: "/remote/$GROUP",
			vars:    map[string][]string{"GROUP": {"eng/ops", "admins"}},
			want:    []string{"/remote/admins"},
		},
		{
			name:    "hardening: all values unsafe drops the pattern",
			pattern: "/remote/$GROUP",
			vars:    map[string][]string{"GROUP": {"a/b", "c/../d"}},
			want:    nil,
		},
		{
			name:    "hardening: NUL byte in value dropped, sibling kept",
			pattern: "/remote/$GROUP",
			vars:    map[string][]string{"GROUP": {"bad\x00name", "goodname"}},
			want:    []string{"/remote/goodname"},
		},
		{
			name:    "hardening: control character in value dropped, sibling kept",
			pattern: "/remote/$GROUP",
			vars:    map[string][]string{"GROUP": {"bad\x1bname", "goodname"}},
			want:    []string{"/remote/goodname"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Expand(tc.pattern, tc.vars)
			assert.True(t, equalStringSlices(got, tc.want), "Expand(%q, %v) = %v, want %v", tc.pattern, tc.vars, got, tc.want)
		})
	}
}

// TestExpandHardeningPreventsSegmentInjection proves the attack the
// hardening rule closes: without it, a $GROUP value containing "/../" could
// inject extra path segments once Matcher's filepath.Clean collapses the
// injected "..".
func TestExpandHardeningPreventsSegmentInjection(t *testing.T) {
	pattern := "/remote/$GROUP"
	vars := map[string][]string{"GROUP": {"../../etc", "legit-group"}}

	expansions := Expand(pattern, vars)
	require.Truef(t, equalStringSlices(expansions, []string{"/remote/legit-group"}), "Expand(%q, %v) = %v, want only the safe expansion", pattern, vars, expansions)

	m := NewMatcher(expansions)
	assert.False(t, m.Allowed("/etc"), "hardening failed to prevent segment injection: /etc is allowed via %v", expansions)
	assert.True(t, m.Allowed("/remote/legit-group"), "expected /remote/legit-group to be allowed via %v", expansions)
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// # benchmarks: request-hot-path operations
//
// These exist so a future change can be checked for a throughput/allocation
// regression with `go test -bench` rather than only functional correctness.

// manyPrefixes builds n distinct, realistic-looking allowlist prefixes, so
// benchmarks exercise Allowed's full linear scan rather than a scan of one
// element.
func manyPrefixes(n int) []string {
	prefixes := make([]string, n)
	for i := range prefixes {
		prefixes[i] = "/data/app" + strconv.Itoa(i) + "/shared"
	}
	return prefixes
}

// BenchmarkMatcherAllowed_Match measures the worst case for a hit: the
// matching prefix is last in the slice, so every candidate before it is
// compared and rejected first.
func BenchmarkMatcherAllowed_Match(b *testing.B) {
	const n = 200
	prefixes := manyPrefixes(n)
	m := NewMatcher(prefixes)
	path := "/data/app" + strconv.Itoa(n-1) + "/shared/deep/nested/path"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		require.True(b, m.Allowed(path), "expected %q to be allowed", path)
	}
}

// BenchmarkMatcherAllowed_NoMatch measures the full-scan cost Allowed pays
// on a deny: every configured prefix is compared and none match.
func BenchmarkMatcherAllowed_NoMatch(b *testing.B) {
	const n = 200
	prefixes := manyPrefixes(n)
	m := NewMatcher(prefixes)
	path := "/completely/unrelated/path"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		require.False(b, m.Allowed(path), "expected %q to be denied", path)
	}
}

// BenchmarkExpand_NoPlaceholders is the cheap, common case for a literal
// allowlist entry: Expand's fast path, no regex fan-out.
func BenchmarkExpand_NoPlaceholders(b *testing.B) {
	pattern := "/data/app1/shared"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Expand(pattern, nil)
	}
}

// BenchmarkExpand_CartesianFanOut measures the more expensive path: two
// placeholders, each with several candidate values, forcing the cartesian
// product's substitute walks.
func BenchmarkExpand_CartesianFanOut(b *testing.B) {
	pattern := "/home/$USER/$GROUP"
	vars := map[string][]string{
		"USER":  {"alice", "bob", "carol", "dave"},
		"GROUP": {"eng", "ops", "sec", "data"},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Expand(pattern, vars)
	}
}

// BenchmarkCanonicalize measures the traversal-bypass path every mount
// request pays before Allowed ever runs.
func BenchmarkCanonicalize(b *testing.B) {
	dir := b.TempDir()
	target := fmt.Sprintf("%s/a/b/c", dir)
	require.NoError(b, os.MkdirAll(target, 0o755))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := Canonicalize(target)
		require.NoError(b, err)
	}
}

// # fuzz: Matcher.Allowed against an independent reference oracle

// referenceAllowed is an independently-written oracle for Matcher.Allowed's
// contract, deliberately NOT implemented via string concatenation +
// strings.HasPrefix (Allowed's own technique), so the fuzz target below is a
// real cross-check rather than the implementation checking itself.
func referenceAllowed(prefix, path string) bool {
	q := filepath.Clean(prefix)
	qSegs, qAbs := referenceSplit(q)
	pSegs, pAbs := referenceSplit(path)

	if qAbs != pAbs {
		return false
	}
	if len(qSegs) > len(pSegs) {
		return false
	}
	for i, seg := range qSegs {
		if pSegs[i] != seg {
			return false
		}
	}
	return true
}

// referenceSplit splits s into path segments, reporting separately whether
// s is absolute. Unlike filepath.Clean, it only trims a trailing "/" - it
// never collapses "//" runs or resolves "." / "..".
func referenceSplit(s string) (segs []string, absolute bool) {
	if strings.HasPrefix(s, "/") {
		absolute = true
		s = s[1:]
	}
	s = strings.TrimSuffix(s, "/")
	if s == "" {
		return nil, absolute
	}
	return strings.Split(s, "/"), absolute
}

func FuzzMatcherAllowed(f *testing.F) {
	type seed struct{ prefix, path string }
	seeds := []seed{
		{"/data/app1", "/data/app1"},
		{"/data/app1", "/data/app12"},
		{"/data/app1", "/data/app1x"},
		{"/data/app12", "/data/app1"},
		{"/data/app1x", "/data/app1"},
		{"/data/app1", "/data/app1/sub"},
		{"/data/app1", "/data/app1/a/b/c/d/e"},
		{"/", "/"},
		{"/", "/anything/at/all"},
		{"/data/app1", "/"},
		{"/data/app1/", "/data/app1"},
		{"/data/app1", "/data/app1/"},
		{"/data/app1/", "/data/app1/"},
		{"/Data/app1", "/data/app1"},
		{"/data/app1", "/Data/app1"},
		{"/data", "/data/app1"},
		{"/data/app1", "/data"},
		{"/data/allowed", "/data/allowed/x/../y"},
		{"/data/allowed", "/data/allowed/../outside"},
		{"/data/*", "/data/*/sub"},
		{"/data/*", "/data/x"},
		{"/data/**", "/data/**/sub"},
		{"/data/**", "/data/anything"},
		{"", ""},
		{"/", ""},
		{"", "/"},
		{"/data/app1", "/data/app1//sub"},
		{"//data", "/data"},
		{"/data", "//data"},
		{strings.Repeat("/a", 500), strings.Repeat("/a", 500) + "/x"},
		{".", "."},
		{"..", "../x"},
		{"/data/app1", "data/app1"},
	}
	for _, s := range seeds {
		f.Add(s.prefix, s.path)
	}

	f.Fuzz(func(t *testing.T, prefix, path string) {
		m := NewMatcher([]string{prefix})
		got := m.Allowed(path)
		want := referenceAllowed(prefix, path)
		require.Equalf(t, want, got, "Matcher.Allowed(%q) with prefix %q, reference oracle = %v", path, prefix, want)
	})
}
