package config

import (
	"bytes"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// # shared test fixtures

// TestMain keeps one permanent, no-op SIGHUP listener alive for the whole
// test run, so a real SIGHUP sent between one Watch's stop() and the next
// Watch's setup never hits the OS default (terminate) action.
func TestMain(m *testing.M) {
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGHUP)
	go func() {
		for range guard {
			// discard
		}
	}()
	os.Exit(m.Run())
}

// writeFile writes content to dir/name (creating any needed parent
// directories, e.g. "conf.d/01.yaml"), returning the full path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

// captureLogs installs a temporary slog default handler for the duration of
// the test, returning the buffer its JSON output is written to. Restores
// the previous default logger on cleanup.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// validConfigYAML is a minimal-but-complete config.yaml that satisfies
// Validate on its own, so tests can layer conf.d files or env/flag
// overrides on top of it.
const validConfigYAML = `
logging_level: info
allowlist:
  - /data
`

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// # Load / conf.d merge

func TestLoad_ListenAddrDefault(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", validConfigYAML)

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, ":80", cfg.Server.ListenAddr)
	assert.Equal(t, "/metrics", cfg.Server.MetricsPath)
	assert.Equal(t, "info", cfg.LoggingLevel, "from config.yaml, not the default")
}

func TestLoad_ConfDUnionsAllowlistAndDatasources(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
allowlist:
  - /data
  - /shared
datasources:
  - name: ad01
    type: ldap
    url: ldaps://ad01.example.com
`)
	writeFile(t, dir, "conf.d/01-extra.yaml", `
allowlist:
  - /shared
  - /srv/app
datasources:
  - name: ad02
    type: ldap
    url: ldaps://ad02.example.com
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	gotAllow := append([]string(nil), cfg.Allowlist...)
	sort.Strings(gotAllow)
	wantAllow := []string{"/data", "/shared", "/srv/app"}
	assert.Equal(t, wantAllow, gotAllow, "Allowlist should union to these entries (any order)")

	require.Lenf(t, cfg.Datasources, 2, "%+v", cfg.Datasources)
	names := map[string]bool{}
	for _, d := range cfg.Datasources {
		names[d.Name] = true
	}
	assert.True(t, names["ad01"] && names["ad02"], "Datasources names = %v, want both ad01 and ad02", names)
}

func TestLoad_ConfDUnionsAdminUsersAndGroups(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
admin_users:
  - alice
admin_groups:
  - ops
`)
	writeFile(t, dir, "conf.d/01-extra.yaml", `
admin_users:
  - alice
  - bob
admin_groups:
  - eng
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	gotUsers := append([]string(nil), cfg.AdminUsers...)
	sort.Strings(gotUsers)
	assert.Equal(t, []string{"alice", "bob"}, gotUsers, "AdminUsers should union+dedup to these entries (any order)")

	gotGroups := append([]string(nil), cfg.AdminGroups...)
	sort.Strings(gotGroups)
	assert.Equal(t, []string{"eng", "ops"}, gotGroups, "AdminGroups should union to these entries (any order)")
}

func TestLoad_DatasourceUnionReplacesSameNameByLastFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
allowlist: [/data]
datasources:
  - name: ad01
    type: ldap
    url: ldaps://old.example.com
`)
	writeFile(t, dir, "conf.d/01.yaml", `
datasources:
  - name: ad01
    type: ldap
    url: ldaps://new.example.com
`)

	cfg, err := Load(path)
	require.NoError(t, err)
	require.Lenf(t, cfg.Datasources, 1, "same name, not appended: %+v", cfg.Datasources)

	var url struct {
		URL string `yaml:"url"`
	}
	require.NoError(t, cfg.Datasources[0].Raw.Decode(&url))
	assert.Equal(t, "ldaps://new.example.com", url.URL, "datasource url should be the conf.d file's value (last-file-wins)")
}

func TestLoad_ScalarsLastFileWinsAcrossConfD(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
logging_level: info
allowlist: [/data]
`)
	writeFile(t, dir, "conf.d/01-first.yaml", "logging_level: warn\n")
	writeFile(t, dir, "conf.d/02-second.yaml", "logging_level: error\n")

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "error", cfg.LoggingLevel, "lexically-last conf.d file should win")
}

func TestLoad_ChecksLastFileWinsAcrossConfD(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
allowlist: [/data]
checks:
  host_network: deny
`)
	writeFile(t, dir, "conf.d/01-first.yaml", "checks:\n  host_network: allow\n")
	writeFile(t, dir, "conf.d/02-second.yaml", "checks:\n  host_network: deny\n")

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, CheckDeny, cfg.Checks.HostNetwork, "lexically-last conf.d file should win, same as any other scalar")
}

func TestLoad_MalformedYAMLIsFatal(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", "logging_level: [this is not valid: yaml\n")

	cfg, err := Load(path)
	require.Errorf(t, err, "cfg = %+v", cfg)
	assert.Nil(t, cfg, "Load returned non-nil cfg alongside a fatal error")
}

func TestLoad_MissingFileIsFatal(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir + "/does-not-exist.yaml")
	require.Error(t, err, "Load should error for a nonexistent config file")
}

func TestLoad_UnrecognizedFieldIsNonFatalAndIgnored(t *testing.T) {
	logs := captureLogs(t)

	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
logging_level: info
allowlist: [/data]
this_field_does_not_exist: true
`)

	cfg, err := Load(path)
	// Non-fatal: Load must succeed despite the stray field.
	require.NoError(t, err, "Load returned an error for an unrecognized-but-otherwise-valid config")
	require.NotNil(t, cfg, "Load returned a nil *Config alongside a nil error")
	assert.Equal(t, "info", cfg.LoggingLevel, "rest of the file should still parse normally")

	assert.Contains(t, logs.String(), "this_field_does_not_exist", "expected a WARN log naming the unrecognized field")
	assert.Contains(t, logs.String(), `"level":"WARN"`, "expected the unrecognized-field log at WARN level")
}

func TestLoad_UnrecognizedNestedFieldIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
allowlist: [/data]
server:
  listen_addr: ":8080"
  bogus_nested_field: true
`)

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, ":8080", cfg.Server.ListenAddr)
}

func TestLoad_ConfigDirOverride(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
allowlist: [/data]
config_dir: alt-conf.d
`)
	writeFile(t, dir, "alt-conf.d/01.yaml", "logging_level: debug\n")
	// Default-location conf.d must not be picked up once config_dir points elsewhere.
	writeFile(t, dir, "conf.d/01.yaml", "logging_level: error\n")

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "debug", cfg.LoggingLevel, "from config_dir's override location")
}

func TestLoad_NoConfDDirectoryIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", validConfigYAML)

	_, err := Load(path)
	require.NoError(t, err, "a missing conf.d directory must not be an error - it's optional")
}

func TestLoad_DatasourceCacheTTLDefault(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
allowlist: [/data]
datasources:
  - name: ad01
    type: ldap
`)
	cfg, err := Load(path)
	require.NoError(t, err)
	require.Len(t, cfg.Datasources, 1)
	assert.Equal(t, "10m0s", cfg.Datasources[0].CacheTTL.String(), "want the 10m default")
}

func TestLoad_DatasourceCacheTTLExplicit(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
allowlist: [/data]
datasources:
  - name: ad01
    type: ldap
    cache_ttl: 30s
`)
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "30s", cfg.Datasources[0].CacheTTL.String())
}

// # Validate

func TestValidate_ServerCertKey(t *testing.T) {
	dir := t.TempDir()
	certPath := writeFile(t, dir, "server.crt", "not a real cert, just needs to exist")
	keyPath := writeFile(t, dir, "server.key", "not a real key, just needs to exist")
	missingPath := filepath.Join(dir, "does-not-exist.crt")

	base := func() *Config {
		return &Config{
			LoggingLevel: "info",
			Allowlist:    []string{"/data"},
			Checks: ChecksConfig{
				HostNetwork: CheckAllow,
				Privileged:  CheckAllow,
				DockerCP:    CheckAllow,
				DockerExec:  CheckAllow,
			},
		}
	}

	tests := []struct {
		name    string
		cert    string
		key     string
		wantErr bool
	}{
		{"both unset is plain HTTP, fine", "", "", false},
		{"both set to existing files, fine", certPath, keyPath, false},
		{"cert only is ambiguous, fatal", certPath, "", true},
		{"key only is ambiguous, fatal", "", keyPath, true},
		{"cert set but file missing, fatal", missingPath, keyPath, true},
		{"key set but file missing, fatal", certPath, missingPath, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base()
			cfg.Server.ServerCert = tt.cert
			cfg.Server.ServerKey = tt.key

			err := Validate(cfg)
			if tt.wantErr {
				assert.Errorf(t, err, "Validate() should error (cert=%q key=%q)", tt.cert, tt.key)
			} else {
				assert.NoErrorf(t, err, "Validate() should be nil (cert=%q key=%q)", tt.cert, tt.key)
			}
		})
	}
}

func TestValidate_ChecksInvalidValueIsFatal(t *testing.T) {
	cfg := &Config{
		LoggingLevel: "info",
		Allowlist:    []string{"/data"},
		Checks: ChecksConfig{
			HostNetwork: CheckAllow,
			Privileged:  CheckAllow,
			DockerCP:    "maybe", // neither "allow" nor "deny"
			DockerExec:  CheckAllow,
		},
	}
	require.Error(t, Validate(cfg), "want an error for an invalid checks.docker_cp value")
}

func TestValidate_AllChecksValuesRejectedIfInvalid(t *testing.T) {
	valid := ChecksConfig{CheckAllow, CheckAllow, CheckAllow, CheckAllow}
	fields := []func(*ChecksConfig){
		func(c *ChecksConfig) { c.HostNetwork = "bogus" },
		func(c *ChecksConfig) { c.Privileged = "bogus" },
		func(c *ChecksConfig) { c.DockerCP = "bogus" },
		func(c *ChecksConfig) { c.DockerExec = "bogus" },
	}
	for i, corrupt := range fields {
		checks := valid
		corrupt(&checks)
		cfg := &Config{LoggingLevel: "info", Allowlist: []string{"/data"}, Checks: checks}
		assert.Errorf(t, Validate(cfg), "field index %d: want an error for checks = %+v", i, checks)
	}
}

func TestValidate_EmptyAllowlistIsFatal(t *testing.T) {
	cfg := &Config{
		LoggingLevel: "info",
		Allowlist:    nil,
		Checks: ChecksConfig{
			HostNetwork: CheckAllow,
			Privileged:  CheckAllow,
			DockerCP:    CheckAllow,
			DockerExec:  CheckAllow,
		},
	}
	require.Error(t, Validate(cfg), "want an error for an empty allowlist")
}

func TestValidate_InvalidLoggingLevelIsFatal(t *testing.T) {
	cfg := &Config{
		LoggingLevel: "not-a-level",
		Allowlist:    []string{"/data"},
		Checks: ChecksConfig{
			HostNetwork: CheckAllow,
			Privileged:  CheckAllow,
			DockerCP:    CheckAllow,
			DockerExec:  CheckAllow,
		},
	}
	require.Error(t, Validate(cfg), "want an error for an invalid logging_level")
}

func TestValidate_DuplicateDatasourceNameIsFatal(t *testing.T) {
	cfg := &Config{
		LoggingLevel: "info",
		Allowlist:    []string{"/data"},
		Checks: ChecksConfig{
			HostNetwork: CheckAllow,
			Privileged:  CheckAllow,
			DockerCP:    CheckAllow,
			DockerExec:  CheckAllow,
		},
		Datasources: []DatasourceConfig{
			{Name: "ad01", Type: "ldap"},
			{Name: "ad01", Type: "ldap"},
		},
	}
	err := Validate(cfg)
	var verr *ValidationError
	require.ErrorAs(t, err, &verr, "want a *ValidationError for a duplicate datasource name")
}

func TestValidate_DatasourceMissingTypeIsFatal(t *testing.T) {
	cfg := &Config{
		LoggingLevel: "info",
		Allowlist:    []string{"/data"},
		Checks: ChecksConfig{
			HostNetwork: CheckAllow,
			Privileged:  CheckAllow,
			DockerCP:    CheckAllow,
			DockerExec:  CheckAllow,
		},
		Datasources: []DatasourceConfig{{Name: "ad01", Type: ""}},
	}
	require.Error(t, Validate(cfg), "want an error for a datasource with no type")
}

// TestValidationError_IsDistinctType confirms Validate's fatal case
// produces a *ValidationError specifically, distinct from Load's own
// I/O/parse errors.
func TestValidationError_IsDistinctType(t *testing.T) {
	cfg := &Config{
		LoggingLevel: "info",
		Allowlist:    []string{"/data"},
		Checks: ChecksConfig{
			HostNetwork: "not-a-real-value",
			Privileged:  CheckAllow,
			DockerCP:    CheckAllow,
			DockerExec:  CheckAllow,
		},
	}
	err := Validate(cfg)
	var verr *ValidationError
	require.ErrorAsf(t, err, &verr, "Validate error = %v (%T), want *ValidationError", err, err)
	assert.Len(t, verr.Issues, 1, "want exactly 1 issue (the bad checks.host_network value)")
}

// # ApplyEnv / ApplyFlags / precedence

func TestApplyEnv_OverridesServerFields(t *testing.T) {
	t.Setenv("AUTHZ_LOGGING_LEVEL", "debug")
	t.Setenv("AUTHZ_SERVER_LISTEN_ADDR", ":9443")
	t.Setenv("AUTHZ_SERVER_CERT", "/tls/env.crt")
	t.Setenv("AUTHZ_SERVER_KEY", "/tls/env.key")
	t.Setenv("AUTHZ_SERVER_METRICS_PATH", "/metrics-env")
	t.Setenv("AUTHZ_SERVER_DECISION_TIMEOUT", "5s")

	cfg := &Config{LoggingLevel: "info", Server: ServerConfig{ListenAddr: ":80"}}
	require.NoError(t, ApplyEnv(cfg))

	assert.Equal(t, "debug", cfg.LoggingLevel)
	assert.Equal(t, ":9443", cfg.Server.ListenAddr)
	assert.Equal(t, "/tls/env.crt", cfg.Server.ServerCert)
	assert.Equal(t, "/tls/env.key", cfg.Server.ServerKey)
	assert.Equal(t, "/metrics-env", cfg.Server.MetricsPath)
	assert.Equal(t, 5*time.Second, time.Duration(cfg.Server.DecisionTimeout))
}

func TestApplyEnv_InvalidDurationIsFatal(t *testing.T) {
	t.Setenv("AUTHZ_SERVER_DECISION_TIMEOUT", "not-a-duration")
	cfg := &Config{}
	require.Error(t, ApplyEnv(cfg), "ApplyEnv() should error for an unparseable AUTHZ_SERVER_DECISION_TIMEOUT")
}

func TestApplyEnv_UnsetVarsLeaveConfigAlone(t *testing.T) {
	cfg := &Config{LoggingLevel: "warn", Server: ServerConfig{ListenAddr: ":1234"}}
	require.NoError(t, ApplyEnv(cfg))
	assert.True(t, cfg.LoggingLevel == "warn" && cfg.Server.ListenAddr == ":1234", "ApplyEnv changed cfg with no AUTHZ_* vars set: %+v", cfg)
}

func TestApplyFlags_OnlyExplicitlyPassedFlagsOverride(t *testing.T) {
	overrides := FlagOverrides{LoggingLevel: "error", DecisionTimeout: "9s"}

	cfg := &Config{LoggingLevel: "info", Server: ServerConfig{ListenAddr: ":80", MetricsPath: "/metrics"}}
	require.NoError(t, ApplyFlags(cfg, overrides))

	assert.Equal(t, "error", cfg.LoggingLevel, "flag was passed")
	assert.Equal(t, 9*time.Second, time.Duration(cfg.Server.DecisionTimeout), "flag was passed")
	// Not passed on the command line - must be untouched.
	assert.Equal(t, ":80", cfg.Server.ListenAddr, "flag not passed, must be left alone")
	assert.Equal(t, "/metrics", cfg.Server.MetricsPath, "flag not passed, must be left alone")
}

func TestApplyFlags_ZeroValueIsNoOp(t *testing.T) {
	cfg := &Config{LoggingLevel: "info"}
	require.NoError(t, ApplyFlags(cfg, FlagOverrides{}))
	assert.Equal(t, "info", cfg.LoggingLevel, "cfg changed by ApplyFlags(cfg, FlagOverrides{})")
}

func TestApplyFlags_InvalidDecisionTimeoutIsFatal(t *testing.T) {
	cfg := &Config{}
	require.Error(t, ApplyFlags(cfg, FlagOverrides{DecisionTimeout: "not-a-duration"}), "ApplyFlags() should error for an unparseable DecisionTimeout")
}

// TestPrecedence_CLIOverEnvOverFile exercises LoadFull end to end: CLI flag
// beats env beats file.
func TestPrecedence_CLIOverEnvOverFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
logging_level: warn
allowlist: [/data]
server:
  listen_addr: ":9000"
  metrics_path: "/from-file"
`)

	t.Setenv("AUTHZ_LOGGING_LEVEL", "error")
	t.Setenv("AUTHZ_SERVER_LISTEN_ADDR", ":9001")

	cfg, err := LoadFull(path, FlagOverrides{LoggingLevel: "debug"})
	require.NoError(t, err)

	assert.Equal(t, "debug", cfg.LoggingLevel, "CLI flag set, must win over env and file")
	assert.Equal(t, ":9001", cfg.Server.ListenAddr, "env set, no flag, must win over file")
	assert.Equal(t, "/from-file", cfg.Server.MetricsPath, "only the file set this")
}

// TestImmunity_AllowlistDatasourcesChecks confirms env vars/flags that would
// plausibly map to allowlist/datasources/checks.*/admin_users/admin_groups
// have zero effect: policy is config-file only.
func TestImmunity_AllowlistDatasourcesChecks(t *testing.T) {
	t.Setenv("AUTHZ_ALLOWLIST", "/should/not/appear")
	t.Setenv("AUTHZ_CHECKS_HOST_NETWORK", "deny")
	t.Setenv("AUTHZ_CHECKS_PRIVILEGED", "deny")
	t.Setenv("AUTHZ_CHECKS_DOCKER_CP", "deny")
	t.Setenv("AUTHZ_CHECKS_DOCKER_EXEC", "deny")
	t.Setenv("AUTHZ_DATASOURCES_0_CACHE_TTL", "1s")
	t.Setenv("AUTHZ_ADMIN_USERS", "should-not-appear")
	t.Setenv("AUTHZ_ADMIN_GROUPS", "should-not-appear")

	cfg := &Config{
		Allowlist: []string{"/data"},
		Checks: ChecksConfig{
			HostNetwork: CheckAllow,
			Privileged:  CheckAllow,
			DockerCP:    CheckAllow,
			DockerExec:  CheckAllow,
		},
		Datasources: []DatasourceConfig{{Name: "ad01", Type: "ldap", CacheTTL: Duration(10 * time.Minute)}},
		AdminUsers:  []string{"alice"},
		AdminGroups: []string{"ops"},
	}

	require.NoError(t, ApplyEnv(cfg))

	assert.Equal(t, []string{"/data"}, cfg.Allowlist, "Allowlist mutated by env vars")
	assert.Equal(t, ChecksConfig{CheckAllow, CheckAllow, CheckAllow, CheckAllow}, cfg.Checks, "Checks mutated by env vars")
	assert.Equal(t, Duration(10*time.Minute), cfg.Datasources[0].CacheTTL, "Datasources[0].CacheTTL mutated by env vars")
	assert.Equal(t, []string{"alice"}, cfg.AdminUsers, "AdminUsers mutated by env vars")
	assert.Equal(t, []string{"ops"}, cfg.AdminGroups, "AdminGroups mutated by env vars")

	// No FlagOverrides field maps to allowlist/datasources/checks.*/admin_* at all.
	require.NoError(t, ApplyFlags(cfg, FlagOverrides{}))
	assert.True(t, len(cfg.Allowlist) == 1 && cfg.Checks.HostNetwork == CheckAllow, "cfg mutated by ApplyFlags despite no matching fields existing: %+v", cfg)
	assert.Len(t, cfg.AdminUsers, 1, "AdminUsers mutated by ApplyFlags despite no matching field existing")
}

// TestImmunity_ConfDCannotBeOverriddenByEnvOrCLI is the end-to-end version:
// an allowlist assembled from config.yaml+conf.d is untouched by env/CLI.
func TestImmunity_ConfDCannotBeOverriddenByEnvOrCLI(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", "allowlist: [/data]\n")
	writeFile(t, dir, "conf.d/01.yaml", "allowlist: [/srv]\n")

	t.Setenv("AUTHZ_ALLOWLIST", "/should/not/appear")

	cfg, err := LoadFull(path, FlagOverrides{})
	require.NoError(t, err)
	assert.Len(t, cfg.Allowlist, 2, "want the 2 conf.d-unioned entries, unaffected by AUTHZ_ALLOWLIST")
}

// # Watch (SIGHUP reload)

// reloadResult bundles one onReload invocation for tests to assert against
// over a channel, since Watch's callback runs on its own goroutine.
type reloadResult struct {
	cfg *Config
	err error
}

// sendSIGHUPAndAwait sends SIGHUP to this test process and waits (bounded)
// for exactly one onReload invocation, delivered via ch, failing fast if
// none arrives in time.
func sendSIGHUPAndAwait(t *testing.T, ch <-chan reloadResult) reloadResult {
	t.Helper()
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGHUP), "sending SIGHUP to self")
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		require.Fail(t, "timed out waiting for onReload after SIGHUP")
		return reloadResult{}
	}
}

func TestWatch_ReloadSwapsStoreOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
logging_level: info
allowlist: [/data]
`)

	initial, err := LoadFull(path, FlagOverrides{})
	require.NoError(t, err, "LoadFull (initial)")
	store := NewStore(initial)

	results := make(chan reloadResult, 1)
	stop := Watch(store, path, FlagOverrides{}, func(cfg *Config, err error) {
		results <- reloadResult{cfg, err}
	})
	defer stop()

	// Rewrite config.yaml, then reload it via SIGHUP.
	writeFile(t, dir, "config.yaml", `
logging_level: debug
allowlist: [/data]
`)

	r := sendSIGHUPAndAwait(t, results)
	require.NoError(t, r.err, "onReload error")
	require.NotNil(t, r.cfg)
	require.Equal(t, "debug", r.cfg.LoggingLevel)

	assert.Equal(t, "debug", store.Current().LoggingLevel, "Watch must swap the Store on a successful reload")
}

func TestWatch_FailedReloadPropagatesAndDoesNotSwapOrFallback(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
logging_level: info
allowlist: [/data]
`)

	initial, err := LoadFull(path, FlagOverrides{})
	require.NoError(t, err, "LoadFull (initial)")
	store := NewStore(initial)

	results := make(chan reloadResult, 1)
	stop := Watch(store, path, FlagOverrides{}, func(cfg *Config, err error) {
		results <- reloadResult{cfg, err}
	})
	defer stop()

	// Break the config: empty allowlist is a fatal Validate() condition.
	writeFile(t, dir, "config.yaml", `
logging_level: debug
allowlist: []
`)

	r := sendSIGHUPAndAwait(t, results)
	require.Error(t, r.err, "onReload err should be propagated from the failed reload")
	assert.Nil(t, r.cfg, "onReload cfg should be nil alongside a reload error")

	// No fallback to last-good: the Store must be untouched by the failed reload.
	assert.Equal(t, "info", store.Current().LoggingLevel, "last-good config, untouched by the failed reload")
}

func TestWatch_LogsInfoOnSIGHUPBeforeReloading(t *testing.T) {
	logs := captureLogs(t)

	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", validConfigYAML)

	initial, err := LoadFull(path, FlagOverrides{})
	require.NoError(t, err, "LoadFull (initial)")
	store := NewStore(initial)

	results := make(chan reloadResult, 1)
	stop := Watch(store, path, FlagOverrides{}, func(cfg *Config, err error) {
		results <- reloadResult{cfg, err}
	})
	defer stop()

	sendSIGHUPAndAwait(t, results)

	got := logs.String()
	assert.True(t, containsAll(got, `"level":"INFO"`, "SIGHUP"), "expected an INFO log mentioning SIGHUP, got: %s", got)
}

func TestWatch_StopPreventsFurtherReloads(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", validConfigYAML)

	initial, err := LoadFull(path, FlagOverrides{})
	require.NoError(t, err, "LoadFull (initial)")
	store := NewStore(initial)

	results := make(chan reloadResult, 1)
	stop := Watch(store, path, FlagOverrides{}, func(cfg *Config, err error) {
		results <- reloadResult{cfg, err}
	})
	stop()
	stop() // must be safe to call twice

	// A SIGHUP after stop() must not be handled by this (dead) watcher;
	// TestMain's background listener keeps this safe from the OS default action.
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGHUP), "sending SIGHUP to self")
	select {
	case r := <-results:
		assert.Fail(t, "received a reload result after stop()", "%+v", r)
	case <-time.After(200 * time.Millisecond):
		// expected: nothing happened, the stopped watcher never saw it
	}
}
