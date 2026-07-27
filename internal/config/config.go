// Config defines authzmtls's configuration schema and the
// load/merge/override/validate/reload pipeline (config.yaml + conf.d/*.yaml,
// AUTHZ_* env vars, CLI flags, and SIGHUP-triggered reload via Watch).
//
// Uses gopkg.in/yaml.v3 specifically because it supports yaml.Node, needed
// for the datasources block's opaque, provider-specific fields.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/weishiuchang/authzmtls/internal/logging"
)

// CheckSetting is the two-value enum backing every checks.* field. All four
// share this one type because they have identical validation and default
// behavior.
type CheckSetting string

const (
	// CheckAllow is the default for every checks.* field.
	CheckAllow CheckSetting = "allow"
	// CheckDeny closes the corresponding gate.
	CheckDeny CheckSetting = "deny"
)

// valid reports whether c is one of the two recognized values. Empty is
// invalid here because applyDefaults fills it in before Validate ever runs.
func (c CheckSetting) valid() bool {
	return c == CheckAllow || c == CheckDeny
}

// ChecksConfig holds the four global on/off gates. Config-file only:
// excluded from ApplyEnv/ApplyFlags, merged last-file-wins across conf.d.
type ChecksConfig struct {
	HostNetwork CheckSetting `yaml:"host_network"`
	Privileged  CheckSetting `yaml:"privileged"`
	DockerCP    CheckSetting `yaml:"docker_cp"`
	DockerExec  CheckSetting `yaml:"docker_exec"`
}

// ServerConfig holds the HTTP listener settings; unlike
// allowlist/datasources/checks.*, these fields do accept env/CLI overrides.
type ServerConfig struct {
	// ListenAddr defaults to ":80"; TLS is opt-in via ServerCert/ServerKey,
	// never assumed.
	ListenAddr string `yaml:"listen_addr"`

	// ServerCert and ServerKey must be both set (TLS) or both unset (plain
	// HTTP); setting only one is a validation error.
	ServerCert string `yaml:"server_cert"`
	ServerKey  string `yaml:"server_key"`

	MetricsPath     string   `yaml:"metrics_path"`
	DecisionTimeout Duration `yaml:"decision_timeout"`
}

// commonDatasourceFields is DatasourceConfig's decode target; a separate
// type so decoding it can't recurse back into DatasourceConfig.UnmarshalYAML.
type commonDatasourceFields struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	CacheTTL Duration `yaml:"cache_ttl"`
}

// DatasourceConfig is the common shape every `datasources` entry decodes
// into. Only Name/Type/CacheTTL are meaningful here - everything else is
// opaque, preserved verbatim in Raw for that provider's own package to
// decode.
type DatasourceConfig struct {
	Name     string
	Type     string
	CacheTTL Duration

	// Raw is the entire original YAML mapping node for this entry; a
	// provider's own decode reads straight from this rather than a
	// re-serialization.
	Raw yaml.Node
}

// UnmarshalYAML implements yaml.Unmarshaler. Decoding this way (rather than
// plain struct tags) keeps provider-specific fields opaque instead of
// triggering "unrecognized field" handling.
func (d *DatasourceConfig) UnmarshalYAML(node *yaml.Node) error {
	var common commonDatasourceFields
	if err := node.Decode(&common); err != nil {
		return err
	}
	d.Name = common.Name
	d.Type = common.Type
	d.CacheTTL = common.CacheTTL
	d.Raw = *node
	return nil
}

// Config is authzmtls's full configuration schema: loaded from config.yaml,
// layered with conf.d/*.yaml, then overridden by AUTHZ_* env vars and CLI
// flags (except Allowlist/Datasources/Checks/AdminUsers/AdminGroups, which
// are config-file only).
type Config struct {
	LoggingLevel string `yaml:"logging_level"`

	Server ServerConfig `yaml:"server"`

	// Allowlist, Datasources, Checks, AdminUsers, and AdminGroups are
	// config-file only - no env var or CLI flag can ever override security
	// policy.
	Allowlist   []string           `yaml:"allowlist"`
	Datasources []DatasourceConfig `yaml:"datasources"`
	Checks      ChecksConfig       `yaml:"checks"`

	// AdminUsers/AdminGroups are resolved $USER/$GROUP values (see
	// "Allowlist matching" in README - same datasource resolution, same
	// $VAR values) that bypass every rule entirely: a request from a
	// matched identity is allowed outright, not just its mount paths.
	// Either or both empty (the default) means the feature is unused.
	AdminUsers  []string `yaml:"admin_users"`
	AdminGroups []string `yaml:"admin_groups"`

	// ConfigDir names where conf.d/*.yaml lives; read only from the
	// top-level config.yaml, defaults to a "conf.d" directory next to it.
	// A relative value resolves relative to config.yaml's directory, not
	// the process's working directory.
	ConfigDir string `yaml:"config_dir"`
}

// Duration is time.Duration with YAML decoding from Go duration strings
// ("2s", "10m", ...) instead of yaml.v3's default numeric-nanoseconds
// decode. Convert with time.Duration(d) at call sites that need the stdlib
// type.
type Duration time.Duration

// String renders d the same way time.Duration does (e.g. "2s", not a raw
// nanosecond count).
func (d Duration) String() string {
	return time.Duration(d).String()
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("config: duration must be a string (e.g. \"2s\"): %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("config: invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements yaml.Marshaler, kept for round-trip symmetry with
// UnmarshalYAML.
func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

// # Load / conf.d merge

// knownTopLevel/knownServerFields/knownChecksFields are the schema's field
// vocabulary, used only by mergeLayer's "unrecognized field" WARN-and-ignore
// check. Hand-maintained rather than derived via reflection over Config's
// yaml tags, so it stays one obvious, greppable place to look.
var (
	knownTopLevel = map[string]bool{
		"logging_level": true,
		"server":        true,
		"allowlist":     true,
		"datasources":   true,
		"checks":        true,
		"admin_users":   true,
		"admin_groups":  true,
		"config_dir":    true,
	}
	knownServerFields = map[string]bool{
		"listen_addr":      true,
		"server_cert":      true,
		"server_key":       true,
		"metrics_path":     true,
		"decision_timeout": true,
	}
	knownChecksFields = map[string]bool{
		"host_network": true,
		"privileged":   true,
		"docker_cp":    true,
		"docker_exec":  true,
	}
)

// Load reads path (config.yaml), then every conf.d/*.yaml file lexically
// ordered next to it, and merges them into one Config: scalars last-file-
// wins, allowlist/datasources/admin_users/admin_groups unioned and
// de-duplicated rather than replaced. Load's error is fatal only if a file
// can't be read or isn't valid YAML; an unrecognized field is instead
// logged at WARN and ignored. Load does not itself call Validate - see
// LoadFull for why that must happen after ApplyEnv/ApplyFlags.
func Load(path string) (*Config, error) {
	cfg := &Config{}
	if err := mergeLayer(cfg, path); err != nil {
		return nil, err
	}

	confDir := cfg.ConfigDir
	switch {
	case confDir == "":
		confDir = filepath.Join(filepath.Dir(path), "conf.d")
	case !filepath.IsAbs(confDir):
		// Relative to config.yaml's own directory, not the process cwd.
		confDir = filepath.Join(filepath.Dir(path), confDir)
	}
	cfg.ConfigDir = confDir

	entries, err := os.ReadDir(confDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("config: read conf.d directory %s: %w", confDir, err)
		}
		entries = nil // conf.d is optional
	}

	for _, entry := range entries {
		// os.ReadDir already returns entries sorted by filename.
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		if err := mergeLayer(cfg, filepath.Join(confDir, entry.Name())); err != nil {
			return nil, err
		}
	}

	// Fill in every field's default wherever no merged layer set it - after
	// all conf.d layers merge but before ApplyEnv/ApplyFlags, so an
	// explicit override always wins over the default.
	if cfg.LoggingLevel == "" {
		cfg.LoggingLevel = "info"
	}
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":80"
	}
	if cfg.Server.MetricsPath == "" {
		cfg.Server.MetricsPath = "/metrics"
	}
	if cfg.Server.DecisionTimeout == 0 {
		cfg.Server.DecisionTimeout = Duration(2 * time.Second)
	}
	if cfg.Checks.HostNetwork == "" {
		cfg.Checks.HostNetwork = CheckAllow
	}
	if cfg.Checks.Privileged == "" {
		cfg.Checks.Privileged = CheckAllow
	}
	if cfg.Checks.DockerCP == "" {
		cfg.Checks.DockerCP = CheckAllow
	}
	if cfg.Checks.DockerExec == "" {
		cfg.Checks.DockerExec = CheckAllow
	}
	for i := range cfg.Datasources {
		if cfg.Datasources[i].CacheTTL == 0 {
			cfg.Datasources[i].CacheTTL = Duration(10 * time.Minute)
		}
	}

	return cfg, nil
}

// mergeLayer reads one YAML file and merges its fields onto cfg in place.
// It parses the file twice on purpose: once into a bare *yaml.Node to see
// which keys are actually present (so a field absent from this file can't
// stomp an earlier layer's value with its Go zero value), and once into a
// typed Config for real, validated values.
func mergeLayer(cfg *Config, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("config: read %s: %w", filePath, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("config: parse %s: %w", filePath, err)
	}

	// present/unknown classify every key this file's document actually has:
	// present as a dotted path (e.g. "server.listen_addr") if this schema
	// recognizes it, unknown (WARN-and-ignore, below) otherwise.
	// datasources entries aren't recursed into - their non-common fields
	// are opaque by design, not "unrecognized".
	present := map[string]bool{}
	var unknown []string
	scanNested := func(node *yaml.Node, prefix string, known map[string]bool) {
		if node.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if known[key] {
				present[prefix+key] = true
			} else {
				unknown = append(unknown, prefix+key)
			}
		}
	}

	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(root.Content); i += 2 {
			key, val := root.Content[i].Value, root.Content[i+1]
			switch key {
			case "server":
				scanNested(val, "server.", knownServerFields)
			case "checks":
				scanNested(val, "checks.", knownChecksFields)
			case "":
				// nothing to classify
			default:
				if knownTopLevel[key] {
					present[key] = true
				} else {
					unknown = append(unknown, key)
				}
			}
		}
	}

	for _, key := range unknown {
		slog.Warn("config: unrecognized field ignored", "file", filePath, "field", key)
	}

	var layer Config
	if err := yaml.Unmarshal(data, &layer); err != nil {
		return fmt.Errorf("config: parse %s: %w", filePath, err)
	}

	// Merge layer onto cfg, but only for fields present marks as actually
	// present in the source file - a Go zero value is otherwise
	// indistinguishable from "not set in this file".
	if present["logging_level"] {
		cfg.LoggingLevel = layer.LoggingLevel
	}
	if present["config_dir"] {
		cfg.ConfigDir = layer.ConfigDir
	}
	if present["server.listen_addr"] {
		cfg.Server.ListenAddr = layer.Server.ListenAddr
	}
	if present["server.server_cert"] {
		cfg.Server.ServerCert = layer.Server.ServerCert
	}
	if present["server.server_key"] {
		cfg.Server.ServerKey = layer.Server.ServerKey
	}
	if present["server.metrics_path"] {
		cfg.Server.MetricsPath = layer.Server.MetricsPath
	}
	if present["server.decision_timeout"] {
		cfg.Server.DecisionTimeout = layer.Server.DecisionTimeout
	}
	if present["checks.host_network"] {
		cfg.Checks.HostNetwork = layer.Checks.HostNetwork
	}
	if present["checks.privileged"] {
		cfg.Checks.Privileged = layer.Checks.Privileged
	}
	if present["checks.docker_cp"] {
		cfg.Checks.DockerCP = layer.Checks.DockerCP
	}
	if present["checks.docker_exec"] {
		cfg.Checks.DockerExec = layer.Checks.DockerExec
	}

	// unionStrings appends every entry of add not already present in base,
	// by exact string content - shared by allowlist/admin_users/
	// admin_groups. canonicalization (for allowlist specifically) is
	// internal/rules' job, not this package's.
	unionStrings := func(base, add []string) []string {
		seen := make(map[string]bool, len(base))
		for _, s := range base {
			seen[s] = true
		}
		for _, s := range add {
			if !seen[s] {
				seen[s] = true
				base = append(base, s)
			}
		}
		return base
	}
	if present["allowlist"] {
		cfg.Allowlist = unionStrings(cfg.Allowlist, layer.Allowlist)
	}
	if present["admin_users"] {
		cfg.AdminUsers = unionStrings(cfg.AdminUsers, layer.AdminUsers)
	}
	if present["admin_groups"] {
		cfg.AdminGroups = unionStrings(cfg.AdminGroups, layer.AdminGroups)
	}
	if present["datasources"] {
		// Merge layer.Datasources into cfg.Datasources by Name: a new name
		// is appended, an existing name has its entry replaced by layer's
		// version (last-file-wins, extended to a keyed list).
		index := make(map[string]int, len(cfg.Datasources))
		for i, d := range cfg.Datasources {
			index[d.Name] = i
		}
		for _, d := range layer.Datasources {
			if i, ok := index[d.Name]; ok {
				cfg.Datasources[i] = d
			} else {
				index[d.Name] = len(cfg.Datasources)
				cfg.Datasources = append(cfg.Datasources, d)
			}
		}
	}

	return nil
}

// # env / flag overrides

// ApplyEnv overrides cfg's fields from AUTHZ_*-prefixed environment
// variables (AUTHZ_SECTION_KEY naming). allowlist, datasources, checks.*,
// admin_users, and admin_groups are deliberately excluded - policy lives in
// the file only.
//
// Only variables that are actually set (os.LookupEnv's ok, not merely
// non-empty) take effect; unset variables leave cfg's value alone.
func ApplyEnv(cfg *Config) error {
	if v, ok := os.LookupEnv("AUTHZ_LOGGING_LEVEL"); ok {
		cfg.LoggingLevel = v
	}
	if v, ok := os.LookupEnv("AUTHZ_SERVER_LISTEN_ADDR"); ok {
		cfg.Server.ListenAddr = v
	}
	if v, ok := os.LookupEnv("AUTHZ_SERVER_CERT"); ok {
		cfg.Server.ServerCert = v
	}
	if v, ok := os.LookupEnv("AUTHZ_SERVER_KEY"); ok {
		cfg.Server.ServerKey = v
	}
	if v, ok := os.LookupEnv("AUTHZ_SERVER_METRICS_PATH"); ok {
		cfg.Server.MetricsPath = v
	}
	if v, ok := os.LookupEnv("AUTHZ_SERVER_DECISION_TIMEOUT"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("config: AUTHZ_SERVER_DECISION_TIMEOUT=%q: %w", v, err)
		}
		cfg.Server.DecisionTimeout = Duration(d)
	}
	return nil
}

// FlagOverrides holds CLI-flag-sourced overrides for ApplyFlags. An empty
// string means "not set on the command line" - the same convention ApplyEnv
// uses for an unset environment variable. cmd/authzmtls populates this from
// its own CLI parsing (kong); this package has no opinion on how.
type FlagOverrides struct {
	LoggingLevel    string
	ListenAddr      string
	ServerCert      string
	ServerKey       string
	MetricsPath     string
	DecisionTimeout string
}

// ApplyFlags overrides cfg's fields from o, field by field, skipping any
// left at "". Same exclusions as ApplyEnv: allowlist, datasources,
// checks.*, admin_users, and admin_groups have no flag equivalent at all.
func ApplyFlags(cfg *Config, o FlagOverrides) error {
	if o.LoggingLevel != "" {
		cfg.LoggingLevel = o.LoggingLevel
	}
	if o.ListenAddr != "" {
		cfg.Server.ListenAddr = o.ListenAddr
	}
	if o.ServerCert != "" {
		cfg.Server.ServerCert = o.ServerCert
	}
	if o.ServerKey != "" {
		cfg.Server.ServerKey = o.ServerKey
	}
	if o.MetricsPath != "" {
		cfg.Server.MetricsPath = o.MetricsPath
	}
	if o.DecisionTimeout != "" {
		d, err := time.ParseDuration(o.DecisionTimeout)
		if err != nil {
			return fmt.Errorf("config: invalid --decision-timeout=%q: %w", o.DecisionTimeout, err)
		}
		cfg.Server.DecisionTimeout = Duration(d)
	}
	return nil
}

// # validation

// ValidationError is the fatal outcome of Validate: every problem found in
// one pass, not just the first, so an operator sees the whole list at once.
// Use errors.As to distinguish it from Load's own file/parse errors.
type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config: invalid configuration: %s", strings.Join(e.Issues, "; "))
}

// Validate checks cfg for every fatal condition. Must run after ApplyEnv and
// ApplyFlags (see LoadFull), since it validates the final, fully overridden
// config; an empty logging_level/listen_addr/etc. surviving to this point
// means an explicit, invalid override (applyDefaults already ran).
func Validate(cfg *Config) error {
	var issues []string

	if !logging.ValidLevelName(cfg.LoggingLevel) {
		issues = append(issues, fmt.Sprintf("logging_level: invalid value %q (want one of trace, debug, info, warn, error)", cfg.LoggingLevel))
	}

	issues = append(issues, validateServerTLS(cfg.Server)...)

	if len(cfg.Allowlist) == 0 {
		// Deliberately fatal rather than "deny everything" by omission -
		// an empty allowlist is more likely a forgotten setting than an
		// intentional lockdown.
		issues = append(issues, "allowlist: must not be empty")
	}

	issues = append(issues, validateDatasources(cfg.Datasources)...)
	issues = append(issues, validateChecks(cfg.Checks)...)

	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Issues: issues}
}

func validateServerTLS(server ServerConfig) []string {
	certSet := server.ServerCert != ""
	keySet := server.ServerKey != ""

	if certSet != keySet {
		return []string{"server: server_cert and server_key must both be set (TLS) or both unset (plain HTTP) - exactly one is ambiguous"}
	}
	if !certSet && !keySet {
		return nil
	}

	var issues []string
	if _, err := os.Stat(server.ServerCert); err != nil {
		issues = append(issues, fmt.Sprintf("server.server_cert: %v", err))
	}
	if _, err := os.Stat(server.ServerKey); err != nil {
		issues = append(issues, fmt.Sprintf("server.server_key: %v", err))
	}
	return issues
}

func validateDatasources(datasources []DatasourceConfig) []string {
	var issues []string
	seen := make(map[string]bool, len(datasources))
	for i, ds := range datasources {
		switch {
		case ds.Name == "":
			issues = append(issues, fmt.Sprintf("datasources[%d]: name is required", i))
		case seen[ds.Name]:
			issues = append(issues, fmt.Sprintf("datasources[%d]: duplicate name %q", i, ds.Name))
		default:
			seen[ds.Name] = true
		}
		// This package doesn't import the provider registry, so it can only
		// check that a type was named at all, not that it's registered.
		if ds.Type == "" {
			issues = append(issues, fmt.Sprintf("datasources[%d] (%s): type is required", i, ds.Name))
		}
	}
	return issues
}

func validateChecks(checks ChecksConfig) []string {
	var issues []string
	for _, c := range []struct {
		field string
		val   CheckSetting
	}{
		{"checks.host_network", checks.HostNetwork},
		{"checks.privileged", checks.Privileged},
		{"checks.docker_cp", checks.DockerCP},
		{"checks.docker_exec", checks.DockerExec},
	} {
		if !c.val.valid() {
			issues = append(issues, fmt.Sprintf("%s: must be \"allow\" or \"deny\", got %q", c.field, c.val))
		}
	}
	return issues
}

// # LoadFull / Store / Watch (SIGHUP reload)

// LoadFull runs Load -> ApplyEnv -> ApplyFlags -> Validate, in README's
// documented precedence order (CLI flags > env vars > config.yaml+conf.d).
// Startup and every SIGHUP reload (via Watch) share this one sequence.
func LoadFull(path string, overrides FlagOverrides) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	if err := ApplyEnv(cfg); err != nil {
		return nil, err
	}
	if err := ApplyFlags(cfg, overrides); err != nil {
		return nil, err
	}
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Store holds the most recently successfully loaded *Config behind a
// lock-free atomic.Pointer, per README's "Performance & concurrency"
// ("Config is read via a lock-free atomic.Pointer, swapped only on
// SIGHUP"). Every per-request read (Current) is wait-free; only Watch's
// SIGHUP handler ever writes to it, and only after a reload has fully
// succeeded - see Watch's doc comment for why a failed reload never
// touches the Store.
type Store struct {
	ptr atomic.Pointer[Config]
}

// NewStore creates a Store seeded with cfg - normally the result of the
// startup call to LoadFull, before Watch is ever set up. cfg must not be
// nil.
func NewStore(cfg *Config) *Store {
	s := &Store{}
	s.ptr.Store(cfg)
	return s
}

// Current returns the most recently successfully loaded Config. Safe for
// concurrent use by any number of readers, concurrently with Watch's
// (single) writer.
func (s *Store) Current() *Config {
	return s.ptr.Load()
}

// Watch reloads configuration on every SIGHUP: logs INFO, re-runs LoadFull,
// and on success atomically swaps store and calls onReload(cfg, nil). A
// failed reload leaves store untouched (last-good config keeps serving) and
// calls onReload(nil, err) - reload failures are fatal, like a bad config at
// startup, but it's onReload's job to act on that; Watch never exits itself.
//
// The returned stop func unregisters the handler; safe to call more than
// once.
func Watch(store *Store, path string, overrides FlagOverrides, onReload func(*Config, error)) (stop func()) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-sigCh:
				slog.Info("SIGHUP received, reloading config", "path", path)

				cfg, err := LoadFull(path, overrides)
				if err != nil {
					onReload(nil, err)
					continue
				}
				slog.Debug("reload: allowlist", "allowlist", cfg.Allowlist)
				store.ptr.Store(cfg)
				onReload(cfg, nil)
			case <-done:
				return
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(sigCh)
			close(done)
		})
	}
}
