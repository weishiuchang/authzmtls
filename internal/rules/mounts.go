package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/sync/errgroup"

	"github.com/weishiuchang/authzmtls/internal/datasources"
	"github.com/weishiuchang/authzmtls/internal/dockerapi"
)

// # Docker request-shape parsing

// mountSpec is the relevant subset of HostConfig.Mounts' object shape. Only
// Source is currently consumed; the rest is kept for clarity.
type mountSpec struct {
	Type     string `json:"Type"`
	Source   string `json:"Source"`
	Target   string `json:"Target"`
	ReadOnly bool   `json:"ReadOnly"`
}

// hostConfig is the private, decoded-once subset of HostConfig that Binds,
// NetworkMode, and Privileged all read from. NetworkMode and Privileged are
// pointers so presence vs. absence in the original JSON survives decode.
type hostConfig struct {
	Binds       []string
	Mounts      []mountSpec
	NetworkMode *string
	Privileged  *bool
}

// decodeHostConfig detects a container-create request and, if it is one,
// decodes the Binds/Mounts/NetworkMode/Privileged subset of its HostConfig.
// ok is false for any non-matching URI or undecodable body; callers treat
// that identically to "field absent".
func decodeHostConfig(uri string, body []byte) (hostConfig, bool) {
	if !isContainerCreate(uri) {
		return hostConfig{}, false
	}

	var wire struct {
		HostConfig struct {
			Binds       []string    `json:"Binds"`
			Mounts      []mountSpec `json:"Mounts"`
			NetworkMode *string     `json:"NetworkMode"`
			Privileged  *bool       `json:"Privileged"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return hostConfig{}, false
	}

	return hostConfig{
		Binds:       wire.HostConfig.Binds,
		Mounts:      wire.HostConfig.Mounts,
		NetworkMode: wire.HostConfig.NetworkMode,
		Privileged:  wire.HostConfig.Privileged,
	}, true
}

// Binds returns the normalized host source paths from HostConfig.Binds and
// HostConfig.Mounts, combined. Non-matching requests return an empty,
// non-nil slice.
func Binds(uri string, body []byte) []string {
	result := []string{}

	hc, ok := decodeHostConfig(uri, body)
	if !ok {
		return result
	}

	for _, b := range hc.Binds {
		src := b
		if idx := strings.IndexByte(b, ':'); idx >= 0 {
			src = b[:idx]
		}
		if src != "" {
			result = append(result, src)
		}
	}
	for _, m := range hc.Mounts {
		if m.Source != "" {
			result = append(result, m.Source)
		}
	}

	return result
}

// NetworkMode returns a container-create request's HostConfig.NetworkMode
// and true, or ("", false) if the request doesn't match, the body doesn't
// decode, or the field is absent from the body.
func NetworkMode(uri string, body []byte) (string, bool) {
	hc, ok := decodeHostConfig(uri, body)
	if !ok || hc.NetworkMode == nil {
		return "", false
	}
	return *hc.NetworkMode, true
}

// Privileged returns a container-create request's HostConfig.Privileged and
// true, or (false, false) if the request doesn't match, the body doesn't
// decode, or the field is absent from the body.
func Privileged(uri string, body []byte) (bool, bool) {
	hc, ok := decodeHostConfig(uri, body)
	if !ok || hc.Privileged == nil {
		return false, false
	}
	return *hc.Privileged, true
}

// volumeCreate is the decoded {Name, Driver, DriverOpts, Labels} subset of a
// /volumes/create request body, an entirely different shape from
// container-create's.
type volumeCreate struct {
	Name       string
	Driver     string
	DriverOpts map[string]string
	Labels     map[string]string
}

// decodeVolumeCreate detects a volume-create request and, if it is one,
// decodes its {Name, Driver, DriverOpts, Labels} body. ok is false for any
// non-matching URI or undecodable body.
func decodeVolumeCreate(uri string, body []byte) (volumeCreate, bool) {
	if !isVolumeCreate(uri) {
		return volumeCreate{}, false
	}

	var wire struct {
		Name       string            `json:"Name"`
		Driver     string            `json:"Driver"`
		DriverOpts map[string]string `json:"DriverOpts"`
		Labels     map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return volumeCreate{}, false
	}

	return volumeCreate{
		Name:       wire.Name,
		Driver:     wire.Driver,
		DriverOpts: wire.DriverOpts,
		Labels:     wire.Labels,
	}, true
}

// VolumeBindDevice recognizes the local-driver bind-mount-passthrough trick
// (docker volume create --opt type=none --opt o=bind --opt device=<path>)
// in a /volumes/create request body, returning DriverOpts.device and
// ok=true on a match. An absent/empty Driver defaults to "local";
// DriverOpts.o is comma-split and matched exactly against "bind" per token
// (so "rbind" doesn't match but "rw,bind" does).
func VolumeBindDevice(uri string, body []byte) (string, bool) {
	vc, ok := decodeVolumeCreate(uri, body)
	if !ok {
		return "", false
	}

	driver := vc.Driver
	if driver == "" {
		driver = "local"
	}
	if driver != "local" {
		return "", false
	}

	o, present := vc.DriverOpts["o"]
	if !present {
		return "", false
	}
	boundFound := false
	for _, tok := range strings.Split(o, ",") {
		if strings.TrimSpace(tok) == "bind" {
			boundFound = true
			break
		}
	}
	if !boundFound {
		return "", false
	}

	device, present := vc.DriverOpts["device"]
	if !present {
		return "", false
	}

	return device, true
}

// IsDockerCP reports whether method+uri is a docker cp request: GET or PUT
// whose path ends in /containers/{id}/archive, independent of API version
// prefix.
func IsDockerCP(method, uri string) bool {
	if method != http.MethodGet && method != http.MethodPut {
		return false
	}
	segs := pathSegments(uri)
	return len(segs) == 3 && segs[0] == "containers" && segs[1] != "" && segs[2] == "archive"
}

// IsDockerExecCreate reports whether method+uri is a docker exec create
// request: POST whose path ends in /containers/{id}/exec, independent of the
// API version prefix. Deliberately does not also match /exec/{id}/start.
func IsDockerExecCreate(method, uri string) bool {
	if method != http.MethodPost {
		return false
	}
	segs := pathSegments(uri)
	return len(segs) == 3 && segs[0] == "containers" && segs[1] != "" && segs[2] == "exec"
}

// isContainerCreate reports whether uri's path is .../containers/create,
// independent of API version prefix.
func isContainerCreate(uri string) bool {
	segs := pathSegments(uri)
	return len(segs) == 2 && segs[0] == "containers" && segs[1] == "create"
}

// isVolumeCreate reports whether uri's path is .../volumes/create,
// independent of API version prefix.
func isVolumeCreate(uri string) bool {
	segs := pathSegments(uri)
	return len(segs) == 2 && segs[0] == "volumes" && segs[1] == "create"
}

// pathSegments splits uri's path into non-empty segments, discarding any
// query string and stripping a leading Docker API version segment
// ("v1.43", "v1", ...) if present.
func pathSegments(uri string) []string {
	p := uri
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}

	segs := strings.Split(p, "/")
	if len(segs) > 0 && isVersionSegment(segs[0]) {
		segs = segs[1:]
	}
	return segs
}

// isVersionSegment reports whether s looks like a Docker API version path
// segment: "v" followed by one or more dot-separated all-digit groups (e.g.
// "v1.43", "v1", "v2.0").
func isVersionSegment(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, part := range strings.Split(s[1:], ".") {
		if part == "" {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// # MountAllowlistRule / VolumeBindMountRule

// maxConcurrentMountChecks bounds how many mount paths one evaluation
// canonicalizes concurrently, capping the worst case for a pathological
// many-mount request. Not operator-configurable - an implementation detail,
// not a policy knob.
const maxConcurrentMountChecks = 8

// MountAllowlistRule is the identity-aware rule: every host path a
// /containers/create request would bind-mount in must resolve (after
// $USER/$GROUP substitution and symlink canonicalization) under some
// configured allowlist prefix.
type MountAllowlistRule struct {
	patterns []string
	ds       *datasources.Set
}

// NewMountAllowlistRule builds a MountAllowlistRule from the configured
// allowlist patterns (still containing $USER/$GROUP placeholders - expansion
// happens per-request, not here) and the datasource set to resolve against.
func NewMountAllowlistRule(patterns []string, ds *datasources.Set) *MountAllowlistRule {
	return &MountAllowlistRule{patterns: patterns, ds: ds}
}

var _ Rule = (*MountAllowlistRule)(nil)

// Evaluate implements Rule. It abstains on any request that isn't a
// container-create with at least one requested mount.
func (r *MountAllowlistRule) Evaluate(ctx context.Context, req *dockerapi.AuthZReq) (Decision, error) {
	paths := Binds(req.RequestURI, req.RequestBody)
	if len(paths) == 0 {
		return abstain(), nil
	}

	matcher := resolveMatcher(ctx, req, r.patterns, r.ds)

	allowedFor := checkPathsConcurrently(paths, matcher)

	// Walk in request order, not goroutine-completion order, so the
	// reported "first non-matching path" is deterministic.
	for i, path := range paths {
		if !allowedFor[i] {
			return deny(fmt.Sprintf("mount path %s not allowed", path)), nil
		}
	}

	return allow(fmt.Sprintf("mount path(s) %s allowed", strings.Join(paths, ", "))), nil
}

// checkPathsConcurrently canonicalizes and matches every path in paths,
// bounded to maxConcurrentMountChecks concurrent goroutines since
// Canonicalize does real symlink-resolution syscalls. A path that fails to
// canonicalize is treated as not-allowed, per Canonicalize's deny-by-default
// contract - never as a rule-evaluation error.
func checkPathsConcurrently(paths []string, matcher *Matcher) []bool {
	allowedFor := make([]bool, len(paths))

	var g errgroup.Group
	g.SetLimit(maxConcurrentMountChecks)
	for i, path := range paths {
		g.Go(func() error {
			canon, err := Canonicalize(path)
			if err != nil {
				allowedFor[i] = false
				return nil
			}
			allowedFor[i] = matcher.Allowed(canon)
			return nil
		})
	}
	// Every Go func above unconditionally returns nil, so Wait can only
	// ever return nil.
	_ = g.Wait()

	return allowedFor
}

// resolveVars extracts this request's request-derived variables and
// resolves them against ds - the one identity-resolution call path every
// identity-aware Rule shares (resolveMatcher below, and AdminRule), so a
// future change to resolution applies to all of them by construction.
func resolveVars(ctx context.Context, req *dockerapi.AuthZReq, ds *datasources.Set) map[string][]string {
	vars := Extract(req)

	// Lets a rejected-vars WARN log (internal/datasources) name which
	// request triggered it; doesn't affect resolution.
	ctx = datasources.WithRequestContext(ctx, req.RequestMethod, req.RequestURI)
	return ds.Resolve(ctx, vars)
}

// resolveMatcher builds a Matcher for one request. It is the one call path
// MountAllowlistRule and VolumeBindMountRule both share, so a future change
// to matching semantics applies to both by construction.
//
// It's also why "no datasource available" implies deny with no explicit
// check: ds.Resolve never errors, it just resolves fewer variables, so a
// pattern referencing an unresolved $VAR is silently dropped by Expand and
// can never match.
func resolveMatcher(ctx context.Context, req *dockerapi.AuthZReq, patterns []string, ds *datasources.Set) *Matcher {
	resolved := resolveVars(ctx, req, ds)

	var expanded []string
	for _, pattern := range patterns {
		expanded = append(expanded, Expand(pattern, resolved)...)
	}
	return NewMatcher(expanded)
}

// VolumeBindMountRule closes the local-driver "type=none/o=bind/device=<path>"
// bypass: it checks a bind-style /volumes/create request's device path
// against the same allowlist as MountAllowlistRule, since the mount
// allowlist alone never sees a host path introduced this way.
type VolumeBindMountRule struct {
	patterns []string
	ds       *datasources.Set
}

// NewVolumeBindMountRule builds a VolumeBindMountRule from the same
// allowlist patterns and datasource set MountAllowlistRule uses.
func NewVolumeBindMountRule(patterns []string, ds *datasources.Set) *VolumeBindMountRule {
	return &VolumeBindMountRule{patterns: patterns, ds: ds}
}

var _ Rule = (*VolumeBindMountRule)(nil)

// Evaluate implements Rule. Unlike MountAllowlistRule, there's no separate
// "right request type, nothing to check" case: "not recognized" by
// VolumeBindDevice is the only abstain condition.
func (r *VolumeBindMountRule) Evaluate(ctx context.Context, req *dockerapi.AuthZReq) (Decision, error) {
	device, ok := VolumeBindDevice(req.RequestURI, req.RequestBody)
	if !ok {
		return abstain(), nil
	}

	matcher := resolveMatcher(ctx, req, r.patterns, r.ds)

	allowed := false
	if canon, err := Canonicalize(device); err == nil {
		allowed = matcher.Allowed(canon)
	}

	if !allowed {
		// Names this as a volume-create bind-mount device, not a plain
		// container-create mount, since it's a less obvious way a host path
		// becomes reachable from a container.
		return deny(fmt.Sprintf("volume-create bind-mount device %s not in allowlist", device)), nil
	}
	return allow(fmt.Sprintf("volume-create bind-mount device %s allowed", device)), nil
}

// # Path canonicalization

// ErrControlChar is returned by Canonicalize when path contains a NUL byte
// or other control character, giving a clean guaranteed-deny failure mode
// rather than relying on filepath/os calls to reject them unpredictably.
var ErrControlChar = errors.New("allowlist: path contains a NUL or control character")

// Canonicalize resolves path to an absolute, symlink-resolved, ".."-free
// form suitable for comparison against a Matcher - the traversal-bypass
// defense that keeps a relative path, embedded "..", or symlink from making
// an out-of-bounds path look allowed.
//
// path must refer to an existing filesystem entry, since resolving symlinks
// requires walking the real filesystem. Callers should treat any error from
// Canonicalize as "deny," never as a reason to skip the check.
func Canonicalize(path string) (string, error) {
	if err := checkNoControlChars(path); err != nil {
		return "", err
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("allowlist: resolve absolute path: %w", err)
	}

	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("allowlist: resolve symlinks: %w", err)
	}

	return filepath.Clean(resolved), nil
}

func checkNoControlChars(path string) error {
	for _, r := range path {
		if unicode.IsControl(r) {
			return ErrControlChar
		}
	}
	return nil
}

// # $VAR expansion

// placeholderPattern matches a single $NAME-style placeholder. Greedy by
// construction, so "$USERNAME" is matched whole, never split into "$USER" +
// "NAME".
var placeholderPattern = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)

// Expand substitutes every $NAME placeholder in pattern using vars,
// returning the resulting concrete, variable-free patterns (pattern
// unchanged if it has none). Multiple placeholders fan out to the cartesian
// product across all of them, each occurrence of a given name taking the
// same value within one produced result.
//
// A candidate expansion is dropped, not errored, if a placeholder has no
// usable value in vars, or if a candidate value contains a "/" or a
// NUL/control character - the latter is hardening against $USER/$GROUP
// (untrusted datasource output) injecting extra path segments into a
// pattern once Matcher's filepath.Clean collapses an embedded "..".
//
// If every candidate combination is dropped, Expand returns nil.
func Expand(pattern string, vars map[string][]string) []string {
	names := placeholderNames(pattern)
	if len(names) == 0 {
		return []string{pattern}
	}

	valuesByName := make([][]string, len(names))
	for i, name := range names {
		var safe []string
		for _, v := range vars[name] {
			if isSafeVarValue(v) {
				safe = append(safe, v)
			}
		}
		if len(safe) == 0 {
			// Missing or all-unsafe: no combination can be built.
			return nil
		}
		valuesByName[i] = safe
	}

	var results []string
	for _, combo := range cartesianProduct(valuesByName) {
		results = append(results, substitute(pattern, names, combo))
	}
	return results
}

// isSafeVarValue reports whether v is safe to substitute into a path
// pattern: no path separator, no NUL/control character. See Expand's doc
// comment for why.
func isSafeVarValue(v string) bool {
	for _, r := range v {
		if r == '/' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// placeholderNames returns the unique placeholder names referenced in
// pattern, in order of first appearance.
func placeholderNames(pattern string) []string {
	var names []string
	seen := make(map[string]bool)
	for _, m := range placeholderPattern.FindAllStringSubmatch(pattern, -1) {
		name := m[1]
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// substitute replaces every placeholder in names with its value in combo
// (combo[i] for names[i]), in a single pass so a substituted value can
// never itself be reinterpreted as part of another placeholder.
func substitute(pattern string, names []string, combo []string) string {
	valueByName := make(map[string]string, len(names))
	for i, name := range names {
		valueByName[name] = combo[i]
	}
	return placeholderPattern.ReplaceAllStringFunc(pattern, func(tok string) string {
		name := tok[1:] // strip leading "$"
		return valueByName[name]
	})
}

// cartesianProduct returns the cartesian product of lists, as a slice of
// combinations, each combination holding one value per input list in the
// same order as lists. cartesianProduct(nil) and cartesianProduct of an
// empty lists slice both return a single empty combination.
func cartesianProduct(lists [][]string) [][]string {
	result := [][]string{{}}
	for _, list := range lists {
		next := make([][]string, 0, len(result)*len(list))
		for _, combo := range result {
			for _, v := range list {
				c := make([]string, len(combo)+1)
				copy(c, combo)
				c[len(combo)] = v
				next = append(next, c)
			}
		}
		result = next
	}
	return result
}

// # Prefix matching

// Matcher checks canonicalized request paths against a fixed set of
// already-expanded, variable-free literal path prefixes (see Expand for the
// variable-substitution step that must happen before a Matcher is built).
type Matcher struct {
	prefixes []string
}

// NewMatcher builds a Matcher from prefixes, a list of literal directory
// paths already $VAR-expanded (Matcher itself never substitutes variables).
// Each prefix is normalized once via filepath.Clean plus stripping any
// trailing slash; unlike glob matching, there's no other "compiled pattern"
// to build.
func NewMatcher(prefixes []string) *Matcher {
	normalized := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		normalized = append(normalized, normalizePrefix(p))
	}
	return &Matcher{prefixes: normalized}
}

func normalizePrefix(p string) string {
	clean := filepath.Clean(p)
	if clean != "/" {
		clean = strings.TrimSuffix(clean, "/")
	}
	return clean
}

// Allowed reports whether path - which the caller MUST have already run
// through Canonicalize - is permitted by any configured prefix.
//
// Contract (the exact invariant the test file's table and fuzz test exist
// to prove): a canonicalized request path P matches a configured prefix Q
// (post-expansion, post-filepath.Clean) if and only if P == Q, or P begins
// with Q followed immediately by "/". No other condition ever produces a
// match.
//
// This is deliberately never a bare strings.HasPrefix(path, prefix), which
// would wrongly match "/data/app12" against configured "/data/app1" -
// matching is component-boundary-aware, and a literal "*" or "**" is just
// an ordinary character, never a glob.
func (m *Matcher) Allowed(path string) bool {
	for _, prefix := range m.prefixes {
		if path == prefix {
			return true
		}
		// Root ("/") is stored as-is, so it's already its own boundary;
		// every other prefix needs "/" appended to check descendants.
		boundary := prefix + "/"
		if prefix == "/" {
			boundary = "/"
		}
		if strings.HasPrefix(path, boundary) {
			return true
		}
	}
	return false
}
