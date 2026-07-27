// Package rules implements authzmtls's authorization rules (admin bypass,
// mount allowlist, volume bind mount, host networking, privileged mode,
// docker cp, docker exec) and the first-match-wins Chain that evaluates
// them, per README.md's "Enforcement" section. It also owns the
// Docker-request-shape parsing and allowlist path matching (mounts.go)
// those rules need - both are single-consumer concerns that don't earn
// their own package.
package rules

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/metric"

	"github.com/weishiuchang/authzmtls/internal/config"
	"github.com/weishiuchang/authzmtls/internal/datasources"
	"github.com/weishiuchang/authzmtls/internal/dockerapi"
	"github.com/weishiuchang/authzmtls/internal/telemetry"
)

// Rule is one authorization check: Evaluate returns an active Allow/Deny
// decision or Abstains if nothing here applies. A non-nil error always means
// an unexpected internal failure, never a policy decision - *Chain also
// implements Rule, so it can nest inside another Chain.
type Rule interface {
	Evaluate(ctx context.Context, req *dockerapi.AuthZReq) (Decision, error)
}

// Verdict is a Rule's (or Chain's) opinion on one request: permit it, block
// it, or abstain. Abstain is its own value rather than folding into Allow so
// Chain's decision logging can tell "checked and fine" apart from "nothing
// to check" (see Decision's doc comment).
type Verdict int

const (
	// Abstain means this Rule found nothing relevant on the request, not
	// "checked and it's fine." A Chain treats all-abstain as default-allow
	// but logs and counts nothing for it.
	Abstain Verdict = iota
	// Allow is an active "yes," always paired with a Detail so it's
	// discoverable at DEBUG even though it's usually the default outcome.
	Allow
	// Deny blocks the request, always paired with a Detail and a Msg (see
	// Decision's doc comment on the content restriction unique to Msg).
	Deny
)

// String renders v as "abstain"/"allow"/"deny", the names used throughout
// this package's logs and tests, rather than slog's default int rendering.
func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	default:
		return "abstain"
	}
}

// Decision is a Rule's (or Chain's) answer for one request. Detail is
// server-side-log-only and can be as rich as useful; Msg (returned to
// dockerd as AuthZRes.Msg on Deny) must contain only request-derived
// content - never anything from a datasource - because the
// dockerd<->authzmtls hop is unauthenticated, so anything in the response is
// reachable by anyone who can hit the port. Both fields are empty on an
// Abstain Decision. A Rule's Msg should not itself include the caller's
// identity - Chain.Decide prefixes it once via prefixIdentity, uniformly
// across every built-in Rule.
type Decision struct {
	Verdict Verdict
	Detail  string
	Msg     string
}

// deny uses the same string for both Detail and Msg, safe since every
// built-in Rule's messages are already request-derived only.
func deny(msg string) Decision {
	return Decision{Verdict: Deny, Detail: msg, Msg: msg}
}

// prefixIdentity prepends identity (AuthZReq.User - dockerd's TLS-cert-CN
// value, not a datasource lookup) to msg, so a denied caller's own CLI error
// names who was denied. Identity-blank (no client cert) leaves msg alone
// rather than emitting a bare "leading colon". Called once from Chain.Decide
// rather than by every Rule, so it's applied uniformly regardless of which
// Rule produced the Deny.
func prefixIdentity(identity, msg string) string {
	if identity == "" {
		return msg
	}
	return identity + ": " + msg
}

// allow is deny's counterpart for an explicit Allow.
func allow(msg string) Decision {
	return Decision{Verdict: Allow, Detail: msg, Msg: msg}
}

// abstain is a Rule's "nothing here for me" answer.
func abstain() Decision {
	return Decision{Verdict: Abstain}
}

// internalErrorMsg is the fixed, generic message returned to dockerd for any
// unexpected internal failure - never err.Error() directly, since the
// dockerd<->authzmtls hop is unauthenticated. Full error detail is logged
// server-side only (see Chain.Decide).
const internalErrorMsg = "internal error"

// requestsInstrumentName and deniedInstrumentName are the two decision
// counters this package owns, incremented only at the point decision logging
// happens - never per-rule.
const (
	requestsInstrumentName = "authzmtls.requests"
	deniedInstrumentName   = "authzmtls.denied"
)

// Chain runs a fixed ordered list of Rules and is also itself a Rule, so a
// Chain can nest inside another Chain. Decision logging and metrics are
// centralized once on Chain.Decide rather than duplicated inside each Rule.
type Chain struct {
	rules  []Rule
	logger *slog.Logger

	requests metric.Int64Counter
	denied   metric.Int64Counter
}

// Chain is usable both as a plain Rule and as the dockerapi.Decider the
// running service wires into dockerapi.NewHandler, with no adapter needed.
var (
	_ Rule              = (*Chain)(nil)
	_ dockerapi.Decider = (*Chain)(nil)
)

// NewChain builds a Chain over rules, run in the given order. A nil logger
// falls back to slog.Default(), so a caller that doesn't care about logs
// doesn't need to construct one just to build a Chain.
func NewChain(logger *slog.Logger, rules ...Rule) (*Chain, error) {
	if logger == nil {
		logger = slog.Default()
	}

	meter := telemetry.Meter()
	requests, err := meter.Int64Counter(requestsInstrumentName,
		metric.WithUnit("1"),
		metric.WithDescription("Requests the rule chain reached an explicit allow or deny verdict on; abstained/pass-through traffic is not counted."),
	)
	if err != nil {
		return nil, err
	}
	denied, err := meter.Int64Counter(deniedInstrumentName,
		metric.WithUnit("1"),
		metric.WithDescription("The subset of authzmtls.requests that were denials."),
	)
	if err != nil {
		return nil, err
	}

	return &Chain{rules: rules, logger: logger, requests: requests, denied: denied}, nil
}

// Evaluate implements Rule: the first non-abstain Decision from c.rules
// wins. An all-abstain result stays Abstain rather than becoming an explicit
// Allow, so a nested Chain can still defer to its outer chain and Decide can
// tell "nothing decided" apart from "decided Allow."
//
// Evaluate is deliberately side-effect-free (no logging, no metrics), which
// keeps it testable as pure rule-evaluation logic, decoupled from Decide.
func (c *Chain) Evaluate(ctx context.Context, req *dockerapi.AuthZReq) (Decision, error) {
	for _, r := range c.rules {
		d, err := r.Evaluate(ctx, req)
		if err != nil {
			return Decision{}, err
		}
		if d.Verdict != Abstain {
			return d, nil
		}
	}
	return abstain(), nil
}

// Decide implements dockerapi.Decider: it turns a Decision into the
// (allow, msg, err) shape dockerapi needs, logs it (deny -> INFO, explicit
// allow -> DEBUG, abstain -> nothing), and records the requests/denied
// counters.
//
// An Evaluate error is logged in full server-side, mapped to
// internalErrorMsg, and fails closed (allow=false) rather than being
// returned - dockerapi's handler would otherwise put a raw error's Error()
// text straight into the HTTP response. Decide therefore always returns a
// nil error itself.
func (c *Chain) Decide(ctx context.Context, req *dockerapi.AuthZReq) (allow bool, msg string, err error) {
	decision, evalErr := c.Evaluate(ctx, req)
	if evalErr != nil {
		// WARN is the closest fit of the "on by default" levels for
		// something an operator should notice, though not ERROR (doesn't
		// crash the process).
		c.logger.WarnContext(ctx, "rule evaluation failed", "error", evalErr)
		return false, internalErrorMsg, nil
	}

	switch decision.Verdict {
	case Deny:
		c.logger.InfoContext(ctx, "denied", "identity", req.User, "detail", decision.Detail)
		c.requests.Add(ctx, 1)
		c.denied.Add(ctx, 1)
		return false, prefixIdentity(req.User, decision.Msg), nil
	case Allow:
		c.logger.DebugContext(ctx, "allowed", "identity", req.User, "detail", decision.Detail)
		c.requests.Add(ctx, 1)
		return true, decision.Msg, nil
	default: // Abstain: default-allow, nothing decided, no logging, no metrics.
		return true, "", nil
	}
}

// NewBuiltinChain assembles the built-in Rules into one Chain, in README's
// canonical "Enforcement" table order, so that order lives in one place
// rather than being re-assembled (and potentially drifting) at every call
// site. AdminRule always goes first: it's the one rule meant to bypass
// every other check, which only holds if nothing else runs before it.
func NewBuiltinChain(cfg *config.Config, ds *datasources.Set, logger *slog.Logger) (*Chain, error) {
	return NewChain(logger,
		NewAdminRule(cfg.AdminUsers, cfg.AdminGroups, ds),
		NewMountAllowlistRule(cfg.Allowlist, ds),
		NewVolumeBindMountRule(cfg.Allowlist, ds),
		NewHostNetworkRule(cfg.Checks.HostNetwork),
		NewPrivilegedRule(cfg.Checks.Privileged),
		NewDockerCPRule(cfg.Checks.DockerCP),
		NewDockerExecRule(cfg.Checks.DockerExec),
	)
}

// HostNetworkRule, PrivilegedRule, DockerCPRule, and DockerExecRule are the
// four simple global on/off gates: unlike the mount allowlist, none of them
// are identity-aware - every request gets the same answer, per their
// checks.* setting.

// HostNetworkRule gates HostConfig.NetworkMode: "host" via checks.host_network.
type HostNetworkRule struct {
	setting config.CheckSetting
}

// NewHostNetworkRule builds a HostNetworkRule from config.Config's
// checks.host_network setting.
func NewHostNetworkRule(setting config.CheckSetting) *HostNetworkRule {
	return &HostNetworkRule{setting: setting}
}

var _ Rule = (*HostNetworkRule)(nil)

// Evaluate implements Rule. Abstains unless this is a container-create
// request that explicitly asked for HostConfig.NetworkMode: "host".
func (r *HostNetworkRule) Evaluate(ctx context.Context, req *dockerapi.AuthZReq) (Decision, error) {
	mode, ok := NetworkMode(req.RequestURI, req.RequestBody)
	if !ok || mode != "host" {
		return abstain(), nil
	}

	if r.setting == config.CheckDeny {
		return deny("host networking requested and denied by policy"), nil
	}
	// An active allow, not abstain, so this stays discoverable at DEBUG
	// instead of vanishing into the silent default-allow path.
	return allow("host networking requested and permitted by policy"), nil
}

// PrivilegedRule gates HostConfig.Privileged via checks.privileged.
type PrivilegedRule struct {
	setting config.CheckSetting
}

// NewPrivilegedRule builds a PrivilegedRule from config.Config's
// checks.privileged setting.
func NewPrivilegedRule(setting config.CheckSetting) *PrivilegedRule {
	return &PrivilegedRule{setting: setting}
}

var _ Rule = (*PrivilegedRule)(nil)

// Evaluate implements Rule. Abstains unless this is a container-create
// request with HostConfig.Privileged: true.
func (r *PrivilegedRule) Evaluate(ctx context.Context, req *dockerapi.AuthZReq) (Decision, error) {
	privileged, ok := Privileged(req.RequestURI, req.RequestBody)
	if !ok || !privileged {
		return abstain(), nil
	}

	if r.setting == config.CheckDeny {
		return deny("privileged mode requested and denied by policy"), nil
	}
	return allow("privileged mode requested and permitted by policy"), nil
}

// DockerCPRule is a global on/off gate on the docker cp endpoint. Unlike
// HostNetworkRule/PrivilegedRule, recognition is a pure method+URI shape
// check (IsDockerCP), so there's no "field absent" middle case.
type DockerCPRule struct {
	setting config.CheckSetting
}

// NewDockerCPRule builds a DockerCPRule from config.Config's checks.docker_cp
// setting.
func NewDockerCPRule(setting config.CheckSetting) *DockerCPRule {
	return &DockerCPRule{setting: setting}
}

var _ Rule = (*DockerCPRule)(nil)

// Evaluate implements Rule. Abstains unless method+URI match the docker cp
// endpoint shape (IsDockerCP).
func (r *DockerCPRule) Evaluate(ctx context.Context, req *dockerapi.AuthZReq) (Decision, error) {
	if !IsDockerCP(req.RequestMethod, req.RequestURI) {
		return abstain(), nil
	}

	if r.setting == config.CheckDeny {
		return deny("docker cp denied by policy"), nil
	}
	return allow("docker cp permitted by policy"), nil
}

// DockerExecRule mirrors DockerCPRule but gates the docker exec create
// endpoint via checks.docker_exec / IsDockerExecCreate instead.
type DockerExecRule struct {
	setting config.CheckSetting
}

// NewDockerExecRule builds a DockerExecRule from config.Config's
// checks.docker_exec setting.
func NewDockerExecRule(setting config.CheckSetting) *DockerExecRule {
	return &DockerExecRule{setting: setting}
}

var _ Rule = (*DockerExecRule)(nil)

// Evaluate implements Rule. Abstains unless method+URI match the docker exec
// create endpoint shape - deliberately not also /exec/{id}/start, since
// blocking create is sufficient.
func (r *DockerExecRule) Evaluate(ctx context.Context, req *dockerapi.AuthZReq) (Decision, error) {
	if !IsDockerExecCreate(req.RequestMethod, req.RequestURI) {
		return abstain(), nil
	}

	if r.setting == config.CheckDeny {
		return deny("docker exec denied by policy"), nil
	}
	return allow("docker exec permitted by policy"), nil
}
