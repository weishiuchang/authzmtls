package rules

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/weishiuchang/authzmtls/internal/config"
	"github.com/weishiuchang/authzmtls/internal/dockerapi"
)

// stubRule is a fixed-answer Rule for exercising Chain.Evaluate/Decide in
// isolation from the built-ins' own request-shape logic.
type stubRule struct {
	decision Decision
	err      error
}

func (s stubRule) Evaluate(context.Context, *dockerapi.AuthZReq) (Decision, error) {
	return s.decision, s.err
}

// # Chain.Evaluate: pure rule-chain composition

func TestChain_Evaluate_FirstNonAbstainWins(t *testing.T) {
	chain, err := NewChain(nil,
		stubRule{decision: abstain()},
		stubRule{decision: deny("second rule denies")},
		stubRule{decision: allow("third rule would allow, never reached")},
	)
	require.NoError(t, err)

	d, err := chain.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict)
	require.Equal(t, "second rule denies", d.Detail)
}

func TestChain_Evaluate_AllAbstainYieldsAbstain(t *testing.T) {
	chain, err := NewChain(nil, stubRule{decision: abstain()}, stubRule{decision: abstain()})
	require.NoError(t, err)

	d, err := chain.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, err)
	// Deliberately Abstain, not Allow - default-allow is applied by Decide,
	// not Evaluate.
	require.Equal(t, Abstain, d.Verdict)
}

// # Chain.Decide: response translation + internal-error handling

func TestChain_Decide_ExplicitAllow(t *testing.T) {
	logger, _ := newTestLogger(t)
	chain, err := NewChain(logger, stubRule{decision: allow("ok")})
	require.NoError(t, err)
	allowed, msg, err := chain.Decide(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, err, "Decide must never return a non-nil error, per its doc comment")
	require.True(t, allowed)
	require.Equal(t, "ok", msg)
}

func TestChain_Decide_ExplicitDeny(t *testing.T) {
	logger, _ := newTestLogger(t)
	chain, err := NewChain(logger, stubRule{decision: deny("no")})
	require.NoError(t, err)
	allowed, msg, err := chain.Decide(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, err)
	require.False(t, allowed)
	require.Equal(t, "cn=alice: no", msg, "Chain.Decide prefixes the caller's identity onto a Deny's Msg")
}

func TestChain_Decide_AbstainDefaultsToAllowWithEmptyMsg(t *testing.T) {
	logger, _ := newTestLogger(t)
	chain, err := NewChain(logger, stubRule{decision: abstain()})
	require.NoError(t, err)
	allowed, msg, err := chain.Decide(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, err)
	require.True(t, allowed)
	require.Empty(t, msg)
}

// TestChain_Decide_InternalErrorNeverLeaksErrorText proves a Rule error is
// swallowed and mapped to internalErrorMsg, logged in full server-side, and
// never returned or leaked into the response message.
func TestChain_Decide_InternalErrorNeverLeaksErrorText(t *testing.T) {
	const marker = "supersecret-internal-stack-trace-detail"
	logger, handler := newTestLogger(t)
	chain, err := NewChain(logger, stubRule{err: errors.New(marker)})
	require.NoError(t, err)

	allowed, msg, decideErr := chain.Decide(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, decideErr, "dockerapi's handler would put its Error() text straight into the HTTP response")
	require.False(t, allowed, "fail closed on an internal error")
	require.Equal(t, internalErrorMsg, msg, "want the fixed generic message")
	require.NotContains(t, msg, marker, "marker leaked into the response message")

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
	require.True(t, foundServerSide, "expected the full internal error (including the marker) to be logged server-side")
}

// # decision logging, all six built-in rules

// ruleLogFixture pairs deny/allow/abstain-triggering requests with a Rule
// instance producing each outcome, for one built-in rule type - used to
// drive the same deny->INFO / allow->DEBUG / abstain->nothing assertions
// uniformly across all six rules.
type ruleLogFixture struct {
	name string

	denyRule Rule
	denyReq  *dockerapi.AuthZReq

	allowRule Rule
	allowReq  *dockerapi.AuthZReq

	abstainRule Rule
	abstainReq  *dockerapi.AuthZReq
}

func allSixRuleLogFixtures(t *testing.T) []ruleLogFixture {
	t.Helper()

	base := t.TempDir()
	allowedDir := mkdir(t, base, "data", "allowed")
	otherDir := mkdir(t, base, "etc")

	mountDS := newDatasourceSet(t)

	return []ruleLogFixture{
		{
			name:        "MountAllowlistRule",
			denyRule:    NewMountAllowlistRule([]string{allowedDir}, mountDS),
			denyReq:     req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, otherDir)),
			allowRule:   NewMountAllowlistRule([]string{allowedDir}, mountDS),
			allowReq:    req("cn=alice", "POST", containerCreateURI, containerCreateBody(t, allowedDir)),
			abstainRule: NewMountAllowlistRule([]string{allowedDir}, mountDS),
			abstainReq:  req("cn=alice", "GET", notAContainerURI, nil),
		},
		{
			name:        "VolumeBindMountRule",
			denyRule:    NewVolumeBindMountRule([]string{allowedDir}, mountDS),
			denyReq:     req("cn=alice", "POST", volumeCreateURI, volumeCreateBindBody(t, otherDir)),
			allowRule:   NewVolumeBindMountRule([]string{allowedDir}, mountDS),
			allowReq:    req("cn=alice", "POST", volumeCreateURI, volumeCreateBindBody(t, allowedDir)),
			abstainRule: NewVolumeBindMountRule([]string{allowedDir}, mountDS),
			abstainReq:  req("cn=alice", "POST", volumeCreateURI, volumeCreatePlainBody(t)),
		},
		{
			name:        "HostNetworkRule",
			denyRule:    NewHostNetworkRule(config.CheckDeny),
			denyReq:     req("cn=alice", "POST", containerCreateURI, hostConfigBody(t, map[string]any{"NetworkMode": "host"})),
			allowRule:   NewHostNetworkRule(config.CheckAllow),
			allowReq:    req("cn=alice", "POST", containerCreateURI, hostConfigBody(t, map[string]any{"NetworkMode": "host"})),
			abstainRule: NewHostNetworkRule(config.CheckDeny),
			abstainReq:  req("cn=alice", "POST", containerCreateURI, hostConfigBody(t, map[string]any{})),
		},
		{
			name:        "PrivilegedRule",
			denyRule:    NewPrivilegedRule(config.CheckDeny),
			denyReq:     req("cn=alice", "POST", containerCreateURI, hostConfigBody(t, map[string]any{"Privileged": true})),
			allowRule:   NewPrivilegedRule(config.CheckAllow),
			allowReq:    req("cn=alice", "POST", containerCreateURI, hostConfigBody(t, map[string]any{"Privileged": true})),
			abstainRule: NewPrivilegedRule(config.CheckDeny),
			abstainReq:  req("cn=alice", "POST", containerCreateURI, hostConfigBody(t, map[string]any{})),
		},
		{
			name:        "DockerCPRule",
			denyRule:    NewDockerCPRule(config.CheckDeny),
			denyReq:     req("cn=alice", "GET", dockerCPURI, nil),
			allowRule:   NewDockerCPRule(config.CheckAllow),
			allowReq:    req("cn=alice", "GET", dockerCPURI, nil),
			abstainRule: NewDockerCPRule(config.CheckDeny),
			abstainReq:  req("cn=alice", "GET", notAContainerURI, nil),
		},
		{
			name:        "DockerExecRule",
			denyRule:    NewDockerExecRule(config.CheckDeny),
			denyReq:     req("cn=alice", "POST", dockerExecURI, nil),
			allowRule:   NewDockerExecRule(config.CheckAllow),
			allowReq:    req("cn=alice", "POST", dockerExecURI, nil),
			abstainRule: NewDockerExecRule(config.CheckDeny),
			abstainReq:  req("cn=alice", "GET", notAContainerURI, nil),
		},
	}
}

func TestChain_DecisionLogging_AllSixRules(t *testing.T) {
	for _, tc := range allSixRuleLogFixtures(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("deny logs exactly one INFO line with identity+detail, no DEBUG", func(t *testing.T) {
				logger, handler := newTestLogger(t)
				chain, err := NewChain(logger, tc.denyRule)
				require.NoError(t, err)
				allowed, _, err := chain.Decide(context.Background(), tc.denyReq)
				require.NoError(t, err)
				require.False(t, allowed, "expected this fixture's denyReq to be denied")

				infos := handler.recordsAtLevel(slog.LevelInfo)
				debugs := handler.recordsAtLevel(slog.LevelDebug)
				require.Len(t, infos, 1)
				require.Len(t, debugs, 0, "want 0 DEBUG records on a deny")
				identity, ok := attrString(infos[0], "identity")
				assert.True(t, ok)
				assert.Equal(t, tc.denyReq.User, identity)
				detail, ok := attrString(infos[0], "detail")
				assert.True(t, ok)
				assert.NotEmpty(t, detail)
			})

			t.Run("explicit allow logs exactly one DEBUG line, no INFO", func(t *testing.T) {
				logger, handler := newTestLogger(t)
				chain, err := NewChain(logger, tc.allowRule)
				require.NoError(t, err)
				allowed, _, err := chain.Decide(context.Background(), tc.allowReq)
				require.NoError(t, err)
				require.True(t, allowed, "expected this fixture's allowReq to be allowed")

				infos := handler.recordsAtLevel(slog.LevelInfo)
				debugs := handler.recordsAtLevel(slog.LevelDebug)
				require.Len(t, infos, 0, "want 0 INFO records on an explicit allow")
				require.Len(t, debugs, 1)
				identity, ok := attrString(debugs[0], "identity")
				assert.True(t, ok)
				assert.Equal(t, tc.allowReq.User, identity)
			})

			t.Run("abstain-all-the-way-through logs nothing", func(t *testing.T) {
				logger, handler := newTestLogger(t)
				chain, err := NewChain(logger, tc.abstainRule)
				require.NoError(t, err)
				allowed, msg, err := chain.Decide(context.Background(), tc.abstainReq)
				require.NoError(t, err)
				require.True(t, allowed, "want (true, \"\") for a fully-abstained request")
				require.Empty(t, msg)
				require.Empty(t, handler.all(), "want 0 log records for a fully-abstained request")
			})
		})
	}
}

// # decision metrics

func TestChain_DecisionMetrics_ExplicitAllow(t *testing.T) {
	logger, _ := newTestLogger(t)
	chain, reader := newTestChain(t, logger, stubRule{decision: allow("ok")})

	_, _, err := chain.Decide(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, err)

	assert.Equal(t, int64(1), counterSum(t, reader, requestsInstrumentName))
	assert.Equal(t, int64(0), counterSum(t, reader, deniedInstrumentName), "allow must not increment denied")
}

func TestChain_DecisionMetrics_Deny(t *testing.T) {
	logger, _ := newTestLogger(t)
	chain, reader := newTestChain(t, logger, stubRule{decision: deny("no")})

	_, _, err := chain.Decide(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, err)

	assert.Equal(t, int64(1), counterSum(t, reader, requestsInstrumentName))
	assert.Equal(t, int64(1), counterSum(t, reader, deniedInstrumentName))
}

func TestChain_DecisionMetrics_Abstain(t *testing.T) {
	logger, _ := newTestLogger(t)
	chain, reader := newTestChain(t, logger, stubRule{decision: abstain()})

	_, _, err := chain.Decide(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, err)

	assert.Equal(t, int64(0), counterSum(t, reader, requestsInstrumentName), "a fully-abstained request must not be counted")
	assert.Equal(t, int64(0), counterSum(t, reader, deniedInstrumentName))
}

// # HostNetworkRule

func TestHostNetworkRule_AbstainNonContainerCreate(t *testing.T) {
	rule := NewHostNetworkRule(config.CheckAllow)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "GET", notAContainerURI, nil))
	require.NoError(t, err)
	require.Equal(t, Abstain, d.Verdict)
}

func TestHostNetworkRule_AbstainFlagNotSet(t *testing.T) {
	rule := NewHostNetworkRule(config.CheckDeny)
	for _, body := range [][]byte{
		hostConfigBody(t, map[string]any{}),
		hostConfigBody(t, map[string]any{"NetworkMode": "bridge"}),
	} {
		d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, body))
		require.NoError(t, err)
		require.Equal(t, Abstain, d.Verdict, "for body %s", body)
	}
}

func TestHostNetworkRule_ExplicitAllowDefault(t *testing.T) {
	rule := NewHostNetworkRule(config.CheckAllow)
	body := hostConfigBody(t, map[string]any{"NetworkMode": "host"})
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, body))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict)
}

func TestHostNetworkRule_ExplicitDeny(t *testing.T) {
	rule := NewHostNetworkRule(config.CheckDeny)
	body := hostConfigBody(t, map[string]any{"NetworkMode": "host"})
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, body))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict)
}

// # PrivilegedRule

func TestPrivilegedRule_AbstainNonContainerCreate(t *testing.T) {
	rule := NewPrivilegedRule(config.CheckAllow)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "GET", notAContainerURI, nil))
	require.NoError(t, err)
	require.Equal(t, Abstain, d.Verdict)
}

func TestPrivilegedRule_AbstainFlagNotSet(t *testing.T) {
	rule := NewPrivilegedRule(config.CheckDeny)
	for _, body := range [][]byte{
		hostConfigBody(t, map[string]any{}),
		hostConfigBody(t, map[string]any{"Privileged": false}),
	} {
		d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, body))
		require.NoError(t, err)
		require.Equal(t, Abstain, d.Verdict, "for body %s", body)
	}
}

func TestPrivilegedRule_ExplicitAllowDefault(t *testing.T) {
	rule := NewPrivilegedRule(config.CheckAllow)
	body := hostConfigBody(t, map[string]any{"Privileged": true})
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, body))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict)
}

func TestPrivilegedRule_ExplicitDeny(t *testing.T) {
	rule := NewPrivilegedRule(config.CheckDeny)
	body := hostConfigBody(t, map[string]any{"Privileged": true})
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, body))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict)
}

// # DockerCPRule
// Unlike HostNetworkRule/PrivilegedRule, recognition is a pure method+URI
// shape check - no "field absent" middle case, so there's only one abstain
// scenario to cover: request shape not matching at all.

func TestDockerCPRule_AbstainWrongShape(t *testing.T) {
	rule := NewDockerCPRule(config.CheckDeny)
	for _, tc := range []struct{ method, uri string }{
		{"GET", notAContainerURI},
		{"POST", dockerCPURI},  // wrong method for cp
		{"GET", dockerExecURI}, // wrong endpoint
	} {
		d, err := rule.Evaluate(context.Background(), req("cn=alice", tc.method, tc.uri, nil))
		require.NoError(t, err)
		require.Equal(t, Abstain, d.Verdict, "method=%s uri=%s", tc.method, tc.uri)
	}
}

func TestDockerCPRule_ExplicitAllowDefault(t *testing.T) {
	rule := NewDockerCPRule(config.CheckAllow)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "GET", dockerCPURI, nil))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict)
}

func TestDockerCPRule_ExplicitDeny(t *testing.T) {
	rule := NewDockerCPRule(config.CheckDeny)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "GET", dockerCPURI, nil))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict)
}

// # DockerExecRule

func TestDockerExecRule_AbstainWrongShape(t *testing.T) {
	rule := NewDockerExecRule(config.CheckDeny)
	for _, tc := range []struct{ method, uri string }{
		{"GET", notAContainerURI},
		{"GET", dockerExecURI}, // wrong method for exec create
		{"POST", dockerCPURI},  // wrong endpoint
	} {
		d, err := rule.Evaluate(context.Background(), req("cn=alice", tc.method, tc.uri, nil))
		require.NoError(t, err)
		require.Equal(t, Abstain, d.Verdict, "method=%s uri=%s", tc.method, tc.uri)
	}
}

func TestDockerExecRule_ExplicitAllowDefault(t *testing.T) {
	rule := NewDockerExecRule(config.CheckAllow)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", dockerExecURI, nil))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict)
}

func TestDockerExecRule_ExplicitDeny(t *testing.T) {
	rule := NewDockerExecRule(config.CheckDeny)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", dockerExecURI, nil))
	require.NoError(t, err)
	require.Equal(t, Deny, d.Verdict)
}

// # NewBuiltinChain: real Rules end-to-end (not stubs)

// TestNewBuiltinChain_AdminBypassesEveryCheck is the end-to-end proof (via
// NewBuiltinChain's real Rules, not stubs) that an admin_users/admin_groups
// match short-circuits every one of the six built-in rules - including
// host_network/privileged/docker_cp/docker_exec, which have nothing to do
// with mounts and would otherwise deny outright under this test's
// checks.*: deny config.
func TestNewBuiltinChain_AdminBypassesEveryCheck(t *testing.T) {
	cfg := &config.Config{
		Checks: config.ChecksConfig{
			HostNetwork: config.CheckDeny,
			Privileged:  config.CheckDeny,
			DockerCP:    config.CheckDeny,
			DockerExec:  config.CheckDeny,
		},
		AdminUsers: []string{"alice"},
	}

	cases := []struct {
		name string
		req  func(t *testing.T) *dockerapi.AuthZReq
	}{
		{"host_network", func(t *testing.T) *dockerapi.AuthZReq {
			return req("cn=alice", "POST", containerCreateURI, hostConfigBody(t, map[string]any{"NetworkMode": "host"}))
		}},
		{"privileged", func(t *testing.T) *dockerapi.AuthZReq {
			return req("cn=alice", "POST", containerCreateURI, hostConfigBody(t, map[string]any{"Privileged": true}))
		}},
		{"docker_cp", func(t *testing.T) *dockerapi.AuthZReq {
			return req("cn=alice", "GET", dockerCPURI, nil)
		}},
		{"docker_exec", func(t *testing.T) *dockerapi.AuthZReq {
			return req("cn=alice", "POST", dockerExecURI, nil)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ds := adminDatasourceSet(t, []string{"alice"}, nil)
			chain, err := NewBuiltinChain(cfg, ds, nil)
			require.NoError(t, err)

			allowed, _, err := chain.Decide(context.Background(), tc.req(t))
			require.NoError(t, err)
			assert.True(t, allowed, "%s: admin match must bypass this check", tc.name)
		})
	}
}

// TestNewBuiltinChain_NonAdminStillDenied is TestNewBuiltinChain_
// AdminBypassesEveryCheck's control: the same checks.*: deny config denies
// a non-matching identity, proving the bypass above is admin_users-gated,
// not a change to the checks themselves.
func TestNewBuiltinChain_NonAdminStillDenied(t *testing.T) {
	cfg := &config.Config{
		Checks: config.ChecksConfig{
			DockerExec: config.CheckDeny,
		},
		AdminUsers: []string{"alice"},
	}
	ds := adminDatasourceSet(t, []string{"bob"}, nil)
	chain, err := NewBuiltinChain(cfg, ds, nil)
	require.NoError(t, err)

	allowed, _, err := chain.Decide(context.Background(), req("cn=bob", "POST", dockerExecURI, nil))
	require.NoError(t, err)
	assert.False(t, allowed, "non-admin must still be denied by checks.docker_exec")
}
