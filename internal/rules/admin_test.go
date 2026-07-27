package rules

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/weishiuchang/authzmtls/internal/datasources"
)

// adminDatasourceSet builds a *datasources.Set whose one provider resolves
// $USER/$GROUP to the given fixed values, regardless of vars - enough for
// AdminRule's tests, which only care about the resolved output.
func adminDatasourceSet(t *testing.T, users, groups []string) *datasources.Set {
	t.Helper()
	typeName := registerFakeProviderType(t, &fakeProvider{
		resolve: func(context.Context, map[string]string) (map[string][]string, error) {
			return map[string][]string{"USER": users, "GROUP": groups}, nil
		},
	})
	return newDatasourceSet(t, datasources.Config{Name: "test", Type: typeName})
}

func TestAdminRule_AbstainWhenUnconfigured(t *testing.T) {
	// A ds that fails the test if ever called, proving Evaluate returns
	// early without any datasource cost when admin_users/admin_groups are
	// both empty - the common case.
	typeName := registerFakeProviderType(t, &fakeProvider{
		resolve: func(context.Context, map[string]string) (map[string][]string, error) {
			require.Fail(t, "ds.Resolve must not be called when admin_users/admin_groups are both empty")
			return nil, nil
		},
	})
	ds := newDatasourceSet(t, datasources.Config{Name: "test", Type: typeName})

	rule := NewAdminRule(nil, nil, ds)
	d, err := rule.Evaluate(context.Background(), req("cn=alice", "GET", notAContainerURI, nil))
	require.NoError(t, err)
	assert.Equal(t, Abstain, d.Verdict)
}

func TestAdminRule_AllowsMatchedUser(t *testing.T) {
	ds := adminDatasourceSet(t, []string{"alice"}, nil)
	rule := NewAdminRule([]string{"alice"}, nil, ds)

	d, err := rule.Evaluate(context.Background(), req("cn=alice", "GET", notAContainerURI, nil))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict)
	assert.Contains(t, d.Detail, "alice", "Detail should name the matched user")
}

func TestAdminRule_AllowsMatchedGroup(t *testing.T) {
	ds := adminDatasourceSet(t, []string{"bob"}, []string{"ops"})
	rule := NewAdminRule(nil, []string{"ops"}, ds)

	d, err := rule.Evaluate(context.Background(), req("cn=bob", "GET", notAContainerURI, nil))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict)
	assert.Contains(t, d.Detail, "ops", "Detail should name the matched group")
}

func TestAdminRule_AbstainWhenNoMatch(t *testing.T) {
	ds := adminDatasourceSet(t, []string{"bob"}, []string{"eng"})
	rule := NewAdminRule([]string{"alice"}, []string{"ops"}, ds)

	d, err := rule.Evaluate(context.Background(), req("cn=bob", "GET", notAContainerURI, nil))
	require.NoError(t, err)
	assert.Equal(t, Abstain, d.Verdict, "no admin_users/admin_groups match - must defer to later rules, not decide anything itself")
}

// TestAdminRule_MsgNeverLeaksMatchedValue is the safety-critical assertion:
// Msg (what actually reaches dockerd, and thus anyone who can hit the
// unauthenticated dockerd<->authzmtls port) must never contain the matched
// username/group itself - that's datasource output, forbidden in Msg per
// decision.go. Only Detail (server-side-log-only) may name it.
func TestAdminRule_MsgNeverLeaksMatchedValue(t *testing.T) {
	const marker = "supersecret-admin-username-marker"
	ds := adminDatasourceSet(t, []string{marker}, nil)
	rule := NewAdminRule([]string{marker}, nil, ds)

	d, err := rule.Evaluate(context.Background(), req("cn=x", "GET", notAContainerURI, nil))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict)
	assert.NotContains(t, d.Msg, marker, "matched username leaked into Msg")
	assert.Contains(t, d.Detail, marker, "expected the match to at least be visible server-side in Detail")
}

// TestAdminRule_BypassesEveryOtherRule proves the actual design goal at the
// Chain level: an admin match short-circuits before a rule that would
// otherwise deny, since Chain.Evaluate is first-non-abstain-wins and
// AdminRule is meant to run first (see NewBuiltinChain in decision.go).
func TestAdminRule_BypassesEveryOtherRule(t *testing.T) {
	ds := adminDatasourceSet(t, []string{"alice"}, nil)
	adminRule := NewAdminRule([]string{"alice"}, nil, ds)
	wouldDeny := stubRule{decision: deny("would have denied everything")}

	chain, err := NewChain(nil, adminRule, wouldDeny)
	require.NoError(t, err)

	d, err := chain.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict, "admin match must win over a later rule's deny")
}

// TestMultiDatasource_AdminInOnlyOneSourceStillBypassesEverything confirms
// claim 3 of the multi-datasource design goal: admin_groups matching a
// group from just one of several configured datasources is enough to grant
// the bypass - AdminRule checks the union across all datasources (via
// twoProviderSet, defined in mounts_test.go), same as MountAllowlistRule
// does (see TestMultiDatasource_* there for claims 1 and 2).
func TestMultiDatasource_AdminInOnlyOneSourceStillBypassesEverything(t *testing.T) {
	ds := twoProviderSet(t,
		map[string][]string{"USER": {"alice"}, "GROUP": {"ops"}},        // admin in datasource a
		map[string][]string{"USER": {"alice2"}, "GROUP": {"engineers"}}, // not admin in datasource b
	)
	rule := NewAdminRule(nil, []string{"ops"}, ds)

	d, err := rule.Evaluate(context.Background(), req("cn=alice", "POST", containerCreateURI, nil))
	require.NoError(t, err)
	require.Equal(t, Allow, d.Verdict, "detail=%q", d.Detail)
	assert.Contains(t, d.Detail, "ops")
}
