package rules

import (
	"context"
	"fmt"

	"github.com/weishiuchang/authzmtls/internal/datasources"
	"github.com/weishiuchang/authzmtls/internal/dockerapi"
)

// AdminRule is the identity-aware global bypass: a request whose resolved
// $USER or $GROUP matches admin_users/admin_groups is allowed outright,
// before any other rule ever runs (see builtin.go - AdminRule is always
// first). Unlike every other built-in Rule, a match means *every* docker
// command is allowed, not just mounts - request shape is irrelevant.
type AdminRule struct {
	users  map[string]struct{}
	groups map[string]struct{}
	ds     *datasources.Set
}

// NewAdminRule builds an AdminRule from config.Config's admin_users/
// admin_groups. Both empty (the common case: this feature unused) makes
// Evaluate abstain immediately without ever calling ds - a deployment that
// doesn't configure admin_users/admin_groups pays no extra datasource cost
// for this rule's presence in the chain.
func NewAdminRule(users, groups []string, ds *datasources.Set) *AdminRule {
	return &AdminRule{users: toSet(users), groups: toSet(groups), ds: ds}
}

func toSet(vals []string) map[string]struct{} {
	set := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		set[v] = struct{}{}
	}
	return set
}

var _ Rule = (*AdminRule)(nil)

// Evaluate implements Rule. Unlike every other built-in Rule, it never
// abstains based on request shape - once admin_users/admin_groups are
// configured, every request's identity is resolved and checked, regardless
// of what that request is.
//
// Msg is a fixed, generic string, deliberately never the matched
// username/group value itself: that's datasource output, and Decision.Msg
// must stay request-derived-only (see decision.go's doc comment) since the
// dockerd<->authzmtls hop is unauthenticated. Detail (server-side-log-only)
// does name the match, for operator visibility at DEBUG.
func (r *AdminRule) Evaluate(ctx context.Context, req *dockerapi.AuthZReq) (Decision, error) {
	if len(r.users) == 0 && len(r.groups) == 0 {
		return abstain(), nil
	}

	resolved := resolveVars(ctx, req, r.ds)

	for _, u := range resolved["USER"] {
		if _, ok := r.users[u]; ok {
			return adminAllow(fmt.Sprintf("user %q matched admin_users", u)), nil
		}
	}
	for _, g := range resolved["GROUP"] {
		if _, ok := r.groups[g]; ok {
			return adminAllow(fmt.Sprintf("group %q matched admin_groups", g)), nil
		}
	}
	return abstain(), nil
}

// adminAllow builds the admin-bypass Decision: Detail names the specific
// match (safe, server-side-log-only) but Msg stays a fixed, generic string
// rather than reusing the allow() helper, which would put the same
// datasource-derived Detail text into Msg too.
func adminAllow(detail string) Decision {
	return Decision{Verdict: Allow, Detail: detail, Msg: "admin: all commands allowed"}
}
