package rules

import "github.com/weishiuchang/authzmtls/internal/dockerapi"

// This file extracts request-derived variables (today, exactly one:
// $IDENTITY, the client certificate's Subject DN) from an already-decoded
// AuthZReq, for resolveVars (mounts.go) to resolve against the configured
// datasources. Extractors are pure functions of AuthZReq - no I/O, no
// blocking, and deliberately no sanitization (that happens once,
// downstream, in internal/datasources' Set.Resolve).

// Extractor pulls a single named, request-derived variable off an
// already-decoded AuthZReq. ok = false means there was nothing to extract
// for this request, not an error - extractors never fail.
//
// Extractors must be pure and non-blocking: no I/O, no locks, no
// ctx/deadline. Anything calling out to a backend belongs behind a
// datasources.Provider instead.
//
// Extract returns whatever's on the request verbatim - sanitization
// happens downstream, in internal/datasources' Set.Resolve, not here.
type Extractor func(req *dockerapi.AuthZReq) (name, value string, ok bool)

// registry holds every self-registered Extractor. Order doesn't matter -
// names are unique by convention.
var registry []Extractor

// Register adds e to the set of extractors Extract runs. Intended to be
// called from a variable's own init(), the same self-registration pattern
// as internal/datasources' Register.
func Register(e Extractor) {
	registry = append(registry, e)
}

// Extract runs every registered Extractor against req, collecting
// {name: value} for every one that returned ok.
func Extract(req *dockerapi.AuthZReq) map[string]string {
	vars := make(map[string]string)
	for _, e := range registry {
		if name, value, ok := e(req); ok {
			vars[name] = value
		}
	}
	return vars
}

// IdentityVar is the variable name $IDENTITY expands to via Extract.
const IdentityVar = "IDENTITY"

func init() {
	Register(extractIdentity)
}

// extractIdentity is the $IDENTITY extractor: AuthZReq.User verbatim,
// unprocessed. ok is false when User is empty.
func extractIdentity(req *dockerapi.AuthZReq) (name, value string, ok bool) {
	return IdentityVar, req.User, req.User != ""
}
