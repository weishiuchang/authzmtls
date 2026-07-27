package ldap

import (
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// normalizeSubjectDN reverses a Subject DN's RDN order: AD's
// altSecurityIdentities mapping expects the opposite order Go's
// pkix.Name.String() produces.
//
//	in:  CN=jdoe,OU=Users,DC=example,DC=com
//	out: DC=com,DC=example,OU=Users,CN=jdoe
//
// Splitting on raw commas is wrong per RFC 2253: an escaped comma
// (CN=Smith\, John) and a `+`-joined multi-valued RDN must each move as one
// atomic unit - see splitOnUnescapedCommas. This must run before
// escapeFilterValue: it needs logical RDN components, which escaping's
// punctuation rewrite destroys (see TestNormalizeThenEscapeOrderMatters).
func normalizeSubjectDN(subject string) string {
	parts := splitOnUnescapedCommas(subject)
	reversed := make([]string, len(parts))
	for i, part := range parts {
		reversed[len(parts)-1-i] = part
	}
	return strings.Join(reversed, ",")
}

// splitOnUnescapedCommas splits s on every non-backslash-escaped comma
// (RFC 2253). Malformed input is never rejected - there's no well-defined
// "correct" reversal of a malformed DN, so it just returns whatever a
// left-to-right scan produces, non-panicking.
func splitOnUnescapedCommas(s string) []string {
	parts := make([]string, 0, strings.Count(s, ",")+1)
	var current strings.Builder
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			// Backslash-escaped char taken literally, so an escaped comma
			// isn't mistaken for a boundary.
			current.WriteByte(c)
			escaped = false
		case c == '\\':
			current.WriteByte(c)
			escaped = true
		case c == ',':
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	// A dangling trailing backslash was already written literally above;
	// nothing more to do.
	parts = append(parts, current.String())
	return parts
}

// escapeFilterValue RFC 4515-escapes a raw value for LDAP filter
// substitution, delegating to go-ldap's EscapeFilter. Named and tested here
// in its own right since every filter substitution must go through it.
func escapeFilterValue(value string) string {
	return goldap.EscapeFilter(value)
}

// substituteFilterToken replaces token in template with rawValue,
// RFC 4515-escaping rawValue immediately before substitution so a filter
// metacharacter can never change the filter's structure.
//
// $IDENTITY never flows through this function - it's normalized and
// escaped exactly once, centrally, in ldap.go's Resolve, so a second pass
// here would double-escape it.
func substituteFilterToken(template, token, rawValue string) string {
	return strings.ReplaceAll(template, token, escapeFilterValue(rawValue))
}
