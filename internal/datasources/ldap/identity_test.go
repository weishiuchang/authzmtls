package ldap

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeSubjectDN(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// Captured from hands-on testing against a real dockerd + AD.
			name: "real-world pinned example",
			in:   "CN=jdoe,OU=Users,DC=example,DC=com",
			want: "DC=com,DC=example,OU=Users,CN=jdoe",
		},
		{
			// The escaped comma must not be mistaken for a component
			// boundary.
			name: "escaped comma inside an RDN value",
			in:   `CN=Smith\, John,OU=Users,DC=example,DC=com`,
			want: `DC=com,DC=example,OU=Users,CN=Smith\, John`,
		},
		{
			// One multi-valued RDN (RFC 2253 `+`) - must not be split at
			// the +.
			name: "multi-valued RDN",
			in:   "CN=John+OU=Sales,DC=example,DC=com",
			want: "DC=com,DC=example,CN=John+OU=Sales",
		},
		{
			name: "single component is a no-op",
			in:   "CN=jdoe",
			want: "CN=jdoe",
		},
		{
			name: "empty string is defined and non-panicking",
			in:   "",
			want: "",
		},
		{
			name: "leading comma",
			in:   ",CN=jdoe",
			want: "CN=jdoe,",
		},
		{
			name: "trailing comma",
			in:   "CN=jdoe,",
			want: ",CN=jdoe",
		},
		{
			name: "consecutive commas",
			in:   "CN=jdoe,,OU=Users",
			want: "OU=Users,,CN=jdoe",
		},
		{
			name: "dangling backslash at the very end of the string",
			in:   `CN=jdoe,OU=Users\`,
			want: `OU=Users\,CN=jdoe`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSubjectDN(tt.in)
			require.Equal(t, tt.want, got, "normalizeSubjectDN(%q)", tt.in)
		})
	}
}

func TestNormalizeSubjectDNNeverPanics(t *testing.T) {
	// Adversarial malformed-DN inputs, checked here purely for non-panic.
	adversarial := []string{
		",", ",,", ",,,", "\\", "\\,", ",\\", strings.Repeat(",", 100),
	}
	for _, s := range adversarial {
		func() {
			defer func() {
				if r := recover(); r != nil {
					assert.Failf(t, "normalizeSubjectDN panicked", "%q panicked: %v", s, r)
				}
			}()
			normalizeSubjectDN(s)
		}()
	}
}

// TestNormalizeThenEscapeOrderMatters proves why normalizeSubjectDN must
// run before escapeFilterValue: escaping first turns a comma-protecting
// backslash into "\5c", so splitOnUnescapedCommas then misreads the comma
// after it as a component boundary.
func TestNormalizeThenEscapeOrderMatters(t *testing.T) {
	const subject = `CN=Smith\, John,OU=Users,DC=example,DC=com`

	correctOrder := escapeFilterValue(normalizeSubjectDN(subject))
	wrongOrder := escapeFilterValue(subject) // escape first, then "reverse" (component-split) the escaped string
	wrongOrder = normalizeSubjectDN(wrongOrder)

	require.NotEqual(t, correctOrder, wrongOrder, "escape-then-reverse produced the same result as reverse-then-escape (%q) - order should matter", correctOrder)

	// Correct: the comma survives as part of one atomic component.
	const wantCorrect = `DC=com,DC=example,OU=Users,CN=Smith\5c, John`
	require.Equal(t, wantCorrect, correctOrder, "reverse-then-escape")

	// Wrong: " John" gets split out as its own component once "\5c" no
	// longer looks like an escape.
	assert.Contains(t, wrongOrder, ", John,CN=Smith\\5c", "expected escape-then-reverse to visibly corrupt the component boundary")
}

func TestEscapeFilterValue(t *testing.T) {
	// Every LDAP filter metacharacter (RFC 4515), plus NUL, must come back
	// backslash-hex-escaped.
	got := escapeFilterValue("a*b(c)d\\e\x00f")
	want := `a\2ab\28c\29d\5ce\00f`
	require.Equal(t, want, got, "escapeFilterValue")
}

func TestSubstituteFilterToken(t *testing.T) {
	template := "(&(objectClass=group)(member=$IDENTITY_DN))"

	// Filter-injection payload: raw concatenation would let `)(cn=*` close
	// and reopen a clause; escaped, it can't.
	got := substituteFilterToken(template, "$IDENTITY_DN", "*)(cn=*")
	require.False(t, strings.Contains(got, ")(cn=*)") || strings.Contains(got, "*)(cn="), "substituteFilterToken let a metacharacter break out of the filter: %q", got)

	want := `(&(objectClass=group)(member=\2a\29\28cn=\2a))`
	require.Equal(t, want, got, "substituteFilterToken")
}

// FuzzNormalizeSubjectDNInvolution exercises normalizeSubjectDN's defining
// property: reversing twice is the identity, over well-formed DNs.
// Fragments are sanitized before assembly so no raw commas or dangling
// backslashes leak in - that edge case is already covered separately by
// TestNormalizeSubjectDN and isn't round-trippable, so it's excluded here.
func FuzzNormalizeSubjectDNInvolution(f *testing.F) {
	f.Add("jdoe", "Users", "example", "com", false)
	f.Add("Smith, John", "Sales", "example", "org", true)
	f.Add("", "", "", "", false)
	f.Add("a+b", "c", "d", "e", true)

	f.Fuzz(func(t *testing.T, cnValue, ou, dc1, dc2 string, escapeCommaInCN bool) {
		clean := func(s string) string {
			s = strings.ReplaceAll(s, "\\", "")
			s = strings.ReplaceAll(s, ",", "")
			return s
		}
		cnValue, ou, dc1, dc2 = clean(cnValue), clean(ou), clean(dc1), clean(dc2)

		cn := "CN=" + cnValue
		if escapeCommaInCN {
			// Reintroduce one well-formed escaped comma, without risking a
			// dangling backslash.
			cn = `CN=` + cnValue + `\, trailing`
		}
		dn := strings.Join([]string{cn, "OU=" + ou, "DC=" + dc1, "DC=" + dc2}, ",")

		once := normalizeSubjectDN(dn)
		twice := normalizeSubjectDN(once)
		require.Equal(t, dn, twice, "normalizeSubjectDN not an involution for %q", dn)

		require.Equal(t, len(splitOnUnescapedCommas(dn)), len(splitOnUnescapedCommas(once)), "component count not preserved by one reversal of %q", dn)
	})
}
