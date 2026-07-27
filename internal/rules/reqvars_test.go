package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/weishiuchang/authzmtls/internal/dockerapi"
)

// fakeExtractor proves Extract unions every registered extractor's output
// rather than being hardcoded to IDENTITY.
func fakeExtractor(req *dockerapi.AuthZReq) (name, value string, ok bool) {
	if req.UserAuthNMethod == "" {
		return "FAKE", "", false
	}
	return "FAKE", req.UserAuthNMethod, true
}

func init() {
	Register(fakeExtractor)
}

func TestExtract_IdentitySet(t *testing.T) {
	req := &dockerapi.AuthZReq{User: "CN=alice,OU=eng,DC=example,DC=com"}

	got := Extract(req)

	want := map[string]string{"IDENTITY": "CN=alice,OU=eng,DC=example,DC=com"}
	assert.Equal(t, want, got)
}

func TestExtract_IdentityEmpty(t *testing.T) {
	req := &dockerapi.AuthZReq{}

	got := Extract(req)

	assert.Empty(t, got, "want empty map")
}

func TestExtract_UnionsAllExtractors(t *testing.T) {
	req := &dockerapi.AuthZReq{
		User:            "CN=bob,DC=example,DC=com",
		UserAuthNMethod: "TLS",
	}

	got := Extract(req)

	want := map[string]string{
		"IDENTITY": "CN=bob,DC=example,DC=com",
		"FAKE":     "TLS",
	}
	assert.Equal(t, want, got)
}

func TestExtract_OneExtractorNotOkDoesNotSuppressOthers(t *testing.T) {
	// UserAuthNMethod empty (FAKE returns ok=false) must not suppress IDENTITY.
	req := &dockerapi.AuthZReq{User: "CN=carol,DC=example,DC=com"}

	got := Extract(req)

	want := map[string]string{"IDENTITY": "CN=carol,DC=example,DC=com"}
	assert.Equal(t, want, got)
}
