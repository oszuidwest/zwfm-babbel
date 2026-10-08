package auth

import (
	"strings"
	"testing"
)

func TestOAuthIdentityRequiresSubject(t *testing.T) {
	s := &Service{}
	_, err := s.findOrCreateOAuthUser(t.Context(), oauthIdentity{Issuer: "https://issuer.example"})
	if err == nil || !strings.Contains(err.Error(), "missing sub") {
		t.Fatalf("error = %v, want missing sub", err)
	}
}
