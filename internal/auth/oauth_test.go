package auth

import (
	"encoding/json"
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

// An explicit false must stay distinguishable from an absent claim, which
// Entra ID omits: only false blocks the legacy email link.
func TestOAuthClaimsEmailVerified(t *testing.T) {
	tests := map[string]*bool{`{}`: nil, `{"email_verified":false}`: new(false), `{"email_verified":true}`: new(true)}
	for raw, want := range tests {
		var claims oauthClaims
		if err := json.Unmarshal([]byte(raw), &claims); err != nil {
			t.Fatal(err)
		}
		if (claims.EmailVerified == nil) != (want == nil) || (want != nil && *claims.EmailVerified != *want) {
			t.Errorf("%s: email_verified = %v, want %v", raw, claims.EmailVerified, want)
		}
	}
}
