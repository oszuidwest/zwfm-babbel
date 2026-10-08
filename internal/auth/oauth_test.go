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

func TestOAuthEmailVerificationClaims(t *testing.T) {
	tests := []struct {
		name, claimsJSON string
		verified         bool
	}{
		{name: "absent", claimsJSON: `{ "email": "user@example.com" }`},
		{name: "false", claimsJSON: `{ "email_verified": false }`},
		{name: "true", claimsJSON: `{ "email_verified": true }`, verified: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var claims oauthClaims
			if err := json.Unmarshal([]byte(tt.claimsJSON), &claims); err != nil {
				t.Fatal(err)
			}
			if claims.EmailVerified != tt.verified {
				t.Fatalf("verified = %t, want %t", claims.EmailVerified, tt.verified)
			}
		})
	}
}
