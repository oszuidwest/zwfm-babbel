package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestOAuthIdentityRejectsInvalidSubjectOrIssuer(t *testing.T) {
	// A nil DB ensures validation precedes database access.
	s := &Service{}
	for name, identity := range map[string]oauthIdentity{
		"missing sub":      {Issuer: "https://issuer.example"},
		"oversized sub":    {Issuer: "https://issuer.example", Subject: strings.Repeat("s", 256)},
		"oversized issuer": {Issuer: strings.Repeat("i", 513), Subject: "sub"},
	} {
		if _, err := s.findOrCreateOAuthUser(t.Context(), identity); !errors.Is(err, ErrLoginRejected) {
			t.Errorf("%s: error = %v, want ErrLoginRejected", name, err)
		}
	}
}

func TestOAuthClaimsEmailMayLink(t *testing.T) {
	tests := map[string]bool{
		`{"email":"a@b.nl"}`:                          true,
		`{"email":"a@b.nl","email_verified":true}`:    true,
		`{"email":"a@b.nl","email_verified":"true"}`:  true,
		`{"email":"a@b.nl","email_verified":false}`:   false,
		`{"email":"a@b.nl","email_verified":"false"}`: false,
		`{"email":"a@b.nl","email_verified":"maybe"}`: false,
		`{"email":"","email_verified":true}`:          false,
	}
	for raw, want := range tests {
		var claims oauthClaims
		if err := json.Unmarshal([]byte(raw), &claims); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := claims.emailMayLink(); got != want {
			t.Errorf("%s: emailMayLink = %t, want %t", raw, got, want)
		}
	}
}

func TestSanitizeUsername(t *testing.T) {
	tests := map[string]string{
		"john.doe@example.com":   "john_doe",
		"ab@example.com":         "ab_example",
		"plain-name":             "plain-name",
		"":                       "oidc_user",
		strings.Repeat("x", 150): strings.Repeat("x", 100),
	}
	for input, want := range tests {
		if got := sanitizeUsername(input); got != want {
			t.Errorf("sanitizeUsername(%q) = %q, want %q", input, got, want)
		}
	}
	if got := oauthUsernameSuffix(strings.Repeat("x", 100), "abcdefgh"); len(got) != 100 || !strings.HasSuffix(got, "_abcdefgh") {
		t.Errorf("oauthUsernameSuffix = %q (%d chars), want 100 chars ending in _abcdefgh", got, len(got))
	}
}

func TestIsOAuthConflict(t *testing.T) {
	tests := map[error]bool{
		&mysql.MySQLError{Number: 1062}:                           true,
		&mysql.MySQLError{Number: 1213}:                           true,
		fmt.Errorf("insert: %w", &mysql.MySQLError{Number: 1062}): true,
		&mysql.MySQLError{Number: 1054}:                           false,
		errors.New("connection refused"):                          false,
	}
	for err, want := range tests {
		if got := isOAuthConflict(err); got != want {
			t.Errorf("isOAuthConflict(%v) = %t, want %t", err, got, want)
		}
	}
}
