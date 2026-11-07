package auth

import (
	"crypto/sha256"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Session keys for storing authentication data in sessions.
const (
	// sessKeyUserID stores the authenticated user's ID.
	sessKeyUserID = "user_id"
	// sessKeyPasswordFingerprint stores the passwordFingerprint the login saw.
	sessKeyPasswordFingerprint = "password_fingerprint"
	// sessKeyOAuthState stores the OAuth CSRF state token.
	sessKeyOAuthState = "oauth_state"
	// sessKeyFrontendURL stores the frontend URL for OAuth redirects.
	sessKeyFrontendURL = "frontend_url"
)

// SessionFrontendURL returns the frontend URL saved by StartOAuthFlow, or "".
func SessionFrontendURL(c *gin.Context) string {
	s, _ := sessions.Default(c).Get(sessKeyFrontendURL).(string)
	return s
}

// passwordFingerprint identifies a stored password hash without keeping it in
// the session. bcrypt salts make every password change give a new hash.
func passwordFingerprint(passwordHash string) string {
	sum := sha256.Sum256([]byte(passwordHash))
	return string(sum[:])
}

// coerceInt64 converts a session or context value to int64, handling the
// int/int64 variants produced by different storage backends.
func coerceInt64(val any) (int64, bool) {
	switch v := val.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	default:
		return 0, false
	}
}
