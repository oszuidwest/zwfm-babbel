package auth

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Session keys for storing authentication data in sessions.
const (
	// sessKeyUserID stores the authenticated user's ID.
	sessKeyUserID = "user_id"
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
