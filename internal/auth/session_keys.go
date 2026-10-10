package auth

import "github.com/gin-contrib/sessions"

// Session keys for storing authentication data in sessions.
const (
	// SessKeyUserID stores the authenticated user's ID.
	SessKeyUserID = "user_id"
	// SessKeyOAuthState stores the OAuth CSRF state token.
	SessKeyOAuthState = "oauth_state"
	// SessKeyFrontendURL stores the frontend URL for OAuth redirects.
	SessKeyFrontendURL = "frontend_url"
)

// SessionUserID retrieves the user ID from session.
func SessionUserID(session sessions.Session) (int64, bool) {
	return coerceInt64(session.Get(SessKeyUserID))
}

// SessionFrontendURL retrieves the frontend URL from session, or "" if unset.
func SessionFrontendURL(session sessions.Session) string {
	s, _ := session.Get(SessKeyFrontendURL).(string)
	return s
}

// ClearSessionOAuth clears OAuth-specific session data after callback.
func ClearSessionOAuth(session sessions.Session) {
	session.Delete(SessKeyOAuthState)
	session.Delete(SessKeyFrontendURL)
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
