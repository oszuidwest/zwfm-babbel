package auth

// SessionKey is a typed key for session values to prevent typos and enable refactoring.
type SessionKey string

// Session keys for storing authentication data in sessions.
const (
	// SessKeyUserID stores the authenticated user's ID.
	SessKeyUserID SessionKey = "user_id"
	// SessKeyOAuthState stores the OAuth CSRF state token.
	SessKeyOAuthState SessionKey = "oauth_state"
	// SessKeyFrontendURL stores the frontend URL for OAuth redirects.
	SessKeyFrontendURL SessionKey = "frontend_url"
)

// SessionUserID retrieves the user ID from session.
func SessionUserID(session Session) (int64, bool) {
	return coerceInt64(session.Get(string(SessKeyUserID)))
}

func sessionString(session Session, key SessionKey) (string, bool) {
	s, ok := session.Get(string(key)).(string)
	return s, ok
}

// SessionFrontendURL retrieves the frontend URL from session.
func SessionFrontendURL(session Session) (string, bool) {
	return sessionString(session, SessKeyFrontendURL)
}

// ClearSessionOAuth clears OAuth-specific session data after callback.
func ClearSessionOAuth(session Session) {
	session.Delete(string(SessKeyOAuthState))
	session.Delete(string(SessKeyFrontendURL))
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
