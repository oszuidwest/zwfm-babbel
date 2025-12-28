// Package auth provides authentication and authorization services.
package auth

// SessionKey is a typed key for session values to prevent typos and enable refactoring.
type SessionKey string

// Session keys for storing authentication data in sessions.
const (
	// SessKeyUserID stores the authenticated user's ID
	SessKeyUserID SessionKey = "user_id"
	// SessKeyUsername stores the authenticated user's username
	SessKeyUsername SessionKey = "username"
	// SessKeyRole stores the authenticated user's role
	SessKeyRole SessionKey = "role"
	// SessKeyAuthMethod stores the authentication method used (local/oidc)
	SessKeyAuthMethod SessionKey = "auth_method"
	// SessKeyOAuthState stores the OAuth CSRF state token
	SessKeyOAuthState SessionKey = "oauth_state"
	// SessKeyFrontendURL stores the frontend URL for OAuth redirects
	SessKeyFrontendURL SessionKey = "frontend_url"
)

// SessionData contains all authentication-related session data.
type SessionData struct {
	UserID     int64
	Username   string
	Role       string
	AuthMethod string
}

// SetSessionAuth stores authentication data in the session type-safely.
func SetSessionAuth(session Session, data SessionData) {
	session.Set(string(SessKeyUserID), data.UserID)
	session.Set(string(SessKeyUsername), data.Username)
	session.Set(string(SessKeyRole), data.Role)
	session.Set(string(SessKeyAuthMethod), data.AuthMethod)
}

// SessionUserID retrieves the user ID from session.
func SessionUserID(session Session) (int64, bool) {
	val := session.Get(string(SessKeyUserID))
	if val == nil {
		return 0, false
	}
	switch v := val.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	default:
		return 0, false
	}
}

// SessionString retrieves a string value from session by key.
func SessionString(session Session, key SessionKey) (string, bool) {
	val := session.Get(string(key))
	if val == nil {
		return "", false
	}
	if s, ok := val.(string); ok {
		return s, true
	}
	return "", false
}

// SessionOAuthState retrieves the OAuth state token from session.
func SessionOAuthState(session Session) (string, bool) {
	return SessionString(session, SessKeyOAuthState)
}

// SessionFrontendURL retrieves the frontend URL from session.
func SessionFrontendURL(session Session) (string, bool) {
	return SessionString(session, SessKeyFrontendURL)
}

// SetSessionOAuthState stores the OAuth state token in session.
func SetSessionOAuthState(session Session, state string) {
	session.Set(string(SessKeyOAuthState), state)
}

// SetSessionFrontendURL stores the frontend URL in session.
func SetSessionFrontendURL(session Session, url string) {
	session.Set(string(SessKeyFrontendURL), url)
}

// ClearSessionOAuth clears OAuth-specific session data after callback.
func ClearSessionOAuth(session Session) {
	session.Delete(string(SessKeyOAuthState))
	session.Delete(string(SessKeyFrontendURL))
}
