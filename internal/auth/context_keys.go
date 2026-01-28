package auth

import "github.com/gin-gonic/gin"

// ContextKey is a typed key for context values.
type ContextKey string

// Context keys for storing user information in request context.
const (
	// CtxKeyUserID is the context key for authenticated user ID.
	CtxKeyUserID ContextKey = "user_id"
	// CtxKeyUsername is the context key for authenticated username.
	CtxKeyUsername ContextKey = "username"
	// CtxKeyUserRole is the context key for authenticated user's role.
	CtxKeyUserRole ContextKey = "user_role"
	// CtxKeyAuthMethod is the context key for authentication method used.
	CtxKeyAuthMethod ContextKey = "auth_method"
)

// UserContext contains all user-related context data for type-safe access.
type UserContext struct {
	UserID     int64
	Username   string
	Role       string
	AuthMethod string
}

// SetUserContext stores user context data in a type-safe manner.
func SetUserContext(c *gin.Context, ctx UserContext) {
	c.Set(string(CtxKeyUserID), ctx.UserID)
	c.Set(string(CtxKeyUsername), ctx.Username)
	c.Set(string(CtxKeyUserRole), ctx.Role)
	c.Set(string(CtxKeyAuthMethod), ctx.AuthMethod)
}

// UserID retrieves the user ID from context.
func UserID(c *gin.Context) (int64, bool) {
	return getContextInt64(c, CtxKeyUserID)
}

// UserRole retrieves the user role from context in a type-safe manner.
func UserRole(c *gin.Context) (string, bool) {
	return getContextString(c, CtxKeyUserRole)
}

// getContextInt64 safely retrieves an int64 from context, handling int/int64 variants.
func getContextInt64(c *gin.Context, key ContextKey) (int64, bool) {
	val, exists := c.Get(string(key))
	if !exists {
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

// getContextString safely retrieves a string from context.
func getContextString(c *gin.Context, key ContextKey) (string, bool) {
	val, exists := c.Get(string(key))
	if !exists {
		return "", false
	}
	if s, ok := val.(string); ok {
		return s, true
	}
	return "", false
}
