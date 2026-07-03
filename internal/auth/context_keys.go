package auth

import "github.com/gin-gonic/gin"

// ContextKey is a typed key for context values.
type ContextKey string

// Context keys for storing user information in request context.
const (
	// CtxKeyUserID is the context key for authenticated user ID.
	CtxKeyUserID ContextKey = "user_id"
	// CtxKeyUserRole is the context key for authenticated user's role.
	CtxKeyUserRole ContextKey = "user_role"
)

// UserContext contains all user-related context data for type-safe access.
type UserContext struct {
	UserID int64
	Role   string
}

// SetUserContext stores user context data in a type-safe manner.
func SetUserContext(c *gin.Context, ctx UserContext) {
	c.Set(string(CtxKeyUserID), ctx.UserID)
	c.Set(string(CtxKeyUserRole), ctx.Role)
}

// UserID retrieves the user ID from context.
func UserID(c *gin.Context) (int64, bool) {
	val, exists := c.Get(string(CtxKeyUserID))
	if !exists {
		return 0, false
	}
	return coerceInt64(val)
}

// UserRole retrieves the user role from context in a type-safe manner.
func UserRole(c *gin.Context) (string, bool) {
	val, exists := c.Get(string(CtxKeyUserRole))
	if !exists {
		return "", false
	}
	if s, ok := val.(string); ok {
		return s, true
	}
	return "", false
}
