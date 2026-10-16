package auth

import "github.com/gin-gonic/gin"

// Context keys for storing user information in the gin context.
const (
	ctxKeyUserID   = "user_id"
	ctxKeyUserRole = "user_role"
)

// UserContext contains all user-related context data for type-safe access.
type UserContext struct {
	UserID int64
	Role   string
}

// SetUserContext stores user context data in a type-safe manner.
func SetUserContext(c *gin.Context, ctx UserContext) {
	c.Set(ctxKeyUserID, ctx.UserID)
	c.Set(ctxKeyUserRole, ctx.Role)
}

// UserID retrieves the user ID from context.
func UserID(c *gin.Context) (int64, bool) {
	val, _ := c.Get(ctxKeyUserID)
	return coerceInt64(val)
}

// UserRole retrieves the user role from context in a type-safe manner.
func UserRole(c *gin.Context) (string, bool) {
	val, _ := c.Get(ctxKeyUserRole)
	role, ok := val.(string)
	return role, ok
}
