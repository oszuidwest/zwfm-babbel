package auth

import "github.com/gin-gonic/gin"

// SessionStore interface for session management
type SessionStore interface {
	Get(c *gin.Context) Session
}

// Session interface for session operations
type Session interface {
	Get(key string) interface{}
	Set(key string, value interface{})
	Delete(key string)
	Clear()
	Save(c *gin.Context) error
}
