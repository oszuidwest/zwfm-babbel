package auth

import "github.com/gin-gonic/gin"

// SessionStore defines the interface for session storage and retrieval.
// Implementations handle the underlying session storage mechanism (memory, redis, etc.).
type SessionStore interface {
	// Get retrieves a session for the given HTTP request context
	Get(c *gin.Context) Session
}

// Session defines the interface for session data operations.
// Provides a consistent API for session management regardless of storage backend.
type Session interface {
	// Get retrieves a value from the session by key
	Get(key string) any
	// Set stores a value in the session with the given key
	Set(key string, value any)
	// Delete removes a key-value pair from the session
	Delete(key string)
	// Clear removes all data from the session
	Clear()
	// Save persists the session changes to the storage backend
	Save(c *gin.Context) error
}
