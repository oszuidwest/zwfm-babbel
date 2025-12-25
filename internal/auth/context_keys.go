package auth

// ContextKey is a typed key for context values
type ContextKey string

const (
	CtxKeyUserID   ContextKey = "user_id"
	CtxKeyUsername ContextKey = "username"
	CtxKeyUserRole ContextKey = "user_role"
)
