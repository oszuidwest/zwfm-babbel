package auth

// ContextKey is a typed key for context values
type ContextKey string

// Context keys for storing user information in request context.
const (
	// CtxKeyUserID is the context key for authenticated user ID
	CtxKeyUserID ContextKey = "user_id"
	// CtxKeyUsername is the context key for authenticated username
	CtxKeyUsername ContextKey = "username"
	// CtxKeyUserRole is the context key for authenticated user's role
	CtxKeyUserRole ContextKey = "user_role"
)
