package handlers

import (
	"database/sql"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/responses"
	"golang.org/x/crypto/bcrypt"
)

// UserInput represents the input for creating a new user.
type UserInput struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	FullName string `json:"full_name" binding:"required"`
	Email    string `json:"email" binding:"omitempty,email"`
	Password string `json:"password" binding:"required,min=8"`
	Role     string `json:"role" binding:"required,oneof=admin editor viewer"`
}

// UserUpdateInput represents the input for updating a user.
type UserUpdateInput struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	FullName string `json:"full_name" binding:"required"`
	Email    string `json:"email" binding:"omitempty,email"`
	Role     string `json:"role" binding:"required,oneof=admin editor viewer"`
}

// UserResponse represents the user data returned by the API.
type UserResponse struct {
	ID                int        `json:"id" db:"id"`
	Username          string     `json:"username" db:"username"`
	FullName          string     `json:"full_name" db:"full_name"`
	Email             string     `json:"email" db:"email"`
	Role              string     `json:"role" db:"role"`
	SuspendedAt       *time.Time `json:"suspended_at" db:"suspended_at"`
	LastLoginAt       *time.Time `json:"last_login_at" db:"last_login_at"`
	LoginCount        int        `json:"login_count" db:"login_count"`
	PasswordChangedAt time.Time  `json:"password_changed_at" db:"password_changed_at"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

// ListUsers returns a paginated list of users.
func (h *Handlers) ListUsers(c *gin.Context) {
	crud := NewCRUDHandler(
		h.db,
		"users",
		WithOrderBy("username ASC"),
		WithSelectColumns("id, username, full_name, email, role, suspended_at, last_login_at, login_count, password_changed_at, created_at, updated_at"),
		WithSoftDelete("suspended_at"),
	)

	var users []UserResponse
	filters := map[string]string{
		"role": "role",
	}

	total, err := crud.List(c, &users, filters)
	if err != nil {
		responses.InternalServerError(c, err.Error())
		return
	}

	limit, offset := extractPaginationParams(c)
	responses.Paginated(c, users, total, limit, offset)
}

// GetUser returns a single user by ID.
func (h *Handlers) GetUser(c *gin.Context) {
	id, ok := validateAndGetIDParam(c, "user")
	if !ok {
		return
	}

	var user UserResponse
	err := h.db.Get(&user,
		"SELECT id, username, full_name, email, role, suspended_at, last_login_at, login_count, password_changed_at, created_at, updated_at FROM users WHERE id = ?",
		id,
	)
	if err == sql.ErrNoRows {
		responses.NotFound(c, "User not found")
		return
	}
	if err != nil {
		responses.InternalServerError(c, "Failed to fetch user")
		return
	}

	responses.Success(c, user)
}

// CreateUser creates a new user account.
func (h *Handlers) CreateUser(c *gin.Context) {
	var input UserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		responses.BadRequest(c, "Invalid request body")
		return
	}

	// Check if username already exists
	var exists bool
	if err := h.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", input.Username); err == nil && exists {
		responses.BadRequest(c, "Username already exists")
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		responses.InternalServerError(c, "Failed to hash password")
		return
	}

	// Create user
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO users (username, full_name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
		input.Username, input.FullName, input.Email, string(hashedPassword), input.Role,
	)
	if err != nil {
		responses.InternalServerError(c, "Failed to create user")
		return
	}

	userID, err := result.LastInsertId()
	if err != nil {
		responses.InternalServerError(c, "Failed to get user ID")
		return
	}

	// Fetch created user (without password)
	var user UserResponse
	h.fetchAndRespond(c,
		"SELECT id, username, full_name, email, role, suspended_at, last_login_at, login_count, password_changed_at, created_at, updated_at FROM users WHERE id = ?",
		userID, &user, true)
}

// UpdateUser updates an existing user's information.
func (h *Handlers) UpdateUser(c *gin.Context) {
	id, ok := validateAndGetIDParam(c, "user")
	if !ok {
		return
	}

	var input UserUpdateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		responses.BadRequest(c, "Invalid request body")
		return
	}

	// Check if user exists
	if !h.validateRecordExists(c, "users", "User", id) {
		return
	}

	// Check if new username conflicts
	var exists bool
	if err := h.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND id != ?)", input.Username, id); err == nil && exists {
		responses.BadRequest(c, "Username already exists")
		return
	}

	// Use query builder for dynamic updates
	qb := NewQueryBuilder()
	qb.AddUpdate("username", input.Username)
	qb.AddUpdate("full_name", input.FullName)
	qb.AddUpdate("email", input.Email)
	qb.AddUpdate("role", input.Role)

	if qb.HasUpdates() {
		query, args := qb.BuildUpdateQuery("users", id)
		if _, err := h.db.ExecContext(c.Request.Context(), query, args...); err != nil {
			responses.InternalServerError(c, "Failed to update user")
			return
		}
	}

	// Fetch updated user
	var user UserResponse
	h.fetchAndRespond(c,
		"SELECT id, username, full_name, email, role, suspended_at, last_login_at, login_count, password_changed_at, created_at, updated_at FROM users WHERE id = ?",
		id, &user, false)
}

// UpdateUserState handles user state changes (suspend/restore) via PATCH - RESTful approach
func (h *Handlers) UpdateUserState(c *gin.Context) {
	id, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid user ID")
		return
	}

	var req struct {
		SuspendedAt *string `json:"suspended_at"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		responses.BadRequest(c, "Invalid request body")
		return
	}

	if req.SuspendedAt == nil {
		responses.BadRequest(c, "suspended_at field is required")
		return
	}

	// null or empty string = restore, any other value = suspend
	if *req.SuspendedAt == "" || *req.SuspendedAt == "null" {
		h.performRestore(c, id)
	} else {
		h.performSuspend(c, id)
	}
}

// Helper to perform suspend action (extracted from SuspendUser)
func (h *Handlers) performSuspend(c *gin.Context, id int) {
	// Prevent suspending the last admin
	var adminCount int
	if err := h.db.Get(&adminCount, "SELECT COUNT(*) FROM users WHERE role = 'admin' AND suspended_at IS NULL AND id != ?", id); err != nil {
		responses.InternalServerError(c, "Failed to check admin count")
		return
	}

	var userRole string
	var suspended bool
	if err := h.db.Get(&userRole, "SELECT role FROM users WHERE id = ?", id); err == sql.ErrNoRows {
		responses.NotFound(c, "User not found")
		return
	} else if err != nil {
		responses.InternalServerError(c, "Failed to fetch user")
		return
	}

	if err := h.db.Get(&suspended, "SELECT suspended_at IS NOT NULL FROM users WHERE id = ?", id); err != nil {
		responses.InternalServerError(c, "Failed to check suspension status")
		return
	}

	if suspended {
		responses.BadRequest(c, "User is already suspended")
		return
	}

	if userRole == "admin" && adminCount == 0 {
		responses.BadRequest(c, "Cannot suspend the last admin user")
		return
	}

	// Invalidate all sessions for this user
	if _, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM user_sessions WHERE user_id = ?", id); err != nil {
		responses.InternalServerError(c, "Failed to invalidate user sessions")
		return
	}

	crud := NewCRUDHandler(h.db, "users", WithSoftDelete("suspended_at"))
	crud.SoftDelete(c, id)
}

// Helper to perform restore action
func (h *Handlers) performRestore(c *gin.Context, id int) {
	crud := NewCRUDHandler(h.db, "users", WithSoftDelete("suspended_at"))
	crud.Restore(c, id)
}

// DeleteUser permanently deletes a user account
func (h *Handlers) DeleteUser(c *gin.Context) {
	id, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid user ID")
		return
	}

	// Prevent deleting the last admin using DRY helper
	isLastAdmin, shouldReturn := h.isLastAdmin(c, id)
	if shouldReturn {
		return
	}
	if isLastAdmin {
		responses.BadRequest(c, "Cannot delete the last admin user")
		return
	}

	// Delete all sessions for this user
	if _, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM user_sessions WHERE user_id = ?", id); err != nil {
		responses.InternalServerError(c, "Failed to delete user sessions")
		return
	}

	// Permanently delete the user
	if _, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM users WHERE id = ?", id); err != nil {
		handleDatabaseError(c, err, "delete")
		return
	}

	responses.NoContent(c)
}

// ChangePassword updates a user's password.
func (h *Handlers) ChangePassword(c *gin.Context) {
	id, ok := validateAndGetIDParam(c, "user")
	if !ok {
		return
	}

	var input struct {
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		responses.BadRequest(c, "Invalid request body")
		return
	}

	// Check if user exists
	if !h.validateRecordExists(c, "users", "User", id) {
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		responses.InternalServerError(c, "Failed to hash password")
		return
	}

	// Update password
	if _, err := h.db.ExecContext(c.Request.Context(),
		"UPDATE users SET password_hash = ?, password_changed_at = NOW() WHERE id = ?",
		string(hashedPassword), id,
	); err != nil {
		responses.InternalServerError(c, "Failed to update password")
		return
	}

	responses.Success(c, gin.H{"message": "Password updated successfully"})
}
