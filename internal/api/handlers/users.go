package handlers

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api"
	"golang.org/x/crypto/bcrypt"
)

// UserResponse represents the user data returned by the API
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

// ListUsers returns a paginated list of users
func (h *Handlers) ListUsers(c *gin.Context) {
	limit, offset := api.GetPagination(c)

	// Build query with optional filters
	query := "SELECT id, username, full_name, email, role, suspended_at, last_login_at, login_count, password_changed_at, created_at, updated_at FROM users"
	countQuery := "SELECT COUNT(*) FROM users"
	args := []interface{}{}
	whereClauses := []string{}

	// Add soft delete filter (exclude suspended users by default)
	if c.Query("include_suspended") != "true" {
		whereClauses = append(whereClauses, "suspended_at IS NULL")
	}

	// Add role filter if provided
	if role := c.Query("role"); role != "" {
		whereClauses = append(whereClauses, "role = ?")
		args = append(args, role)
	}

	// Apply WHERE clauses
	if len(whereClauses) > 0 {
		whereClause := " WHERE " + strings.Join(whereClauses, " AND ")
		query += whereClause
		countQuery += whereClause
	}

	// Get total count
	var total int64
	if err := h.db.Get(&total, countQuery, args...); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count users"})
		return
	}

	// Get paginated data
	query += " ORDER BY username ASC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	var users []UserResponse
	if err := h.db.Select(&users, query, args...); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetUser returns a single user by ID
func (h *Handlers) GetUser(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	var user UserResponse
	query := "SELECT id, username, full_name, email, role, suspended_at, last_login_at, login_count, password_changed_at, created_at, updated_at FROM users WHERE id = ?"
	if err := h.db.Get(&user, query, id); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		}
		return
	}

	c.JSON(http.StatusOK, user)
}

// CreateUser creates a new user account
func (h *Handlers) CreateUser(c *gin.Context) {
	var req api.UserCreateRequest
	if !api.BindAndValidate(c, &req) {
		return
	}

	// Check username uniqueness
	if err := api.CheckUnique(h.db, "users", "username", req.Username, nil); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	// Check email uniqueness (if provided)
	if req.Email != nil && *req.Email != "" {
		if err := api.CheckUnique(h.db, "users", "email", *req.Email, nil); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
			return
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Create user
	_, err = h.db.ExecContext(c.Request.Context(),
		"INSERT INTO users (username, full_name, email, password_hash, role, metadata) VALUES (?, ?, ?, ?, ?, ?)",
		req.Username, req.FullName, req.Email, string(hashedPassword), req.Role, req.Metadata,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

// UpdateUser updates an existing user's information
func (h *Handlers) UpdateUser(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	var req api.UserUpdateRequest
	if !api.BindAndValidate(c, &req) {
		return
	}

	// Check if user exists
	if !api.ValidateResourceExists(c, h.db, "users", "User", id) {
		return
	}

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}

	if req.Username != "" {
		if err := api.CheckUnique(h.db, "users", "username", req.Username, &id); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
			return
		}
		updates = append(updates, "username = ?")
		args = append(args, req.Username)
	}

	if req.FullName != "" {
		updates = append(updates, "full_name = ?")
		args = append(args, req.FullName)
	}

	if req.Email != nil && *req.Email != "" {
		if err := api.CheckUnique(h.db, "users", "email", *req.Email, &id); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
			return
		}
		updates = append(updates, "email = ?")
		args = append(args, *req.Email)
	}

	if req.Role != "" {
		updates = append(updates, "role = ?")
		args = append(args, req.Role)
	}

	if req.Metadata != "" {
		updates = append(updates, "metadata = ?")
		args = append(args, req.Metadata)
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	// Execute update
	query := "UPDATE users SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	args = append(args, id)

	if _, err := h.db.ExecContext(c.Request.Context(), query, args...); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// SuspendUser suspends a user account
func (h *Handlers) SuspendUser(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	// Check if this would be the last admin
	var adminCount int
	if err := h.db.Get(&adminCount, "SELECT COUNT(*) FROM users WHERE role = 'admin' AND suspended_at IS NULL AND id != ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check admin count"})
		return
	}

	var userRole string
	if err := h.db.Get(&userRole, "SELECT role FROM users WHERE id = ?", id); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		}
		return
	}

	if userRole == "admin" && adminCount == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot suspend the last admin user"})
		return
	}

	// Suspend user and invalidate sessions
	_, err := h.db.ExecContext(c.Request.Context(), "UPDATE users SET suspended_at = NOW() WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to suspend user"})
		return
	}

	// Invalidate all sessions
	h.db.ExecContext(c.Request.Context(), "DELETE FROM user_sessions WHERE user_id = ?", id)

	c.JSON(http.StatusOK, gin.H{"message": "User suspended successfully"})
}

// RestoreUser restores a suspended user account
func (h *Handlers) RestoreUser(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	result, err := h.db.ExecContext(c.Request.Context(), "UPDATE users SET suspended_at = NULL WHERE id = ? AND suspended_at IS NOT NULL", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to restore user"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found or not suspended"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User restored successfully"})
}

// DeleteUser permanently deletes a user account
func (h *Handlers) DeleteUser(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	// Check if this would be the last admin
	var adminCount int
	if err := h.db.Get(&adminCount, "SELECT COUNT(*) FROM users WHERE role = 'admin' AND suspended_at IS NULL AND id != ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check admin count"})
		return
	}

	var userRole string
	if err := h.db.Get(&userRole, "SELECT role FROM users WHERE id = ?", id); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		}
		return
	}

	if userRole == "admin" && adminCount == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete the last admin user"})
		return
	}

	// Delete user and all sessions
	h.db.ExecContext(c.Request.Context(), "DELETE FROM user_sessions WHERE user_id = ?", id)

	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.Status(http.StatusNoContent)
}

// ChangePassword updates a user's password
func (h *Handlers) ChangePassword(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	var input struct {
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		return
	}

	// Check if user exists
	if !api.ValidateResourceExists(c, h.db, "users", "User", id) {
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update password
	_, err = h.db.ExecContext(c.Request.Context(),
		"UPDATE users SET password_hash = ?, password_changed_at = NOW() WHERE id = ?",
		string(hashedPassword), id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}