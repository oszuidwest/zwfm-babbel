// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"database/sql"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"golang.org/x/crypto/bcrypt"
)

// UserResponse represents the user data returned by the API
type UserResponse struct {
	ID                  int        `json:"id" db:"id"`
	Username            string     `json:"username" db:"username"`
	FullName            *string    `json:"full_name" db:"full_name"`
	Email               *string    `json:"email" db:"email"`
	Role                string     `json:"role" db:"role"`
	SuspendedAt         *time.Time `json:"suspended_at" db:"suspended_at"`
	LastLoginAt         *time.Time `json:"last_login_at" db:"last_login_at"`
	LoginCount          int        `json:"login_count" db:"login_count"`
	FailedLoginAttempts int        `json:"failed_login_attempts" db:"failed_login_attempts"`
	LockedUntil         *time.Time `json:"locked_until" db:"locked_until"`
	PasswordChangedAt   *time.Time `json:"password_changed_at" db:"password_changed_at"`
	Metadata            *string    `json:"metadata" db:"metadata"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
}

// ListUsers returns a paginated list of users with modern query parameter support
func (h *Handlers) ListUsers(c *gin.Context) {
	// Configure modern query with field mappings and search fields
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery: `SELECT id, username, full_name, email, role, suspended_at, last_login_at, 
			            login_count, failed_login_attempts, locked_until, password_changed_at, 
			            metadata, created_at, updated_at FROM users`,
			CountQuery:   "SELECT COUNT(*) FROM users",
			DefaultOrder: "username ASC",
		},
		SearchFields:  []string{"username", "full_name", "email"},
		TableAlias:    "",
		DefaultFields: "*",
		FieldMapping: map[string]string{
			"id":                    "id",
			"username":              "username",
			"full_name":             "full_name",
			"email":                 "email",
			"role":                  "role",
			"suspended_at":          "suspended_at",
			"last_login_at":         "last_login_at",
			"login_count":           "login_count",
			"failed_login_attempts": "failed_login_attempts",
			"locked_until":          "locked_until",
			"password_changed_at":   "password_changed_at",
			"metadata":              "metadata",
			"created_at":            "created_at",
			"updated_at":            "updated_at",
		},
	}

	var users []UserResponse
	utils.ModernListWithQuery(c, h.db, config, &users)
}

// GetUser returns a single user by ID
func (h *Handlers) GetUser(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	var user UserResponse
	query := "SELECT id, username, full_name, email, role, suspended_at, last_login_at, login_count, failed_login_attempts, locked_until, password_changed_at, metadata, created_at, updated_at FROM users WHERE id = ?"
	if err := h.db.Get(&user, query, id); err != nil {
		if err == sql.ErrNoRows {
			utils.ProblemNotFound(c, "User")
		} else {
			utils.ProblemInternalServer(c, "Failed to fetch user")
		}
		return
	}

	utils.Success(c, user)
}

// CreateUser creates a new user account
func (h *Handlers) CreateUser(c *gin.Context) {
	var req utils.UserCreateRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Check username uniqueness
	if err := utils.CheckUnique(h.db, "users", "username", req.Username, nil); err != nil {
		utils.ProblemDuplicate(c, "Username")
		return
	}

	// Check email uniqueness (if provided)
	if req.Email != nil && *req.Email != "" {
		if err := utils.CheckUnique(h.db, "users", "email", *req.Email, nil); err != nil {
			utils.ProblemDuplicate(c, "Email")
			return
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to hash password")
		return
	}

	// Handle metadata - empty string should be NULL for JSON column
	var metadataValue interface{}
	if req.Metadata == "" {
		metadataValue = nil
	} else {
		metadataValue = req.Metadata
	}

	// Create user
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO users (username, full_name, email, password_hash, role, metadata) VALUES (?, ?, ?, ?, ?, ?)",
		req.Username, req.FullName, req.Email, string(hashedPassword), req.Role, metadataValue,
	)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to create user")
		return
	}

	id, _ := result.LastInsertId()
	utils.CreatedWithID(c, id, "User created successfully")
}

// UpdateUser updates an existing user's information
func (h *Handlers) UpdateUser(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	var req utils.UserUpdateRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Check if user exists
	if !utils.ValidateResourceExists(c, h.db, "users", "User", id) {
		return
	}

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}

	if req.Username != "" {
		if err := utils.CheckUnique(h.db, "users", "username", req.Username, &id); err != nil {
			utils.ProblemDuplicate(c, "Username")
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
		if err := utils.CheckUnique(h.db, "users", "email", *req.Email, &id); err != nil {
			utils.ProblemDuplicate(c, "Email")
			return
		}
		updates = append(updates, "email = ?")
		args = append(args, *req.Email)
	}

	if req.Password != "" {
		// Hash the new password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			utils.ProblemInternalServer(c, "Failed to hash password")
			return
		}
		updates = append(updates, "password_hash = ?, password_changed_at = NOW()")
		args = append(args, string(hashedPassword))
	}

	if req.Role != "" {
		updates = append(updates, "role = ?")
		args = append(args, req.Role)
	}

	if req.Metadata != "" {
		updates = append(updates, "metadata = ?")
		args = append(args, req.Metadata)
	}

	if req.Suspended != nil {
		if *req.Suspended {
			updates = append(updates, "suspended_at = NOW()")
		} else {
			updates = append(updates, "suspended_at = NULL")
		}
	}

	if len(updates) == 0 {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "fields",
			Message: "No fields to update",
		}})
		return
	}

	// Execute update
	query := "UPDATE users SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	args = append(args, id)

	if _, err := h.db.ExecContext(c.Request.Context(), query, args...); err != nil {
		utils.ProblemInternalServer(c, "Failed to update user")
		return
	}

	utils.SuccessWithMessage(c, "User updated successfully")
}

// DeleteUser permanently deletes a user account
func (h *Handlers) DeleteUser(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Check if this would be the last admin
	adminCount, err := utils.CountActivesExcludingID(h.db, "users", "role = 'admin' AND suspended_at IS NULL", id)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to check admin count")
		return
	}

	var userRole string
	if err := h.db.Get(&userRole, "SELECT role FROM users WHERE id = ?", id); err != nil {
		if err == sql.ErrNoRows {
			utils.ProblemNotFound(c, "User")
		} else {
			utils.ProblemInternalServer(c, "Failed to fetch user")
		}
		return
	}

	if userRole == "admin" && adminCount == 0 {
		utils.ProblemCustom(c, "https://babbel.api/problems/admin-constraint", "Admin Constraint", 409, "Cannot delete the last admin user")
		return
	}

	// Delete user and all sessions
	if _, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM user_sessions WHERE user_id = ?", id); err != nil {
		logger.Error("Failed to delete user sessions: %v", err)
	}

	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to delete user")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		utils.ProblemNotFound(c, "User")
		return
	}

	utils.NoContent(c)
}

// UpdateUserStatus handles user suspension and restoration
func (h *Handlers) UpdateUserStatus(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}
	if !utils.ValidateResourceExists(c, h.db, "users", "User", id) {
		return
	}
	var req struct {
		Action string `json:"action" binding:"required,oneof=suspend restore"`
	}
	if !utils.BindAndValidate(c, &req) {
		return
	}
	query := "UPDATE users SET suspended_at = NOW() WHERE id = ?"
	if req.Action == "restore" {
		query = "UPDATE users SET suspended_at = NULL WHERE id = ?"
	}
	_, err := h.db.ExecContext(c.Request.Context(), query, id)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to update user state")
		return
	}
	utils.SuccessWithMessage(c, "User state updated")
}
