// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// UserResponse represents the user data returned by the API
type UserResponse struct {
	ID                  int64      `json:"id" db:"id"`
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
	utils.ModernListWithQuery(c, h.userSvc.DB(), config, &users)
}

// GetUser returns a single user by ID
func (h *Handlers) GetUser(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Get user via service
	user, err := h.userSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "User")
		return
	}

	// Convert to response format using safe pointer conversion
	response := UserResponse{
		ID:                  user.ID,
		Username:            user.Username,
		FullName:            stringToPtr(user.FullName),
		Email:               user.Email,
		Role:                string(user.Role),
		SuspendedAt:         user.SuspendedAt,
		LastLoginAt:         user.LastLoginAt,
		LoginCount:          user.LoginCount,
		FailedLoginAttempts: user.FailedLoginAttempts,
		LockedUntil:         user.LockedUntil,
		PasswordChangedAt:   user.PasswordChangedAt,
		Metadata:            user.Metadata,
		CreatedAt:           user.CreatedAt,
		UpdatedAt:           user.UpdatedAt,
	}

	utils.Success(c, response)
}

// CreateUser creates a new user account
func (h *Handlers) CreateUser(c *gin.Context) {
	var req utils.UserCreateRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Prepare email value (convert pointer to string)
	email := ""
	if req.Email != nil {
		email = *req.Email
	}

	// Create user via service
	user, err := h.userSvc.Create(c.Request.Context(), req.Username, req.FullName, email, req.Password, req.Role)
	if err != nil {
		handleServiceError(c, err, "User")
		return
	}

	utils.CreatedWithID(c, user.ID, "User created successfully")
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

	// Convert to service request
	serviceReq := &services.UpdateUserRequest{
		Username:  req.Username,
		FullName:  req.FullName,
		Email:     req.Email,
		Password:  req.Password,
		Role:      req.Role,
		Metadata:  req.Metadata,
		Suspended: req.Suspended,
	}

	// Update user via service
	if err := h.userSvc.Update(c.Request.Context(), id, serviceReq); err != nil {
		handleServiceError(c, err, "User")
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

	// Delete user via service
	err := h.userSvc.SoftDelete(c.Request.Context(), id)
	if err != nil {
		// Special handling for last admin constraint
		if errors.Is(err, services.ErrInvalidInput) {
			// Check if this is the last admin error
			utils.ProblemCustom(c, "https://babbel.api/problems/admin-constraint", "Admin Constraint", 409, "Cannot delete the last admin user")
			return
		}
		handleServiceError(c, err, "User")
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

	var req struct {
		Action string `json:"action" binding:"required,oneof=suspend restore"`
	}
	if !utils.BindAndValidate(c, &req) {
		return
	}

	var err error
	if req.Action == "suspend" {
		err = h.userSvc.Suspend(c.Request.Context(), id)
	} else {
		err = h.userSvc.Unsuspend(c.Request.Context(), id)
	}

	if err != nil {
		handleServiceError(c, err, "User")
		return
	}

	utils.SuccessWithMessage(c, "User status updated successfully")
}
