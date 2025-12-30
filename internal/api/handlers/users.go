// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListUsers returns a paginated list of users.
func (h *Handlers) ListUsers(c *gin.Context) {
	// Parse query parameters
	params := utils.ParseQueryParams(c)
	if params == nil {
		utils.ProblemInternalServer(c, "Failed to parse query parameters")
		return
	}

	// Convert utils.QueryParams to repository.ListQuery using shared function
	query := convertToListQuery(params)

	result, err := h.userSvc.List(c.Request.Context(), query)
	if err != nil {
		handleServiceError(c, err, "User")
		return
	}

	// Apply field filtering if requested
	var responseData any = result.Data
	if len(params.Fields) > 0 {
		responseData = utils.FilterStructFields(result.Data, params.Fields)
	}

	utils.PaginatedResponse(c, responseData, result.Total, result.Limit, result.Offset)
}

// GetUser returns a single user by ID.
func (h *Handlers) GetUser(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	user, err := h.userSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "User")
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

	// Prepare email value (convert pointer to string)
	email := ""
	if req.Email != nil {
		email = *req.Email
	}

	// Create user via service
	user, err := h.userSvc.Create(c.Request.Context(), req.Username, req.FullName, email, req.Password, req.Role, req.Metadata)
	if err != nil {
		handleServiceError(c, err, "User")
		return
	}

	utils.CreatedWithLocation(c, user.ID, "/api/v1/users", "User created successfully")
}

// UpdateUser updates an existing user's information
func (h *Handlers) UpdateUser(c *gin.Context) {
	id, ok := utils.IDParam(c)
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
	updated, err := h.userSvc.Update(c.Request.Context(), id, serviceReq)
	if err != nil {
		handleServiceError(c, err, "User")
		return
	}
	utils.Success(c, updated)
}

// DeleteUser permanently deletes a user account
func (h *Handlers) DeleteUser(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Delete user via service
	err := h.userSvc.SoftDelete(c.Request.Context(), id)
	if err != nil {
		// Special handling for last admin constraint
		var validationErr *apperrors.ValidationError
		if errors.As(err, &validationErr) && validationErr.Message == "cannot delete last admin" {
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
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req struct {
		Action string `json:"action" binding:"required,oneof=suspend restore"`
	}
	if !utils.BindAndValidate(c, &req) {
		return
	}

	var updated *models.User
	var err error
	if req.Action == "suspend" {
		updated, err = h.userSvc.Suspend(c.Request.Context(), id)
	} else {
		updated, err = h.userSvc.Unsuspend(c.Request.Context(), id)
	}

	if err != nil {
		handleServiceError(c, err, "User")
		return
	}
	utils.Success(c, updated)
}
