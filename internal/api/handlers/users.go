package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListUsers returns a paginated list of users.
func (h *Handlers) ListUsers(c *gin.Context) {
	params, ok := utils.ParseListQueryWithTrashed(c)
	if !ok {
		return
	}

	result, err := h.userSvc.List(c.Request.Context(), &params.ListQuery)
	if err != nil {
		handleServiceError(c, err, "User")
		return
	}

	utils.PaginatedListResponse(c, params, result)
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

// RespondWithCurrentUser writes the current user and their effective permissions.
func (h *Handlers) RespondWithCurrentUser(c *gin.Context, id int64, permissions auth.PermissionSet) {
	user, err := h.userSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "User")
		return
	}

	utils.Success(c, CurrentSessionResponse{
		User:        user,
		Permissions: permissions,
	})
}

// CreateUser accepts a JSON account payload and returns the created user ID.
func (h *Handlers) CreateUser(c *gin.Context) {
	var req utils.UserCreateRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	email := ""
	if req.Email != nil {
		email = *req.Email
	}

	user, err := h.userSvc.Create(c.Request.Context(), services.CreateUserRequest{
		Username: req.Username,
		FullName: req.FullName,
		Email:    email,
		Password: req.Password,
		Role:     req.Role,
		Metadata: req.Metadata,
	})
	if err != nil {
		handleServiceError(c, err, "User")
		return
	}

	utils.CreatedWithLocation(c, user.ID, "/api/v1/users", "User created successfully")
}

// UpdateUser applies a JSON partial account update.
func (h *Handlers) UpdateUser(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req utils.UserUpdateRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	if !utils.RequireAnyField(c, req) {
		return
	}

	serviceReq := services.UpdateUserRequest(req)

	updated, err := h.userSvc.Update(c.Request.Context(), id, &serviceReq)
	if err != nil {
		handleServiceError(c, err, "User")
		return
	}
	utils.Success(c, updated)
}

// DeleteUser permanently deletes a user account unless it is the last admin.
func (h *Handlers) DeleteUser(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	if err := h.userSvc.SoftDelete(c.Request.Context(), id); err != nil {
		handleServiceError(c, err, "User")
		return
	}

	utils.NoContent(c)
}

// UpdateUserStatus handles user suspension and restoration.
func (h *Handlers) UpdateUserStatus(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req struct {
		Action string `json:"action" binding:"required,oneof=suspend restore"`
	}
	if !utils.BindJSON(c, &req) {
		return
	}

	suspend := req.Action == "suspend"
	updated, err := h.userSvc.Update(c.Request.Context(), id, &services.UpdateUserRequest{Suspended: &suspend})
	if err != nil {
		handleServiceError(c, err, "User")
		return
	}
	utils.Success(c, updated)
}
