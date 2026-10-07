package handlers

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// AuditEventsHandler lists history visible under the actor's entity permissions.
type AuditEventsHandler struct {
	repo        *repository.AuditEventRepository
	permissions func(string) (auth.PermissionSet, error)
}

// NewAuditEventsHandler binds history reads to the existing permission evaluator.
func NewAuditEventsHandler(repo *repository.AuditEventRepository, permissions func(string) (auth.PermissionSet, error)) *AuditEventsHandler {
	return &AuditEventsHandler{repo: repo, permissions: permissions}
}

// List returns audit events after restricting both rows and totals by permission.
func (h *AuditEventsHandler) List(c *gin.Context) {
	role, ok := auth.UserRole(c)
	if !ok {
		utils.ProblemAuthentication(c, "Authentication required")
		return
	}
	permissions, err := h.permissions(role)
	if err != nil {
		utils.ProblemInternalServer(c, "Permission check failed")
		return
	}
	entityTypes := []string{}
	for entity, resource := range map[string]auth.Resource{
		"story":               auth.ResourceStories,
		"tts_settings":        auth.ResourceSettingsTTS,
		"pronunciation_rules": auth.ResourcePronunciationRules,
	} {
		if slices.Contains(permissions[string(resource)], string(auth.ActionRead)) {
			entityTypes = append(entityTypes, entity)
		}
	}
	if len(entityTypes) == 0 {
		utils.ProblemCustom(c, utils.ProblemTypeInsufficientPermissions, "Insufficient Permissions",
			http.StatusForbidden, "Insufficient permissions")
		return
	}
	params, query, ok := utils.ParseListQuery(c)
	if !ok {
		return
	}
	result, err := h.repo.List(c.Request.Context(), query, entityTypes)
	if err != nil {
		handleServiceError(c, err, "AuditEvent")
		return
	}
	utils.PaginatedListResponse(c, params, result)
}
