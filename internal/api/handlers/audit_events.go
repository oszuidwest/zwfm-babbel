package handlers

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// auditEntityResources maps each audited entity type to the resource whose read
// permission exposes its history.
var auditEntityResources = map[string]auth.Resource{
	"story":               auth.ResourceStories,
	"tts_settings":        auth.ResourceSettingsTTS,
	"pronunciation_rules": auth.ResourcePronunciationRules,
}

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
		logger.Error("Audit events: permission evaluation failed", "role", role, "error", err)
		utils.ProblemInternalServer(c, "Permission check failed")
		return
	}
	entityTypes, includeActorNames := auditScope(permissions)
	if len(entityTypes) == 0 {
		utils.ProblemCustom(c, utils.ProblemTypeInsufficientPermissions, "Insufficient Permissions",
			http.StatusForbidden, "Insufficient permissions")
		return
	}
	params, query, ok := utils.ParseListQuery(c)
	if !ok {
		return
	}
	result, err := h.repo.List(c.Request.Context(), query, entityTypes, includeActorNames)
	if err != nil {
		handleServiceError(c, apperrors.TranslateRepoError("AuditEvent", apperrors.OpQuery, err), "AuditEvent")
		return
	}
	utils.PaginatedListResponse(c, params, result)
}

// auditScope returns the readable entity types, sorted, and whether actor
// names may be joined in.
func auditScope(permissions auth.PermissionSet) (entityTypes []string, includeActorNames bool) {
	canRead := func(resource auth.Resource) bool {
		return slices.Contains(permissions[string(resource)], string(auth.ActionRead))
	}
	for entity, resource := range auditEntityResources {
		if canRead(resource) {
			entityTypes = append(entityTypes, entity)
		}
	}
	slices.Sort(entityTypes)
	return entityTypes, canRead(auth.ResourceUsers)
}
