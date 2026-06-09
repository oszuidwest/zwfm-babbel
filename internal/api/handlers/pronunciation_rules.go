package handlers

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// PronunciationRulesService is the handler-facing pronunciation rules contract.
type PronunciationRulesService interface {
	// Get loads the current editor-facing pronunciation rule set.
	Get(ctx context.Context) (*services.PronunciationRulesResponse, error)

	// Update validates and replaces the full pronunciation rule set.
	Update(ctx context.Context, req *services.UpdatePronunciationRulesRequest) (*services.PronunciationRulesResponse, error)
}

type pronunciationRuleRequest struct {
	StringToReplace string `json:"string_to_replace"`
	IPA             string `json:"ipa"`
	CaseSensitive   *bool  `json:"case_sensitive,omitempty"`
	WordBoundaries  *bool  `json:"word_boundaries,omitempty"`
}

type pronunciationRulesUpdateRequest struct {
	Rules []pronunciationRuleRequest `json:"rules" binding:"required"`
}

type pronunciationRuleResponse struct {
	StringToReplace string `json:"string_to_replace"`
	IPA             string `json:"ipa"`
	CaseSensitive   bool   `json:"case_sensitive"`
	WordBoundaries  bool   `json:"word_boundaries"`
}

type pronunciationRulesResponse struct {
	Rules     []pronunciationRuleResponse `json:"rules"`
	UpdatedAt *time.Time                  `json:"updated_at"`
}

// GetPronunciationRules returns the local inline-IPA pronunciation rules.
func (h *Handlers) GetPronunciationRules(c *gin.Context) {
	if !h.requirePronunciationRulesService(c) {
		return
	}

	result, err := h.pronunciationRulesSvc.Get(c.Request.Context())
	if err != nil {
		handleServiceError(c, err, "PronunciationRules")
		return
	}

	utils.Success(c, toPronunciationRulesResponse(result))
}

// UpdatePronunciationRules replaces the full local inline-IPA pronunciation rule set.
func (h *Handlers) UpdatePronunciationRules(c *gin.Context) {
	if !h.requirePronunciationRulesService(c) {
		return
	}

	var req pronunciationRulesUpdateRequest
	removed := utils.RemovedFields{
		"alias": "field has been replaced by 'ipa'",
	}
	if !utils.BindJSONStrict(c, &req, removed) {
		return
	}

	serviceReq := &services.UpdatePronunciationRulesRequest{
		Rules: toPronunciationRuleUpdates(req.Rules),
	}
	if userID, ok := auth.UserID(c); ok {
		serviceReq.ActorUserID = &userID
	}

	result, err := h.pronunciationRulesSvc.Update(c.Request.Context(), serviceReq)
	if err != nil {
		handleServiceError(c, err, "PronunciationRules")
		return
	}

	utils.Success(c, toPronunciationRulesResponse(result))
}

func toPronunciationRuleUpdates(rules []pronunciationRuleRequest) []services.PronunciationRuleUpdate {
	updates := make([]services.PronunciationRuleUpdate, 0, len(rules))
	for _, rule := range rules {
		updates = append(updates, services.PronunciationRuleUpdate{
			StringToReplace: rule.StringToReplace,
			IPA:             rule.IPA,
			CaseSensitive:   rule.CaseSensitive,
			WordBoundaries:  rule.WordBoundaries,
		})
	}
	return updates
}

func toPronunciationRulesResponse(result *services.PronunciationRulesResponse) pronunciationRulesResponse {
	if result == nil {
		return pronunciationRulesResponse{Rules: []pronunciationRuleResponse{}}
	}

	rules := make([]pronunciationRuleResponse, 0, len(result.Rules))
	for _, rule := range result.Rules {
		rules = append(rules, toPronunciationRuleResponse(rule))
	}
	return pronunciationRulesResponse{
		Rules:     rules,
		UpdatedAt: result.UpdatedAt,
	}
}

func toPronunciationRuleResponse(rule models.PronunciationRule) pronunciationRuleResponse {
	return pronunciationRuleResponse{
		StringToReplace: rule.StringToReplace,
		IPA:             rule.IPA,
		CaseSensitive:   rule.CaseSensitive,
		WordBoundaries:  rule.WordBoundaries,
	}
}
