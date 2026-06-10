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

// pronunciationRulesService is the slice of PronunciationRulesService the
// handler depends on. Narrowing to an interface lets tests substitute a
// request-capturing fake to assert that the authenticated user propagates to
// the service audit trail.
type pronunciationRulesService interface {
	Get(ctx context.Context) (*services.PronunciationRulesResponse, error)
	Update(ctx context.Context, req *services.UpdatePronunciationRulesRequest) (*services.PronunciationRulesResponse, error)
}

var _ pronunciationRulesService = (*services.PronunciationRulesService)(nil)

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
	result, err := h.pronunciationRulesSvc.Get(c.Request.Context())
	if err != nil {
		handleServiceError(c, err, "PronunciationRules")
		return
	}

	utils.Success(c, toPronunciationRulesResponse(result))
}

// UpdatePronunciationRules replaces the full local inline-IPA pronunciation rule set.
func (h *Handlers) UpdatePronunciationRules(c *gin.Context) {
	var req utils.PronunciationRulesUpdateRequest
	if !utils.BindJSONStrict(c, &req) {
		return
	}

	serviceReq := toPronunciationRulesServiceRequest(req)
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

func toPronunciationRulesServiceRequest(
	req utils.PronunciationRulesUpdateRequest,
) *services.UpdatePronunciationRulesRequest {
	rules := make([]services.PronunciationRuleUpdate, 0, len(req.Rules))
	for _, rule := range req.Rules {
		rules = append(rules, services.PronunciationRuleUpdate{
			StringToReplace: rule.StringToReplace,
			IPA:             rule.IPA,
			CaseSensitive:   rule.CaseSensitive,
			WordBoundaries:  rule.WordBoundaries,
		})
	}
	return &services.UpdatePronunciationRulesRequest{Rules: rules}
}

func toPronunciationRulesResponse(result *services.PronunciationRulesResponse) pronunciationRulesResponse {
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
