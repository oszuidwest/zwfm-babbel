package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
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
	Alias           string `json:"alias"`
	CaseSensitive   *bool  `json:"case_sensitive,omitempty"`
	WordBoundaries  *bool  `json:"word_boundaries,omitempty"`
}

type pronunciationRulesUpdateRequest struct {
	Rules []pronunciationRuleRequest `json:"rules" binding:"required"`
}

type pronunciationRuleResponse struct {
	StringToReplace string `json:"string_to_replace"`
	Alias           string `json:"alias"`
	CaseSensitive   bool   `json:"case_sensitive"`
	WordBoundaries  bool   `json:"word_boundaries"`
}

type pronunciationRulesResponse struct {
	Rules           []pronunciationRuleResponse `json:"rules"`
	LatestVersionID *string                     `json:"latest_version_id"`
	CreatedAt       *time.Time                  `json:"created_at"`
	Warning         *string                     `json:"warning,omitempty"`
}

// GetPronunciationRules returns the managed ElevenLabs pronunciation rules.
func (h *Handlers) GetPronunciationRules(c *gin.Context) {
	if !h.ensurePronunciationRulesEnabled(c) {
		return
	}

	result, err := h.pronunciationRulesSvc.Get(c.Request.Context())
	if err != nil {
		handleServiceError(c, err, "PronunciationRules")
		return
	}

	utils.Success(c, toPronunciationRulesResponse(result))
}

// UpdatePronunciationRules replaces the full managed pronunciation rule set.
func (h *Handlers) UpdatePronunciationRules(c *gin.Context) {
	if !h.ensurePronunciationRulesEnabled(c) {
		return
	}

	var req pronunciationRulesUpdateRequest
	if !utils.BindAndValidate(c, &req) {
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

func (h *Handlers) ensurePronunciationRulesEnabled(c *gin.Context) bool {
	if h.ttsEnabled && h.pronunciationRulesSvc != nil {
		return true
	}
	utils.ProblemExtended(
		c,
		http.StatusNotImplemented,
		"Text-to-speech is not configured",
		"tts.not_configured",
		"Set BABBEL_ELEVENLABS_API_KEY to enable TTS",
	)
	return false
}

func toPronunciationRuleUpdates(rules []pronunciationRuleRequest) []services.PronunciationRuleUpdate {
	updates := make([]services.PronunciationRuleUpdate, 0, len(rules))
	for _, rule := range rules {
		updates = append(updates, services.PronunciationRuleUpdate{
			StringToReplace: rule.StringToReplace,
			Alias:           rule.Alias,
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
		Rules:           rules,
		LatestVersionID: result.LatestVersionID,
		CreatedAt:       result.CreatedAt,
		Warning:         result.Warning,
	}
}

func toPronunciationRuleResponse(rule tts.Rule) pronunciationRuleResponse {
	return pronunciationRuleResponse{
		StringToReplace: rule.StringToReplace,
		Alias:           rule.Alias,
		CaseSensitive:   rule.CaseSensitive,
		WordBoundaries:  rule.WordBoundaries,
	}
}
