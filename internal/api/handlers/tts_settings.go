package handlers

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// TTSSettingsResponse exposes global TTS settings plus API-key availability.
type TTSSettingsResponse struct {
	Stability              float64   `json:"stability"`
	SimilarityBoost        float64   `json:"similarity_boost"`
	Style                  float64   `json:"style"`
	Speed                  float64   `json:"speed"`
	ApplyTextNormalization string    `json:"apply_text_normalization"`
	Seed                   *uint32   `json:"seed"`
	TTSStylePrefix         string    `json:"tts_style_prefix"`
	UpdatedAt              time.Time `json:"updated_at"`
	APIKeyConfigured       bool      `json:"api_key_configured"`
}

// GetTTSSettings returns the singleton settings used for generated story audio.
func (h *Handlers) GetTTSSettings(c *gin.Context) {
	settings, err := h.ttsSettingsSvc.Get(c.Request.Context())
	if err != nil {
		handleServiceError(c, err, "TTSSettings")
		return
	}

	utils.Success(c, h.toTTSSettingsResponse(settings))
}

// UpdateTTSSettings applies a validated PATCH to the singleton TTS settings.
func (h *Handlers) UpdateTTSSettings(c *gin.Context) {
	var req utils.TTSSettingsUpdateRequest
	removed := utils.RemovedFields{
		"model":             "field has been removed in v3-only release",
		"use_speaker_boost": "field has been removed in v3-only release",
	}
	if !utils.BindJSONStrict(c, &req, removed) {
		return
	}

	if req.IsEmpty() {
		utils.ProblemValidationError(c, "Validation failed", []apperrors.ValidationError{{
			Field:   "request",
			Message: "At least one field must be provided",
		}})
		return
	}

	serviceReq := toTTSSettingsServiceRequest(req)
	if userID, ok := auth.UserID(c); ok {
		serviceReq.ActorUserID = &userID
	}

	updated, err := h.ttsSettingsSvc.Update(c.Request.Context(), serviceReq)
	if err != nil {
		handleServiceError(c, err, "TTSSettings")
		return
	}

	utils.Success(c, h.toTTSSettingsResponse(updated))
}

func (h *Handlers) toTTSSettingsResponse(settings *models.TTSSettings) TTSSettingsResponse {
	return TTSSettingsResponse{
		Stability:              settings.Stability,
		SimilarityBoost:        settings.SimilarityBoost,
		Style:                  settings.Style,
		Speed:                  settings.Speed,
		ApplyTextNormalization: settings.ApplyTextNormalization,
		Seed:                   settings.Seed,
		TTSStylePrefix:         settings.TTSStylePrefix,
		UpdatedAt:              settings.UpdatedAt,
		APIKeyConfigured:       h.config.TTS.APIKey != "",
	}
}

func toTTSSettingsServiceRequest(req utils.TTSSettingsUpdateRequest) *services.UpdateTTSSettingsRequest {
	serviceReq := &services.UpdateTTSSettingsRequest{
		Stability:              req.Stability,
		SimilarityBoost:        req.SimilarityBoost,
		Style:                  req.Style,
		Speed:                  req.Speed,
		ApplyTextNormalization: req.ApplyTextNormalization,
		TTSStylePrefix:         req.TTSStylePrefix,
	}

	if req.Seed.HasValue() {
		serviceReq.Seed = req.Seed.Value
	} else if req.Seed.IsClearing() {
		serviceReq.ClearSeed = true
	}

	return serviceReq
}
