package handlers

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// TTSSettingsResponse exposes global TTS settings plus runtime TTS configuration.
type TTSSettingsResponse struct {
	Stability              float64   `json:"stability"`
	ApplyTextNormalization string    `json:"apply_text_normalization"`
	Seed                   *uint32   `json:"seed"`
	TTSStylePrefix         string    `json:"tts_style_prefix"`
	UpdatedAt              time.Time `json:"updated_at"`
	APIKeyConfigured       bool      `json:"api_key_configured"`
	ModelID                string    `json:"model_id"`
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
	if !utils.BindJSON(c, &req) {
		return
	}

	serviceReq := toTTSSettingsServiceRequest(req)
	if !utils.RequireAnyField(c, *serviceReq) {
		return
	}
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
		ApplyTextNormalization: settings.ApplyTextNormalization,
		Seed:                   settings.Seed,
		TTSStylePrefix:         settings.TTSStylePrefix,
		UpdatedAt:              settings.UpdatedAt,
		APIKeyConfigured:       h.config.TTS.APIKey != "",
		ModelID:                tts.ModelID,
	}
}

func toTTSSettingsServiceRequest(req utils.TTSSettingsUpdateRequest) *services.UpdateTTSSettingsRequest {
	serviceReq := &services.UpdateTTSSettingsRequest{
		Stability:              req.Stability,
		ApplyTextNormalization: req.ApplyTextNormalization,
		TTSStylePrefix:         req.TTSStylePrefix,
		Seed:                   req.Seed.Value,
		ClearSeed:              req.Seed.IsClearing(),
	}

	return serviceReq
}
