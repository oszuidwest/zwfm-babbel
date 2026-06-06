package services

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const (
	TTSModelElevenV3        = "eleven_v3"
	TTSModelMultilingualV2  = "eleven_multilingual_v2"
	TTSModelFlashV25        = "eleven_flash_v2_5"
	TTSNormalizationAuto    = "auto"
	TTSNormalizationOn      = "on"
	TTSNormalizationOff     = "off"
	maxTTSStylePrefixRunes  = 500
	maxElevenLabsSeedUint32 = 4_294_967_295
)

var (
	allowedTTSModels = []string{
		TTSModelElevenV3,
		TTSModelMultilingualV2,
		TTSModelFlashV25,
	}
	allowedTextNormalizations = []string{
		TTSNormalizationAuto,
		TTSNormalizationOn,
		TTSNormalizationOff,
	}
)

// TTSSettingsService handles global text-to-speech settings.
type TTSSettingsService struct {
	repo *repository.TTSSettingsRepository
}

// NewTTSSettingsService creates a TTS settings service.
func NewTTSSettingsService(repo *repository.TTSSettingsRepository) *TTSSettingsService {
	return &TTSSettingsService{repo: repo}
}

// UpdateTTSSettingsRequest contains partial TTS settings updates.
type UpdateTTSSettingsRequest struct {
	Model                  *string
	Stability              *float64
	SimilarityBoost        *float64
	Style                  *float64
	UseSpeakerBoost        *bool
	Speed                  *float64
	ApplyTextNormalization *string
	Seed                   *int64
	TTSStylePrefix         *string
	ClearSeed              bool
	ActorUserID            *int64
}

// Get retrieves the current singleton settings.
func (s *TTSSettingsService) Get(ctx context.Context) (*models.TTSSettings, error) {
	settings, err := s.repo.Get(ctx)
	if err != nil {
		return nil, translateTTSSettingsRepoError(err)
	}
	return settings, nil
}

// Update validates, applies, and returns the updated singleton settings.
func (s *TTSSettingsService) Update(ctx context.Context, req *UpdateTTSSettingsRequest) (*models.TTSSettings, error) {
	current, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}

	if req == nil || req.IsEmpty() {
		return current, nil
	}

	if validationErrs := validateTTSSettingsUpdate(req); len(validationErrs) > 0 {
		return nil, apperrors.NewValidationProblemError("tts_settings", "One or more fields failed validation", validationErrs)
	}

	update := &repository.TTSSettingsUpdate{
		Model:                  req.Model,
		Stability:              req.Stability,
		SimilarityBoost:        req.SimilarityBoost,
		Style:                  req.Style,
		UseSpeakerBoost:        req.UseSpeakerBoost,
		Speed:                  req.Speed,
		ApplyTextNormalization: req.ApplyTextNormalization,
		Seed:                   req.Seed,
		TTSStylePrefix:         req.TTSStylePrefix,
		ClearSeed:              req.ClearSeed,
	}

	if err := s.repo.Update(ctx, update); err != nil {
		return nil, translateTTSSettingsRepoError(err)
	}

	updated, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}

	logTTSSettingsUpdate(req, current, updated)
	return updated, nil
}

// IsEmpty reports whether no fields are being updated.
func (r *UpdateTTSSettingsRequest) IsEmpty() bool {
	return r.Model == nil &&
		r.Stability == nil &&
		r.SimilarityBoost == nil &&
		r.Style == nil &&
		r.UseSpeakerBoost == nil &&
		r.Speed == nil &&
		r.ApplyTextNormalization == nil &&
		r.Seed == nil &&
		!r.ClearSeed &&
		r.TTSStylePrefix == nil
}

func translateTTSSettingsRepoError(err error) error {
	if errors.Is(err, repository.ErrSchemaUnavailable) || errors.Is(err, repository.ErrNotFound) {
		return apperrors.NotInitialized("tts_settings", "apply migration 005_tts_settings.sql", err)
	}
	return apperrors.TranslateRepoError("TTSSettings", apperrors.OpQuery, err)
}

func validateTTSSettingsUpdate(req *UpdateTTSSettingsRequest) []apperrors.FieldValidationError {
	errs := []apperrors.FieldValidationError{}

	if req.Model != nil && !slices.Contains(allowedTTSModels, *req.Model) {
		errs = append(errs, fieldError("model", "must be one of: eleven_v3, eleven_multilingual_v2, eleven_flash_v2_5"))
	}
	if req.Stability != nil && !betweenInclusive(*req.Stability, 0, 1) {
		errs = append(errs, fieldError("stability", "must be between 0 and 1"))
	}
	if req.SimilarityBoost != nil && !betweenInclusive(*req.SimilarityBoost, 0, 1) {
		errs = append(errs, fieldError("similarity_boost", "must be between 0 and 1"))
	}
	if req.Style != nil && !betweenInclusive(*req.Style, 0, 1) {
		errs = append(errs, fieldError("style", "must be between 0 and 1"))
	}
	if req.Speed != nil && !betweenInclusive(*req.Speed, 0.7, 1.2) {
		errs = append(errs, fieldError("speed", "must be between 0.7 and 1.2"))
	}
	if req.ApplyTextNormalization != nil && !slices.Contains(allowedTextNormalizations, *req.ApplyTextNormalization) {
		errs = append(errs, fieldError("apply_text_normalization", "must be one of: auto, on, off"))
	}
	if req.Seed != nil && (*req.Seed < 0 || *req.Seed > maxElevenLabsSeedUint32) {
		errs = append(errs, fieldError("seed", "must be between 0 and 4294967295"))
	}
	if req.TTSStylePrefix != nil && utf8.RuneCountInString(*req.TTSStylePrefix) > maxTTSStylePrefixRunes {
		errs = append(errs, fieldError("tts_style_prefix", "must be at most 500 characters"))
	}

	return errs
}

func fieldError(field, message string) apperrors.FieldValidationError {
	return apperrors.FieldValidationError{Field: field, Message: message}
}

func betweenInclusive(value, min, max float64) bool {
	return value >= min && value <= max
}

func logTTSSettingsUpdate(req *UpdateTTSSettingsRequest, before, after *models.TTSSettings) {
	changed := changedTTSSettingsFields(req, before, after)
	if len(changed) == 0 {
		return
	}

	fields := map[string]any{
		"changed_fields": changed,
		"new_model":      after.Model,
	}
	if req.ActorUserID != nil {
		fields["user_id"] = *req.ActorUserID
	}
	for _, field := range changed {
		fields["new_"+field] = ttsSettingsFieldValue(after, field)
	}

	logger.WithFields(fields).Info("tts settings updated")
}

func changedTTSSettingsFields(req *UpdateTTSSettingsRequest, before, after *models.TTSSettings) []string {
	changed := []string{}
	appendIfChanged := func(set bool, field string, equal bool) {
		if set && !equal {
			changed = append(changed, field)
		}
	}

	appendIfChanged(req.Model != nil, "model", before.Model == after.Model)
	appendIfChanged(req.Stability != nil, "stability", before.Stability == after.Stability)
	appendIfChanged(req.SimilarityBoost != nil, "similarity_boost", before.SimilarityBoost == after.SimilarityBoost)
	appendIfChanged(req.Style != nil, "style", before.Style == after.Style)
	appendIfChanged(req.UseSpeakerBoost != nil, "use_speaker_boost", before.UseSpeakerBoost == after.UseSpeakerBoost)
	appendIfChanged(req.Speed != nil, "speed", before.Speed == after.Speed)
	appendIfChanged(
		req.ApplyTextNormalization != nil,
		"apply_text_normalization",
		before.ApplyTextNormalization == after.ApplyTextNormalization,
	)
	appendIfChanged(req.Seed != nil || req.ClearSeed, "seed", seedEqual(before.Seed, after.Seed))
	appendIfChanged(req.TTSStylePrefix != nil, "tts_style_prefix", before.TTSStylePrefix == after.TTSStylePrefix)

	return changed
}

func seedEqual(a, b *uint32) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

func ttsSettingsFieldValue(settings *models.TTSSettings, field string) any {
	switch field {
	case "model":
		return settings.Model
	case "stability":
		return settings.Stability
	case "similarity_boost":
		return settings.SimilarityBoost
	case "style":
		return settings.Style
	case "use_speaker_boost":
		return settings.UseSpeakerBoost
	case "speed":
		return settings.Speed
	case "apply_text_normalization":
		return settings.ApplyTextNormalization
	case "seed":
		if settings.Seed == nil {
			return nil
		}
		return *settings.Seed
	case "tts_style_prefix":
		return settings.TTSStylePrefix
	default:
		return fmt.Sprintf("<unknown field %s>", field)
	}
}

func modelCharLimit(model string) int {
	switch model {
	case TTSModelElevenV3:
		return 5000
	case TTSModelMultilingualV2:
		return 10000
	case TTSModelFlashV25:
		return 40000
	default:
		return 0
	}
}
