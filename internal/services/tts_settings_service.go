package services

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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
// TTS settings updates are intentionally last-writer-wins, matching the rest of
// the PATCH APIs. The audit log is best-effort and compares snapshots around the
// update; it is not an immutable serialized audit trail.
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
		Seed:                   seedUpdateValue(req.Seed),
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
// Keep in sync with utils.TTSSettingsUpdateRequest.IsEmpty: the HTTP handler
// returns 422 for empty PATCHes, while the service keeps a defensive no-op for
// programmatic callers.
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
	if errors.Is(err, repository.ErrSchemaUnavailable) {
		return apperrors.NotInitialized("tts_settings", "apply migration 005_tts_settings.sql", err)
	}
	if errors.Is(err, repository.ErrNotFound) {
		return apperrors.NotInitializedWithCode(
			"tts_settings",
			"tts_settings.row_missing",
			"tts_settings singleton row missing",
			"restore the id=1 row from migrations/005_tts_settings.sql seed data",
			err,
		)
	}
	return apperrors.TranslateRepoError("TTSSettings", apperrors.OpQuery, err)
}

func seedUpdateValue(seed *int64) *uint32 {
	if seed == nil {
		return nil
	}
	// validateSeed runs before this conversion and guarantees the uint32 range.
	value := uint32(*seed) //nolint:gosec // G115 guarded by validateSeed in Update.
	return &value
}

func validateTTSSettingsUpdate(req *UpdateTTSSettingsRequest) []apperrors.FieldValidationError {
	errs := []apperrors.FieldValidationError{}

	errs = append(errs, validateEnumField(
		"model",
		req.Model,
		allowedTTSModels,
		enumMessage(allowedTTSModels),
	)...)
	errs = append(errs, validateNumberField("stability", req.Stability, 0, 1, "must be between 0 and 1")...)
	errs = append(errs, validateNumberField("similarity_boost", req.SimilarityBoost, 0, 1, "must be between 0 and 1")...)
	errs = append(errs, validateNumberField("style", req.Style, 0, 1, "must be between 0 and 1")...)
	errs = append(errs, validateNumberField("speed", req.Speed, 0.7, 1.2, "must be between 0.7 and 1.2")...)
	errs = append(errs, validateEnumField(
		"apply_text_normalization",
		req.ApplyTextNormalization,
		allowedTextNormalizations,
		enumMessage(allowedTextNormalizations),
	)...)
	errs = append(errs, validateSeed(req.Seed)...)
	errs = append(errs, validateTTSStylePrefix(req.TTSStylePrefix)...)

	return errs
}

func enumMessage(allowed []string) string {
	return "must be one of: " + strings.Join(allowed, ", ")
}

func validateEnumField(field string, value *string, allowed []string, message string) []apperrors.FieldValidationError {
	if value == nil || slices.Contains(allowed, *value) {
		return nil
	}
	return []apperrors.FieldValidationError{fieldError(field, message)}
}

func validateNumberField(field string, value *float64, min, max float64, message string) []apperrors.FieldValidationError {
	if value == nil || betweenInclusive(*value, min, max) {
		return nil
	}
	return []apperrors.FieldValidationError{fieldError(field, message)}
}

func validateSeed(seed *int64) []apperrors.FieldValidationError {
	if seed == nil || (*seed >= 0 && *seed <= maxElevenLabsSeedUint32) {
		return nil
	}
	return []apperrors.FieldValidationError{fieldError("seed", "must be between 0 and 4294967295")}
}

func validateTTSStylePrefix(prefix *string) []apperrors.FieldValidationError {
	if prefix == nil || utf8.RuneCountInString(*prefix) <= maxTTSStylePrefixRunes {
		return nil
	}
	return []apperrors.FieldValidationError{fieldError("tts_style_prefix", "must be at most 500 characters")}
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
	// ElevenLabs documents different per-request character ceilings by model:
	// eleven_v3=5000, multilingual_v2=10000, flash_v2_5=40000.
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
