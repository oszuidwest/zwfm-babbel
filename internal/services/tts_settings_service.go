package services

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const (
	// TTSNormalizationAuto delegates text normalization to ElevenLabs.
	TTSNormalizationAuto = "auto"
	// TTSNormalizationOn forces ElevenLabs text normalization on.
	TTSNormalizationOn = "on"
	// TTSNormalizationOff disables ElevenLabs text normalization.
	TTSNormalizationOff = "off"

	maxTTSStylePrefixRunes  = 500
	maxElevenLabsSeedUint32 = math.MaxUint32
)

var allowedTextNormalizations = []string{
	TTSNormalizationAuto,
	TTSNormalizationOn,
	TTSNormalizationOff,
}

// TTSSettingsService manages the singleton ElevenLabs request settings.
type TTSSettingsService struct {
	repo      *repository.TTSSettingsRepository
	txManager repository.TxManager
}

// NewTTSSettingsService binds settings validation and persistence to repo.
func NewTTSSettingsService(repo *repository.TTSSettingsRepository, txManager repository.TxManager) *TTSSettingsService {
	return &TTSSettingsService{repo: repo, txManager: txManager}
}

// UpdateTTSSettingsRequest carries PATCH-style updates for TTS settings.
type UpdateTTSSettingsRequest struct {
	Stability              *float64
	ApplyTextNormalization *string
	Seed                   *int64
	TTSStylePrefix         *string
	ClearSeed              bool
	ActorUserID            *int64
}

// Get loads the current singleton settings row.
func (s *TTSSettingsService) Get(ctx context.Context) (*models.TTSSettings, error) {
	settings, err := s.repo.Get(ctx)
	if err != nil {
		return nil, translateTTSSettingsRepoError(apperrors.OpQuery, err)
	}
	return settings, nil
}

// Update validates and persists settings with last-writer-wins semantics.
// Audit entries include changed values and the actor when available.
func (s *TTSSettingsService) Update(ctx context.Context, req *UpdateTTSSettingsRequest) (*models.TTSSettings, error) {
	if req == nil || req.IsEmpty() {
		return s.Get(ctx)
	}

	if validationErrs := validateTTSSettingsUpdate(req); len(validationErrs) > 0 {
		return nil, &apperrors.ValidationError{Errors: validationErrs}
	}

	update := &repository.TTSSettingsUpdate{
		Stability:              req.Stability,
		ApplyTextNormalization: req.ApplyTextNormalization,
		Seed:                   seedUpdateValue(req.Seed),
		TTSStylePrefix:         req.TTSStylePrefix,
		ClearSeed:              req.ClearSeed,
	}

	var current, updated *models.TTSSettings
	err := s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		var err error
		current, err = s.repo.GetForUpdate(ctx)
		if err != nil {
			return err
		}
		if err := s.repo.Update(ctx, update); err != nil {
			return err
		}
		updated, err = s.repo.Get(ctx)
		if err != nil {
			return err
		}
		return repository.RecordAudit(ctx, models.AuditEvent{
			UserID: req.ActorUserID, EntityType: models.AuditEntityTTSSettings, EntityID: repository.TTSSettingsSingletonID, Action: models.AuditActionUpdate,
		}, ttsSettingsAuditValues(current), ttsSettingsAuditValues(updated))
	})
	if err != nil {
		return nil, translateTTSSettingsRepoError(apperrors.OpUpdate, err)
	}

	logTTSSettingsUpdate(req, current, updated)
	return updated, nil
}

// IsEmpty reports whether no fields are set.
func (r *UpdateTTSSettingsRequest) IsEmpty() bool {
	return r.Stability == nil &&
		r.ApplyTextNormalization == nil &&
		r.Seed == nil &&
		!r.ClearSeed &&
		r.TTSStylePrefix == nil
}

func translateTTSSettingsRepoError(op apperrors.Operation, err error) error {
	if errors.Is(err, repository.ErrSchemaUnavailable) {
		return apperrors.NotInitialized("tts_settings", "apply migrations/001_complete_schema.sql", err)
	}
	if errors.Is(err, repository.ErrNotFound) {
		return apperrors.NotInitializedWithCode(
			"tts_settings",
			"tts_settings.row_missing",
			"tts_settings singleton row missing",
			"restore the id=1 row from migrations/001_complete_schema.sql seed data",
			err,
		)
	}
	return apperrors.TranslateRepoError("TTSSettings", op, err)
}

func seedUpdateValue(seed *int64) *uint32 {
	if seed == nil {
		return nil
	}
	// Defense in depth: validateSeed in Update is the primary guard.
	if *seed < 0 || *seed > maxElevenLabsSeedUint32 {
		return nil
	}
	value := uint32(*seed)
	return &value
}

func validateTTSSettingsUpdate(req *UpdateTTSSettingsRequest) []apperrors.FieldError {
	errs := []apperrors.FieldError{}

	errs = append(errs, validateStability(req.Stability)...)
	if v := req.ApplyTextNormalization; v != nil && !slices.Contains(allowedTextNormalizations, *v) {
		errs = append(errs, fieldError("apply_text_normalization", apperrors.CodeInvalidChoice,
			"must be one of: "+strings.Join(allowedTextNormalizations, ", ")))
	}
	errs = append(errs, validateSeed(req.Seed)...)
	errs = append(errs, validateTTSStylePrefix(req.TTSStylePrefix)...)

	return errs
}

func validateStability(value *float64) []apperrors.FieldError {
	if value == nil || (*value >= 0 && *value <= 1) {
		return nil
	}
	return []apperrors.FieldError{fieldError("stability", apperrors.CodeOutOfRange, "must be between 0 and 1")}
}

func validateSeed(seed *int64) []apperrors.FieldError {
	if seed == nil || (*seed >= 0 && *seed <= maxElevenLabsSeedUint32) {
		return nil
	}
	return []apperrors.FieldError{fieldError("seed", apperrors.CodeOutOfRange, "must be between 0 and 4294967295")}
}

func validateTTSStylePrefix(prefix *string) []apperrors.FieldError {
	if prefix == nil || utf8.RuneCountInString(*prefix) <= maxTTSStylePrefixRunes {
		return nil
	}
	return []apperrors.FieldError{fieldError("tts_style_prefix", apperrors.CodeTooLong, "must be at most 500 characters")}
}

func fieldError(field, code, message string) apperrors.FieldError {
	return apperrors.FieldError{Field: field, Code: code, Message: message}
}

func logTTSSettingsUpdate(req *UpdateTTSSettingsRequest, before, after *models.TTSSettings) {
	fields := buildTTSSettingsAuditFields(req, before, after)
	if fields == nil {
		return
	}
	logger.WithFields(fields).Info("tts settings updated")
}

func buildTTSSettingsAuditFields(req *UpdateTTSSettingsRequest, before, after *models.TTSSettings) map[string]any {
	changed := changedTTSSettingsFields(req, before, after)
	if len(changed) == 0 {
		return nil
	}

	fields := map[string]any{
		"changed_fields": changed,
	}
	if req.ActorUserID != nil {
		fields["user_id"] = *req.ActorUserID
	}
	oldValues, newValues := ttsSettingsAuditValues(before), ttsSettingsAuditValues(after)
	for _, field := range changed {
		fields["old_"+field] = oldValues[field]
		fields["new_"+field] = newValues[field]
	}
	return fields
}

func changedTTSSettingsFields(req *UpdateTTSSettingsRequest, before, after *models.TTSSettings) []string {
	changed := []string{}
	appendIfChanged := func(set bool, field string, equal bool) {
		if set && !equal {
			changed = append(changed, field)
		}
	}

	// Float equality is intentional: both sides are read from the same DECIMAL(3,2)
	// database columns around the update, with no arithmetic between reads.
	appendIfChanged(req.Stability != nil, "stability", before.Stability == after.Stability)
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

// ttsSettingsAuditValues returns every audited setting by API field name;
// RecordAudit and the update log keep only the ones that changed.
func ttsSettingsAuditValues(settings *models.TTSSettings) map[string]any {
	var seed any
	if settings.Seed != nil {
		seed = *settings.Seed
	}
	return map[string]any{
		"stability":                settings.Stability,
		"apply_text_normalization": settings.ApplyTextNormalization,
		"seed":                     seed,
		"tts_style_prefix":         settings.TTSStylePrefix,
	}
}
