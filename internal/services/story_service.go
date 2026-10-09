// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/datatypes"
)

// StoryServiceDeps groups the collaborators required for story persistence,
// audio processing, text-to-speech generation, and pronunciation injection.
type StoryServiceDeps struct {
	StoryRepo             *repository.StoryRepository
	VoiceRepo             *repository.VoiceRepository
	AudioSvc              *audio.Service
	TTSSvc                *tts.Service
	TTSSettingsSvc        *TTSSettingsService
	PronunciationInjector *PronunciationInjector
	Config                *config.Config
	Alerts                notify.Alerter
}

type storyRepository interface {
	Create(context.Context, *repository.StoryCreateData) (*models.Story, error)
	GetByID(context.Context, int64) (*models.Story, error)
	Update(context.Context, int64, *repository.StoryUpdate) error
	Exists(context.Context, int64) (bool, error)
	SoftDelete(context.Context, int64, *int64) error
	Restore(context.Context, int64, *int64) error
	UpdateAudio(context.Context, int64, repository.StoryAudioUpdate) error
	UpdateStatus(context.Context, int64, string, *int64) error
	List(context.Context, *repository.ListQuery) (*repository.ListResult[models.Story], error)
}

type voiceRepository interface {
	Exists(context.Context, int64) (bool, error)
	GetByID(context.Context, int64) (*models.Voice, error)
}

type speechGenerator interface {
	GenerateSpeech(context.Context, string, string, tts.Options) ([]byte, error)
}

type ttsSettingsGetter interface {
	Get(context.Context) (*models.TTSSettings, error)
}

// StoryService coordinates story lifecycle changes, audio publication, and
// text-to-speech generation.
type StoryService struct {
	storyRepo             storyRepository
	voiceRepo             voiceRepository
	audioSvc              *audio.Service
	ttsSvc                speechGenerator
	ttsSettingsSvc        ttsSettingsGetter
	pronunciationInjector *PronunciationInjector
	config                *config.Config
	alerts                notify.Alerter
}

// NewStoryService wires story business logic to its dependencies.
func NewStoryService(deps StoryServiceDeps) *StoryService {
	if deps.PronunciationInjector == nil {
		panic("services: NewStoryService requires a non-nil pronunciation injector")
	}
	return &StoryService{
		storyRepo:             deps.StoryRepo,
		voiceRepo:             deps.VoiceRepo,
		audioSvc:              deps.AudioSvc,
		ttsSvc:                deps.TTSSvc,
		ttsSettingsSvc:        deps.TTSSettingsSvc,
		pronunciationInjector: deps.PronunciationInjector,
		config:                deps.Config,
		alerts:                notify.OrDiscard(deps.Alerts),
	}
}

// CreateStoryRequest carries the required fields for a scheduled story.
// Dates use YYYY-MM-DD in the server's local timezone.
type CreateStoryRequest struct {
	ActorUserID *int64

	Title      string
	Text       string
	VoiceID    *int64
	Status     string
	StartDate  string
	EndDate    string
	Weekdays   models.Weekdays
	IsBreaking bool
	Metadata   *datatypes.JSONMap
}

// UpdateStoryRequest carries PATCH-style story fields; nil leaves a field unchanged.
// Dates use YYYY-MM-DD in the server's local timezone.
type UpdateStoryRequest struct {
	ActorUserID *int64

	Title      *string
	Text       *string
	VoiceID    *int64
	Status     *string
	StartDate  *string
	EndDate    *string
	Weekdays   *models.Weekdays
	IsBreaking *bool
	Metadata   *datatypes.JSONMap
}

// Create validates local-date bounds and optional voice ownership before
// persisting a story.
func (s *StoryService) Create(ctx context.Context, req *CreateStoryRequest) (*models.Story, error) {
	if req.VoiceID != nil {
		exists, err := s.voiceRepo.Exists(ctx, *req.VoiceID)
		if err != nil {
			return nil, apperrors.TranslateRepoError("Story", apperrors.OpQuery, err)
		}
		if !exists {
			return nil, apperrors.NotFoundWithID("Voice", *req.VoiceID)
		}
	}

	startDate, err := time.ParseInLocation("2006-01-02", req.StartDate, time.Local)
	if err != nil {
		return nil, apperrors.Validation("Story", "start_date", "invalid format, must be YYYY-MM-DD")
	}

	endDate, err := time.ParseInLocation("2006-01-02", req.EndDate, time.Local)
	if err != nil {
		return nil, apperrors.Validation("Story", "end_date", "invalid format, must be YYYY-MM-DD")
	}

	if endDate.Before(startDate) {
		return nil, apperrors.Validation("Story", "end_date", "cannot be before start date")
	}

	data := &repository.StoryCreateData{
		ActorUserID: req.ActorUserID,
		Title:       req.Title,
		Text:        req.Text,
		VoiceID:     req.VoiceID,
		Status:      req.Status,
		StartDate:   startDate,
		EndDate:     endDate,
		Weekdays:    req.Weekdays,
		IsBreaking:  req.IsBreaking,
		Metadata:    req.Metadata,
	}

	story, err := s.storyRepo.Create(ctx, data)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Story", apperrors.OpCreate, err)
	}

	return story, nil
}

// Update applies a partial story update and validates the effective date range,
// including the existing date when only one side of the range changes. The
// voice cannot change while the story has audio; resending the current voice
// is a no-op.
func (s *StoryService) Update(ctx context.Context, id int64, req *UpdateStoryRequest) (*models.Story, error) {
	startDate, endDate, err := s.parseDateUpdates(req)
	if err != nil {
		return nil, err
	}

	oneDateChanged := (startDate != nil) != (endDate != nil)
	var existing *models.Story
	if oneDateChanged || req.VoiceID != nil {
		existing, err = s.storyRepo.GetByID(ctx, id)
		if err != nil {
			return nil, apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpQuery, err)
		}
	}

	// Exactly one date changed, so the other bound must be loaded to validate
	// the effective range.
	if oneDateChanged {
		if err := validateEffectiveDateRange(existing, startDate, endDate); err != nil {
			return nil, err
		}
	}

	effective := *req
	effective.VoiceID, err = effectiveVoiceUpdate(existing, req.VoiceID)
	if err != nil {
		return nil, err
	}

	updates, err := s.buildUpdateStruct(ctx, &effective, startDate, endDate)
	if err != nil {
		return nil, err
	}

	if updates == nil {
		// Only the current voice was sent.
		if req.VoiceID != nil {
			return existing, nil
		}
		return nil, apperrors.Validation("Story", "", "no fields to update")
	}

	if err := s.storyRepo.Update(ctx, id, updates); err != nil {
		if errors.Is(err, repository.ErrStateConflict) {
			return nil, errStoryVoiceLocked(err)
		}
		return nil, apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpUpdate, err)
	}

	return s.GetByID(ctx, id)
}

// validateEffectiveDateRange checks the range formed by the changed bound and
// the existing story's other bound.
func validateEffectiveDateRange(existing *models.Story, startDate, endDate *time.Time) error {
	effectiveStart := existing.StartDate
	effectiveEnd := existing.EndDate
	if startDate != nil {
		effectiveStart = *startDate
	}
	if endDate != nil {
		effectiveEnd = *endDate
	}

	if effectiveEnd.Before(effectiveStart) {
		return apperrors.Validation("Story", "end_date", "cannot be before start date")
	}
	return nil
}

// effectiveVoiceUpdate returns the voice to write: nil when none was requested
// or it is unchanged. A different voice is rejected while the story has audio.
func effectiveVoiceUpdate(existing *models.Story, voiceID *int64) (*int64, error) {
	if !changesVoice(existing, voiceID) {
		return nil, nil
	}
	if existing.AudioFile != "" {
		return nil, errStoryVoiceLocked(nil)
	}
	return voiceID, nil
}

// changesVoice reports whether voiceID names a voice other than the story's.
func changesVoice(story *models.Story, voiceID *int64) bool {
	return voiceID != nil && (story.VoiceID == nil || *story.VoiceID != *voiceID)
}

// errStoryVoiceLocked reports an attempt to change the voice of a story whose
// audio was recorded or generated for another voice.
func errStoryVoiceLocked(cause error) error {
	return apperrors.ConflictWithCause(
		"Story",
		"story.voice_locked",
		"voice_id cannot change while the story has audio",
		"Upload or generate new audio with the voice_id query parameter to change the voice",
		cause,
	)
}

// parseDateUpdates parses changed date fields in the server's local timezone.
func (s *StoryService) parseDateUpdates(req *UpdateStoryRequest) (*time.Time, *time.Time, error) {
	var startDate, endDate *time.Time

	if req.StartDate != nil {
		parsed, err := time.ParseInLocation("2006-01-02", *req.StartDate, time.Local)
		if err != nil {
			return nil, nil, apperrors.Validation("Story", "start_date", "invalid format, must be YYYY-MM-DD")
		}
		startDate = &parsed
	}

	if req.EndDate != nil {
		parsed, err := time.ParseInLocation("2006-01-02", *req.EndDate, time.Local)
		if err != nil {
			return nil, nil, apperrors.Validation("Story", "end_date", "invalid format, must be YYYY-MM-DD")
		}
		endDate = &parsed
	}

	if startDate != nil && endDate != nil {
		if endDate.Before(*startDate) {
			return nil, nil, apperrors.Validation("Story", "end_date", "cannot be before start date")
		}
	}

	return startDate, endDate, nil
}

// buildUpdateStruct translates API-level PATCH semantics into repository
// updates and verifies a changed voice exists.
func (s *StoryService) buildUpdateStruct(
	ctx context.Context,
	req *UpdateStoryRequest,
	startDate, endDate *time.Time,
) (*repository.StoryUpdate, error) {
	updates := &repository.StoryUpdate{ActorUserID: req.ActorUserID}
	hasUpdates := false

	if req.Title != nil {
		updates.Title = req.Title
		hasUpdates = true
	}
	if req.Text != nil {
		updates.Text = req.Text
		hasUpdates = true
	}
	if req.Status != nil {
		updates.Status = req.Status
		hasUpdates = true
	}

	if req.VoiceID != nil {
		exists, err := s.voiceRepo.Exists(ctx, *req.VoiceID)
		if err != nil {
			return nil, apperrors.TranslateRepoError("Story", apperrors.OpQuery, err)
		}
		if !exists {
			return nil, apperrors.NotFoundWithID("Voice", *req.VoiceID)
		}
		updates.VoiceID = req.VoiceID
		hasUpdates = true
	}

	if startDate != nil {
		updates.StartDate = startDate
		hasUpdates = true
	}
	if endDate != nil {
		updates.EndDate = endDate
		hasUpdates = true
	}

	if req.Weekdays != nil {
		updates.Weekdays = req.Weekdays
		hasUpdates = true
	}

	if req.IsBreaking != nil {
		updates.IsBreaking = req.IsBreaking
		hasUpdates = true
	}

	if req.Metadata != nil {
		updates.Metadata = req.Metadata
		hasUpdates = true
	}

	if !hasUpdates {
		return nil, nil
	}

	return updates, nil
}

// GetByID loads a story and maps repository misses to a domain not-found error.
func (s *StoryService) GetByID(ctx context.Context, id int64) (*models.Story, error) {
	story, err := s.storyRepo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpQuery, err)
	}

	return story, nil
}

// Exists reports whether a story with the given ID exists.
func (s *StoryService) Exists(ctx context.Context, id int64) (bool, error) {
	exists, err := s.storyRepo.Exists(ctx, id)
	if err != nil {
		return false, apperrors.TranslateRepoError("Story", apperrors.OpQuery, err)
	}
	return exists, nil
}

// SoftDelete hides a story without removing its row.
func (s *StoryService) SoftDelete(ctx context.Context, id int64, actorUserID *int64) error {
	err := s.storyRepo.SoftDelete(ctx, id, actorUserID)
	if err != nil {
		return apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpDelete, err)
	}

	return nil
}

// Restore reactivates a soft-deleted story.
func (s *StoryService) Restore(ctx context.Context, id int64, actorUserID *int64) error {
	err := s.storyRepo.Restore(ctx, id, actorUserID)
	if err != nil {
		return apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpUpdate, err)
	}

	return nil
}

// AudioTarget is a validated destination for new story audio: the story as it
// was read and the voice heard in the audio. Publishing is conditional on the
// story still being in that state.
type AudioTarget struct {
	isTTS bool
	story *models.Story
	voice *models.Voice
}

// PrepareAudio loads a story and resolves the voice for new audio: voiceID
// when given, otherwise the story's current voice. Stories without a voice
// are rejected, so audio is never stored without a known speaker.
func (s *StoryService) PrepareAudio(ctx context.Context, storyID int64, voiceID *int64) (*AudioTarget, error) {
	story, err := s.GetByID(ctx, storyID)
	if err != nil {
		return nil, err
	}
	return s.audioTarget(ctx, story, voiceID)
}

func (s *StoryService) audioTarget(ctx context.Context, story *models.Story, voiceID *int64) (*AudioTarget, error) {
	if !changesVoice(story, voiceID) {
		if story.VoiceID == nil || story.Voice == nil {
			return nil, apperrors.Validation("Story", "voice_id",
				"story has no voice; select the voice heard in the audio first")
		}
		return &AudioTarget{story: story, voice: story.Voice}, nil
	}

	voice, err := s.voiceRepo.GetByID(ctx, *voiceID)
	if err != nil {
		return nil, apperrors.TranslateRepoErrorWithID("Voice", *voiceID, apperrors.OpQuery, err)
	}
	return &AudioTarget{story: story, voice: voice}, nil
}

// ProcessAudio converts uploaded audio and publishes it with the target's
// voice. The previous file is removed once the database points at the new one.
func (s *StoryService) ProcessAudio(ctx context.Context, target *AudioTarget, tempPath string, actorUserID *int64) error {
	story := target.story
	filename := utils.StoryFilename(story.ID, target.voice.ID, newAudioID())
	finalPath := utils.StoryPath(s.config, filename)
	published := false
	defer func() {
		if published {
			return
		}
		if rmErr := os.Remove(finalPath); rmErr != nil && !os.IsNotExist(rmErr) {
			logger.Error("Failed to remove unpublished audio file", "path", finalPath, "error", rmErr)
		}
	}()

	_, duration, err := s.audioSvc.ConvertStoryToWAV(ctx, tempPath, finalPath)
	if err != nil {
		return apperrors.Audio("Story", "convert", err)
	}

	err = s.storyRepo.UpdateAudio(ctx, story.ID, repository.StoryAudioUpdate{
		ActorUserID:       actorUserID,
		IsTTS:             target.isTTS,
		AudioFile:         filename,
		DurationSeconds:   duration,
		VoiceID:           target.voice.ID,
		ExpectedVoiceID:   story.VoiceID,
		ExpectedAudioFile: story.AudioFile,
	})
	if errors.Is(err, repository.ErrStateConflict) {
		return apperrors.ConflictWithCause(
			"Story",
			"story.audio_changed",
			"story voice or audio changed while the audio was being processed",
			"Reload the story and try again",
			err,
		)
	}
	if err != nil {
		return apperrors.TranslateRepoErrorWithID("Story", story.ID, apperrors.OpUpdate, err)
	}
	published = true

	if story.AudioFile != "" {
		oldPath := utils.StoryPath(s.config, story.AudioFile)
		if rmErr := os.Remove(oldPath); rmErr != nil && !os.IsNotExist(rmErr) {
			logger.Warn("Failed to remove replaced story audio", "path", oldPath, "error", rmErr)
		}
	}

	logger.Info("Processed audio for story",
		"story_id", story.ID, "voice_id", target.voice.ID, "filename", finalPath, "duration_s", duration)
	return nil
}

// newAudioID returns a short random ID that keeps story audio filenames unique.
func newAudioID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error.
	return hex.EncodeToString(b)
}

// UpdateStatus changes a story's workflow state to draft, active, or expired.
func (s *StoryService) UpdateStatus(ctx context.Context, id int64, status string, actorUserID *int64) (*models.Story, error) {
	storyStatus := models.StoryStatus(status)
	if !storyStatus.IsValid() {
		return nil, apperrors.Validation("Story", "status", "must be one of: draft, active, expired")
	}

	err := s.storyRepo.UpdateStatus(ctx, id, status, actorUserID)
	if err != nil {
		return nil, apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpUpdate, err)
	}

	return s.GetByID(ctx, id)
}

// List retrieves stories with filtering, sorting, and pagination.
func (s *StoryService) List(
	ctx context.Context,
	query *repository.ListQuery,
) (*repository.ListResult[models.Story], error) {
	result, err := s.storyRepo.List(ctx, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Story", apperrors.OpQuery, err)
	}
	return result, nil
}

// GenerateTTS creates story audio through the configured text-to-speech service
// with voiceID, or with the story's current voice when voiceID is nil.
// Existing audio is preserved unless force is true.
func (s *StoryService) GenerateTTS(ctx context.Context, storyID int64, voiceID *int64, force bool, actorUserID *int64) error {
	story, err := s.storyRepo.GetByID(ctx, storyID)
	if err != nil {
		return apperrors.TranslateRepoErrorWithID("Story", storyID, apperrors.OpQuery, err)
	}

	if err := validateStoryTTSPrerequisites(story, force); err != nil {
		return err
	}

	target, err := s.audioTarget(ctx, story, voiceID)
	if err != nil {
		return err
	}
	if target.voice.ElevenLabsVoiceID == nil || *target.voice.ElevenLabsVoiceID == "" {
		return apperrors.Validation("Voice", "elevenlabs_voice_id", "voice has no ElevenLabs voice ID configured")
	}

	settings, err := s.ttsSettingsSvc.Get(ctx)
	if err != nil {
		return err
	}

	processedText, err := s.pronunciationInjector.Apply(ctx, story.Text)
	if err != nil {
		return err
	}

	finalText := composeTTSText(processedText, settings.TTSStylePrefix)
	if err := validateTTSTextLength(finalText); err != nil {
		return err
	}
	options := ttsOptionsFromSettings(settings)

	audioData, err := s.ttsSvc.GenerateSpeech(
		tts.ContextWithStoryID(ctx, storyID),
		finalText,
		*target.voice.ElevenLabsVoiceID,
		options,
	)
	if err != nil {
		s.alertTTSError(ctx, storyID, err)
		return translateTTSError(storyID, err)
	}
	s.resolveTTSAlerts(ctx)

	tempPath, err := writeTempFile(audioData, fmt.Sprintf("tts_story_%d_*.opus", storyID))
	if err != nil {
		return apperrors.Audio("Story", "tts_write_temp", err)
	}
	defer func() {
		if err := os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove TTS temp file", "path", tempPath, "error", err)
		}
	}()

	target.isTTS = true
	return s.ProcessAudio(ctx, target, tempPath, actorUserID)
}

// alertTTSError maps operational TTS failures to stable alert categories.
func (s *StoryService) alertTTSError(ctx context.Context, storyID int64, err error) {
	event := notify.Event{
		Key:               "tts:upstream",
		Summary:           "ElevenLabs TTS is repeatedly unavailable",
		Details:           fmt.Sprintf("Story %d: %v", storyID, err),
		RequiresThreshold: true,
	}
	if apiErr, ok := errors.AsType[*tts.APIError](err); ok {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			event.Key = "tts:credentials"
			event.Summary = "ElevenLabs credentials are invalid or expired"
			event.RequiresThreshold = false
		case http.StatusTooManyRequests:
			event.Key = "tts:rate-limit"
			event.Summary = "ElevenLabs quota or rate limit is repeatedly exceeded"
		case http.StatusNotFound, http.StatusUnprocessableEntity:
			return // Voice/request validation errors are user-actionable, not incidents.
		}
	}
	s.alerts.Alert(ctx, event)
}

// resolveTTSAlerts clears all TTS incidents after successful synthesis.
func (s *StoryService) resolveTTSAlerts(ctx context.Context) {
	s.alerts.Resolve(ctx, "tts:credentials", "ElevenLabs credentials recovered", "TTS generation succeeded again.")
	s.alerts.Resolve(ctx, "tts:rate-limit", "ElevenLabs capacity recovered", "TTS generation succeeded again.")
	s.alerts.Resolve(ctx, "tts:upstream", "ElevenLabs service recovered", "TTS generation succeeded again.")
}

func validateStoryTTSPrerequisites(story *models.Story, force bool) error {
	if story.AudioFile != "" && !force {
		return apperrors.Validation("Story", "audio_file", "story already has audio - use ?force=true to overwrite")
	}
	if story.Text == "" {
		return apperrors.Validation("Story", "text", "story has no text for TTS generation")
	}
	return nil
}

func composeTTSText(text, prefix string) string {
	if strings.TrimSpace(prefix) == "" {
		return text
	}
	return prefix + "\n" + text
}

func validateTTSTextLength(text string) error {
	count := utf8.RuneCountInString(text)
	if count <= tts.MaxInputChars {
		return nil
	}

	return apperrors.NewValidationProblemError(
		"story",
		"Text exceeds ElevenLabs input limit",
		[]apperrors.ValidationError{{
			Field: "text",
			Message: fmt.Sprintf(
				"rune count %d exceeds ElevenLabs input limit of %d",
				count,
				tts.MaxInputChars,
			),
		}},
	)
}

func ttsOptionsFromSettings(settings *models.TTSSettings) tts.Options {
	return tts.Options{
		Stability:              settings.Stability,
		ApplyTextNormalization: settings.ApplyTextNormalization,
		Seed:                   settings.Seed,
	}
}

func translateTTSError(storyID int64, err error) error {
	if apiErr, ok := errors.AsType[*tts.APIError](err); ok {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return apperrors.Upstream(
				"TTS",
				"ElevenLabs",
				http.StatusServiceUnavailable,
				"Check the ElevenLabs API key and account access",
				apiErr,
			)
		case http.StatusNotFound:
			return apperrors.ValidationWithCause("Voice", "elevenlabs_voice_id", apiErr.Error(), apiErr)
		case http.StatusTooManyRequests:
			return apperrors.RateLimited("TTS", apiErr.RetryAfter, apiErr)
		case http.StatusUnprocessableEntity:
			return apperrors.ValidationWithCause("TTS", "request", apiErr.Error(), apiErr)
		default:
			logger.WithFields(map[string]any{
				"story_id":    storyID,
				"status_code": apiErr.StatusCode,
				"body":        apiErr.Body,
			}).Error("unmapped ElevenLabs TTS error")
			return apperrors.Upstream(
				"TTS",
				"ElevenLabs",
				http.StatusBadGateway,
				"Please try again later",
				apiErr,
			)
		}
	}
	return apperrors.Audio("Story", "tts_generate", err)
}

// writeTempFile writes data to an OS temp file and removes partial output on
// write or close failure.
func writeTempFile(data []byte, pattern string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}

	path := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}

	return path, nil
}
