// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
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
	GetByIDForWrite(context.Context, int64) (*models.Story, error)
	Update(context.Context, int64, *repository.StoryUpdate) error
	Exists(context.Context, int64) (bool, error)
	SoftDelete(context.Context, int64) error
	Restore(context.Context, int64) error
	UpdateAudio(context.Context, int64, string, float64) error
	UpdateStatus(context.Context, int64, string) error
	List(context.Context, *repository.ListQuery) (*repository.ListResult[models.Story], error)
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
	voiceRepo             *repository.VoiceRepository
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
	startDate, err := parseStoryDate("start_date", req.StartDate)
	if err != nil {
		return nil, err
	}

	endDate, err := parseStoryDate("end_date", req.EndDate)
	if err != nil {
		return nil, err
	}

	if err := checkDateRange(startDate, endDate, "end_date"); err != nil {
		return nil, err
	}

	if req.VoiceID != nil {
		if err := requireReference(ctx, s.voiceRepo.Exists, "Story", "voice_id", *req.VoiceID); err != nil {
			return nil, err
		}
	}

	data := &repository.StoryCreateData{
		Title:      req.Title,
		Text:       req.Text,
		VoiceID:    req.VoiceID,
		Status:     req.Status,
		StartDate:  startDate,
		EndDate:    endDate,
		Weekdays:   req.Weekdays,
		IsBreaking: req.IsBreaking,
		Metadata:   req.Metadata,
	}

	story, err := s.storyRepo.Create(ctx, data)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Story", apperrors.OpCreate, err)
	}

	return story, nil
}

// Update applies a partial story update and validates the effective date range,
// including the existing date when only one side of the range changes.
func (s *StoryService) Update(ctx context.Context, id int64, req *UpdateStoryRequest) (*models.Story, error) {
	existing, err := s.storyRepo.GetByIDForWrite(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpQuery, err)
	}

	startDate, endDate, err := s.parseDateUpdates(req)
	if err != nil {
		return nil, err
	}

	if startDate != nil || endDate != nil {
		start, end := startDate, endDate
		if start == nil {
			start = (*time.Time)(&existing.StartDate)
		}
		if end == nil {
			end = (*time.Time)(&existing.EndDate)
		}
		// Blame the date the client sent; with both, the end date is out of order.
		field := "end_date"
		if endDate == nil {
			field = "start_date"
		}
		if err := checkDateRange(*start, *end, field); err != nil {
			return nil, err
		}
	}

	if req.VoiceID != nil {
		if err := requireReference(ctx, s.voiceRepo.Exists, "Story", "voice_id", *req.VoiceID); err != nil {
			return nil, err
		}
	}

	updates := &repository.StoryUpdate{
		Title:      req.Title,
		Text:       req.Text,
		VoiceID:    req.VoiceID,
		Status:     req.Status,
		StartDate:  startDate,
		EndDate:    endDate,
		Weekdays:   req.Weekdays,
		Metadata:   req.Metadata,
		IsBreaking: req.IsBreaking,
	}

	if err := s.storyRepo.Update(ctx, id, updates); err != nil {
		return nil, apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpUpdate, err)
	}

	return s.GetByID(ctx, id)
}

// checkDateRange rejects an end date before the start date, labeling field.
func checkDateRange(start, end time.Time, field string) error {
	if !end.Before(start) {
		return nil
	}
	return apperrors.Invalid(field, apperrors.CodeDateOrder, "end_date cannot be before start_date")
}

// parseStoryDate parses a YYYY-MM-DD date in the server's local timezone.
func parseStoryDate(field, value string) (time.Time, error) {
	parsed, err := time.ParseInLocation(time.DateOnly, value, time.Local)
	if err != nil {
		return time.Time{}, apperrors.Invalid(field, apperrors.CodeInvalidFormat, "must be in YYYY-MM-DD format")
	}
	return parsed, nil
}

// parseDateUpdates parses changed date fields in the server's local timezone.
func (s *StoryService) parseDateUpdates(req *UpdateStoryRequest) (*time.Time, *time.Time, error) {
	var startDate, endDate *time.Time

	if req.StartDate != nil {
		parsed, err := parseStoryDate("start_date", *req.StartDate)
		if err != nil {
			return nil, nil, err
		}
		startDate = &parsed
	}

	if req.EndDate != nil {
		parsed, err := parseStoryDate("end_date", *req.EndDate)
		if err != nil {
			return nil, nil, err
		}
		endDate = &parsed
	}

	return startDate, endDate, nil
}

// GetByID loads a story and maps repository misses to a domain not-found error.
func (s *StoryService) GetByID(ctx context.Context, id int64) (*models.Story, error) {
	story, err := s.storyRepo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpQuery, err)
	}

	return story, nil
}

// GetByIDForWrite loads a story before writing, reporting deleted stories separately.
func (s *StoryService) GetByIDForWrite(ctx context.Context, id int64) (*models.Story, error) {
	story, err := s.storyRepo.GetByIDForWrite(ctx, id)
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
func (s *StoryService) SoftDelete(ctx context.Context, id int64) error {
	err := s.storyRepo.SoftDelete(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpDelete, err)
	}

	return nil
}

// Restore reactivates a soft-deleted story.
func (s *StoryService) Restore(ctx context.Context, id int64) error {
	err := s.storyRepo.Restore(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoErrorWithID("Story", id, apperrors.OpUpdate, err)
	}

	return nil
}

// ProcessAudio converts uploaded audio and atomically replaces the published file.
func (s *StoryService) ProcessAudio(ctx context.Context, storyID int64, tempPath string) error {
	// Convert beside the final file for atomic rename. Updating the database first
	// preserves existing audio on failure and avoids stale paths after concurrent deletion.
	// The .wav suffix makes FFmpeg select the WAV muxer.
	finalPath := utils.StoryPath(s.config, storyID)
	convertedPath := strings.TrimSuffix(finalPath, ".wav") + ".processing.wav"
	defer func() {
		if rmErr := os.Remove(convertedPath); rmErr != nil && !os.IsNotExist(rmErr) {
			logger.Error("Failed to remove temporary audio file", "path", convertedPath, "error", rmErr)
		}
	}()

	duration, err := s.audioSvc.ConvertStoryToWAV(ctx, tempPath, convertedPath)
	if err != nil {
		return apperrors.Audio("Story", "convert", err)
	}

	filenameOnly := utils.StoryFilename(storyID)
	if err := s.storyRepo.UpdateAudio(ctx, storyID, filenameOnly, duration); err != nil {
		return apperrors.TranslateRepoErrorWithID("Story", storyID, apperrors.OpUpdate, err)
	}

	if err := os.Rename(convertedPath, finalPath); err != nil {
		return apperrors.Audio("Story", "finalize", err)
	}

	logger.Info("Processed audio for story", "story_id", storyID, "filename", finalPath, "duration_s", duration)
	return nil
}

// UpdateStatus changes a story's workflow state to draft, active, or expired.
// Request binding validates status.
func (s *StoryService) UpdateStatus(ctx context.Context, id int64, status string) (*models.Story, error) {
	err := s.storyRepo.UpdateStatus(ctx, id, status)
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

// GenerateTTS creates story audio through the configured text-to-speech service.
// Existing audio is preserved unless force is true.
func (s *StoryService) GenerateTTS(ctx context.Context, storyID int64, force bool) error {
	story, err := s.storyRepo.GetByIDForWrite(ctx, storyID)
	if err != nil {
		return apperrors.TranslateRepoErrorWithID("Story", storyID, apperrors.OpQuery, err)
	}

	if err := validateStoryTTSPrerequisites(story, force); err != nil {
		return err
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
		*story.Voice.ElevenLabsVoiceID,
		options,
	)
	if err != nil {
		s.alertTTSError(ctx, storyID, err)
		return translateTTSError(storyID, err)
	}

	tempPath, err := writeTempFile(audioData, fmt.Sprintf("tts_story_%d_*.opus", storyID))
	if err != nil {
		return apperrors.Audio("Story", "tts_write_temp", err)
	}
	defer func() {
		if err := os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove TTS temp file", "path", tempPath, "error", err)
		}
	}()

	if err := s.ProcessAudio(ctx, storyID, tempPath); err != nil {
		if errors.Is(err, audio.ErrSilent) {
			s.alertTTSError(ctx, storyID, err)
			return apperrors.Upstream("TTS", "ElevenLabs", http.StatusBadGateway,
				"ElevenLabs returned silent audio; try again", err)
		}
		return err
	}
	s.resolveTTSAlerts(ctx)
	return nil
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
		case http.StatusNotFound:
			return // A missing voice is user-actionable, not an incident.
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
		return apperrors.Conflict("story.audio_exists", "Story already has audio",
			"Use ?force=true to overwrite the existing audio")
	}
	if story.Text == "" {
		return apperrors.Conflict("story.no_text", "Story has no text for TTS generation",
			"Add text to the story first")
	}
	if story.VoiceID == nil {
		return apperrors.Conflict("story.no_voice", "Story has no voice assigned for TTS generation",
			"Assign a voice to the story first")
	}
	if story.Voice == nil || story.Voice.ElevenLabsVoiceID == nil || *story.Voice.ElevenLabsVoiceID == "" {
		return apperrors.Conflict("voice.no_elevenlabs_id", "Voice has no ElevenLabs voice ID configured",
			"Set elevenlabs_voice_id on the voice first")
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

	return apperrors.Conflict(
		"story.tts_text_too_long",
		fmt.Sprintf("Text with style prefix has %d characters; ElevenLabs accepts at most %d", count, tts.MaxInputChars),
		"Shorten the story text or the TTS style prefix",
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
			return apperrors.ConflictWithCause("voice.elevenlabs_not_found", "ElevenLabs does not know the configured voice ID",
				"Check elevenlabs_voice_id on the story's voice", apiErr)
		case http.StatusTooManyRequests:
			return apperrors.RateLimited("TTS", apiErr.RetryAfter, apiErr)
		case http.StatusUnprocessableEntity:
			return apperrors.Upstream("TTS", "ElevenLabs", http.StatusBadGateway,
				"ElevenLabs rejected the generated request; check the TTS settings", apiErr)
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
