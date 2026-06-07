// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/datatypes"
)

const maxJSONRequestBodyBytes int64 = 1 << 20

// IDParam extracts and validates the ID parameter from the request URL.
func IDParam(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		ProblemBadRequest(c, "Invalid ID parameter")
		return 0, false
	}
	return id, true
}

const (
	defaultPaginationLimit = 20
	maxPaginationLimit     = 100
)

// Pagination extracts pagination parameters from the query string. Absent
// parameters fall back to defaults (limit=20, offset=0). Malformed or
// out-of-range values return a *QueryParamError so the caller can surface a
// structured 422 response instead of silently substituting defaults.
func Pagination(c *gin.Context) (limit, offset int, err error) {
	limit = defaultPaginationLimit
	if raw := c.Query("limit"); raw != "" {
		l, atoiErr := strconv.Atoi(raw)
		switch {
		case atoiErr != nil:
			return 0, 0, &QueryParamError{Field: "limit", Message: fmt.Sprintf("expected integer, got %q", raw)}
		case l < 1:
			return 0, 0, &QueryParamError{Field: "limit", Message: "must be >= 1"}
		case l > maxPaginationLimit:
			return 0, 0, &QueryParamError{Field: "limit", Message: fmt.Sprintf("must be <= %d", maxPaginationLimit)}
		default:
			limit = l
		}
	}
	if raw := c.Query("offset"); raw != "" {
		o, atoiErr := strconv.Atoi(raw)
		switch {
		case atoiErr != nil:
			return 0, 0, &QueryParamError{Field: "offset", Message: fmt.Sprintf("expected integer, got %q", raw)}
		case o < 0:
			return 0, 0, &QueryParamError{Field: "offset", Message: "must be >= 0"}
		default:
			offset = o
		}
	}
	return limit, offset, nil
}

// ValidateAndSaveAudioFile validates an uploaded audio file and saves it to a temporary location.
func ValidateAndSaveAudioFile(
	c *gin.Context, fieldName string, prefix string,
) (tempPath string, cleanup func() error, err error) {
	file, header, err := c.Request.FormFile(fieldName)
	if err != nil {
		return "", nil, err
	}

	if err := ValidateAudioFile(header); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn("Failed to close file during validation error", "error", closeErr)
		}
		return "", nil, fmt.Errorf("invalid audio file: %w", err)
	}

	safeFilename := SanitizeFilename(header.Filename)
	tempPath = filepath.Join(os.TempDir(), fmt.Sprintf("%s_%s", prefix, safeFilename))

	if err := saveFileToPath(file, tempPath); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn("Failed to close file during save error", "error", closeErr)
		}
		return "", nil, err
	}

	cleanup = func() error {
		var errs []error
		if err := file.Close(); err != nil {
			logger.Warn("Failed to close uploaded file during cleanup", "error", err)
			errs = append(errs, err)
		}
		if err := os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove temp file", "path", tempPath, "error", err)
			errs = append(errs, err)
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		return nil
	}

	return tempPath, cleanup, nil
}

// ValidateAudioFile validates an uploaded audio file for size and format.
func ValidateAudioFile(header *multipart.FileHeader) error {
	// Check file size (100MB max)
	const maxSize = 100 * 1024 * 1024
	if header.Size > maxSize {
		return fmt.Errorf("file too large (max 100MB)")
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	validExts := []string{".wav", ".mp3", ".m4a", ".aac", ".ogg", ".flac", ".opus"}

	if !slices.Contains(validExts, ext) {
		return fmt.Errorf("unsupported file type: %s", ext)
	}
	return nil
}

// SanitizeFilename removes unsafe characters from filenames.
func SanitizeFilename(filename string) string {
	// Remove path separators and other unsafe characters
	filename = filepath.Base(filename)
	filename = strings.ReplaceAll(filename, " ", "_")
	return filename
}

// saveFileToPath saves an uploaded multipart file to the specified path.
func saveFileToPath(file multipart.File, dst string) error {
	// #nosec G304 - dst is sanitized temp path from ValidateAndSaveAudioFile
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if err := out.Close(); err != nil {
			logger.Error("Failed to close output file", "error", err)
		}
	}()

	_, err = io.Copy(out, file)
	return err
}

// StationRequest represents the request for creating and updating radio stations.
type StationRequest struct {
	Name               string  `json:"name" binding:"required,notblank,max=255"`
	MaxStoriesPerBlock int     `json:"max_stories_per_block" binding:"gte=1,lte=50"`
	PauseSeconds       float64 `json:"pause_seconds" binding:"gte=0,lte=60"`
}

// VoiceRequest represents the request for creating voices.
type VoiceRequest struct {
	Name              string  `json:"name" binding:"required,notblank,max=255"`
	ElevenLabsVoiceID *string `json:"elevenlabs_voice_id" binding:"omitempty,notblank,max=255"`
}

// VoiceUpdateRequest represents the request for updating voices.
// Name is optional (omit to skip), ElevenLabsVoiceID supports null-to-clear via Optional.
type VoiceUpdateRequest struct {
	Name              *string          `json:"name" binding:"omitempty,notblank,max=255"`
	ElevenLabsVoiceID Optional[string] `json:"elevenlabs_voice_id" binding:"omitempty,notblank,max=255"`
}

// StationVoiceRequest represents the request for creating station-voice relationships.
type StationVoiceRequest struct {
	StationID int64   `json:"station_id" binding:"required,min=1"`
	VoiceID   int64   `json:"voice_id" binding:"required,min=1"`
	MixPoint  float64 `json:"mix_point" binding:"gte=0,lte=300"`
}

// StationVoiceUpdateRequest represents the request for updating station-voice relationships.
type StationVoiceUpdateRequest struct {
	StationID *int64   `json:"station_id,omitempty" binding:"omitempty,min=1"`
	VoiceID   *int64   `json:"voice_id,omitempty" binding:"omitempty,min=1"`
	MixPoint  *float64 `json:"mix_point,omitempty" binding:"omitempty,gte=0,lte=300"`
}

// UserCreateRequest represents the request for creating new user accounts.
type UserCreateRequest struct {
	Username string             `json:"username" binding:"required,min=3,max=100,alphanum"`
	FullName string             `json:"full_name" binding:"required,notblank,max=255"`
	Password string             `json:"password" binding:"required,min=8,max=128"`
	Email    *string            `json:"email" binding:"omitempty,email,max=255"`
	Role     string             `json:"role" binding:"required,oneof=admin editor viewer"`
	Metadata *datatypes.JSONMap `json:"metadata,omitempty"`
}

// UserUpdateRequest represents the request for updating existing user accounts.
type UserUpdateRequest struct {
	Username  string             `json:"username" binding:"omitempty,min=3,max=100,alphanum"`
	FullName  string             `json:"full_name" binding:"omitempty,notblank,max=255"`
	Email     *string            `json:"email" binding:"omitempty,email,max=255"`
	Password  string             `json:"password" binding:"omitempty,min=8,max=255"`
	Role      string             `json:"role" binding:"omitempty,oneof=admin editor viewer"`
	Metadata  *datatypes.JSONMap `json:"metadata,omitempty"`
	Suspended *bool              `json:"suspended" binding:"omitempty"`
}

// StoryCreateRequest represents the request for creating news stories.
type StoryCreateRequest struct {
	Title      string             `json:"title" binding:"required,notblank,max=500"`
	Text       string             `json:"text" binding:"required,notblank"`
	VoiceID    *int64             `json:"voice_id" binding:"omitempty,min=1"`
	Status     string             `json:"status" binding:"omitempty,story_status"`
	StartDate  string             `json:"start_date" binding:"required,dateformat"`
	EndDate    string             `json:"end_date" binding:"required,dateformat,dateafter=StartDate"`
	Weekdays   models.Weekdays    `json:"weekdays"`    // Bitmask (0-127): Sun=1 Mon=2 Tue=4 Wed=8 Thu=16 Fri=32 Sat=64
	IsBreaking bool               `json:"is_breaking"` // Breaking stories are prioritized for inclusion in bulletins
	Metadata   *datatypes.JSONMap `json:"metadata,omitempty"`
}

// NormalizeText decodes HTML entities in text fields to plain Unicode.
func (r *StoryCreateRequest) NormalizeText() {
	r.Title = html.UnescapeString(r.Title)
	r.Text = html.UnescapeString(r.Text)
}

// StoryUpdateRequest represents the request for updating existing stories.
type StoryUpdateRequest struct {
	Title      *string            `json:"title" binding:"omitempty,notblank,max=500"`
	Text       *string            `json:"text" binding:"omitempty,notblank"`
	VoiceID    *int64             `json:"voice_id" binding:"omitempty,min=1"`
	Status     *string            `json:"status" binding:"omitempty,story_status"`
	StartDate  *string            `json:"start_date" binding:"omitempty,dateformat"`
	EndDate    *string            `json:"end_date" binding:"omitempty,dateformat"`
	Weekdays   *models.Weekdays   `json:"weekdays"`    // Bitmask (0-127): Sun=1 Mon=2 Tue=4 Wed=8 Thu=16 Fri=32 Sat=64
	IsBreaking *bool              `json:"is_breaking"` // Breaking stories are prioritized for inclusion in bulletins
	Metadata   *datatypes.JSONMap `json:"metadata,omitempty"`
}

// TTSSettingsUpdateRequest represents a partial update to global TTS settings.
type TTSSettingsUpdateRequest struct {
	Model                  *string         `json:"model"`
	Stability              *float64        `json:"stability"`
	SimilarityBoost        *float64        `json:"similarity_boost"`
	Style                  *float64        `json:"style"`
	UseSpeakerBoost        *bool           `json:"use_speaker_boost"`
	Speed                  *float64        `json:"speed"`
	ApplyTextNormalization *string         `json:"apply_text_normalization"`
	Seed                   Optional[int64] `json:"seed"`
	TTSStylePrefix         *string         `json:"tts_style_prefix"`
}

// IsEmpty reports whether no update fields were provided.
// Keep in sync with services.UpdateTTSSettingsRequest.IsEmpty.
func (r *TTSSettingsUpdateRequest) IsEmpty() bool {
	return r.Model == nil &&
		r.Stability == nil &&
		r.SimilarityBoost == nil &&
		r.Style == nil &&
		r.UseSpeakerBoost == nil &&
		r.Speed == nil &&
		r.ApplyTextNormalization == nil &&
		!r.Seed.Set &&
		r.TTSStylePrefix == nil
}

// NormalizeText decodes HTML entities in text fields to plain Unicode.
func (r *StoryUpdateRequest) NormalizeText() {
	if r.Title != nil {
		normalized := html.UnescapeString(*r.Title)
		r.Title = &normalized
	}
	if r.Text != nil {
		normalized := html.UnescapeString(*r.Text)
		r.Text = &normalized
	}
}

// textNormalizer is implemented by request structs that need text normalization
// (e.g. HTML entity decoding) before validation runs. Currently only story
// requests need this, as story content often originates from CMS integrations.
type textNormalizer interface {
	NormalizeText()
}

// BindAndValidate decodes a JSON request, normalizes text fields, then validates.
// Normalization runs before validation so that validators like notblank and max
// operate on the decoded values rather than the raw encoded input.
func BindAndValidate(c *gin.Context, req any) bool {
	// Step 1: Decode JSON without validation
	if err := json.NewDecoder(c.Request.Body).Decode(req); err != nil {
		ProblemValidationError(c, "The request contains invalid data", []apperrors.ValidationError{
			{Field: "request", Message: "Invalid request format"},
		})
		return false
	}

	// Step 2: Normalize text fields (e.g. unescape HTML entities)
	if n, ok := req.(textNormalizer); ok {
		n.NormalizeText()
	}

	// Step 3: Validate using Gin's registered validators (including custom ones)
	v, ok := binding.Validator.Engine().(*validator.Validate)
	if !ok {
		logger.Error("Validator engine is not *validator.Validate", "type", fmt.Sprintf("%T", binding.Validator.Engine()))
		ProblemInternalServer(c, "Internal validation error")
		return false
	}
	if err := v.Struct(req); err != nil {
		validationErrors := convertValidationErrors(err)
		ProblemValidationError(c, "The request contains invalid data", validationErrors)
		return false
	}

	return true
}

// BindOptionalJSON decodes an optional JSON body into req. Empty or
// whitespace-only bodies are accepted (req is left at its zero value). Returns
// false (and writes a Problem response) on oversized bodies, read failures, or
// invalid JSON. Parse failures include the underlying error in the response so
// clients can locate the offending token.
func BindOptionalJSON(c *gin.Context, req any) bool {
	if c == nil || c.Request == nil || c.Request.Body == nil {
		return true
	}

	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxJSONRequestBodyBytes))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			ProblemCustom(c,
				"https://babbel.api/problems/payload-too-large",
				"Payload Too Large",
				http.StatusRequestEntityTooLarge,
				"Request body too large",
			)
			return false
		}
		ProblemBadRequest(c, fmt.Sprintf("Failed to read request body: %s", err.Error()))
		return false
	}

	if strings.TrimSpace(string(body)) == "" {
		return true
	}

	if err := json.Unmarshal(body, req); err != nil {
		ProblemValidationError(c, "The request contains invalid data", []apperrors.ValidationError{
			{Field: "request", Message: err.Error()},
		})
		return false
	}

	return true
}

// formatValidationMessage generates a user-friendly error message for a validation failure.
func formatValidationMessage(field, tag, param string) string {
	switch tag {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "min":
		if param == "1" {
			return fmt.Sprintf("%s cannot be empty", field)
		}
		return fmt.Sprintf("%s must be at least %s characters", field, param)
	case "max":
		return fmt.Sprintf("%s cannot exceed %s characters", field, param)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "gte":
		return fmt.Sprintf("%s must be at least %s", field, param)
	case "lte":
		return fmt.Sprintf("%s must be at most %s", field, param)
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, param)
	case "alphanum":
		return fmt.Sprintf("%s can only contain letters and numbers", field)
	case "json":
		return fmt.Sprintf("%s must be valid JSON", field)
	case "notblank":
		return fmt.Sprintf("%s cannot be empty or whitespace only", field)
	case "story_status":
		return fmt.Sprintf("%s must be one of: %s, %s, %s",
			field, models.StoryStatusDraft, models.StoryStatusActive, models.StoryStatusExpired)
	case "dateformat":
		return fmt.Sprintf("%s must be in YYYY-MM-DD format", field)
	case "dateafter":
		return fmt.Sprintf("%s must be after or equal to %s", field, param)
	default:
		return fmt.Sprintf("%s failed validation (%s)", field, tag)
	}
}

// convertValidationErrors converts Go validator errors into structured error messages.
func convertValidationErrors(err error) []apperrors.ValidationError {
	validationErrors, ok := errors.AsType[validator.ValidationErrors](err)
	if !ok {
		return []apperrors.ValidationError{{
			Field:   "request",
			Message: "Invalid request format",
		}}
	}

	validationErrs := make([]apperrors.ValidationError, 0, len(validationErrors))
	for _, e := range validationErrors {
		validationErrs = append(validationErrs, apperrors.ValidationError{
			Field:   e.Field(),
			Message: formatValidationMessage(e.Field(), e.Tag(), e.Param()),
		})
	}

	return validationErrs
}
