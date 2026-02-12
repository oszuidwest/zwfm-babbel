// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/datatypes"
)

// IDParam extracts and validates the ID parameter from the request URL.
func IDParam(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		ProblemBadRequest(c, "Invalid ID parameter")
		return 0, false
	}
	return id, true
}

// Pagination extracts pagination parameters from the query string.
func Pagination(c *gin.Context) (limit, offset int) {
	limit = 20 // default
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	if o, err := strconv.Atoi(c.Query("offset")); err == nil && o >= 0 {
		offset = o
	}
	return
}

// ValidateDateRange parses start and end date strings and validates the range.
// Uses local timezone for consistent date handling across the application.
func ValidateDateRange(startStr, endStr string) (time.Time, time.Time, error) {
	start, err := time.ParseInLocation("2006-01-02", startStr, time.Local)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid start_date: %w", err)
	}
	end, err := time.ParseInLocation("2006-01-02", endStr, time.Local)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid end_date: %w", err)
	}
	if end.Before(start) {
		return time.Time{}, time.Time{}, errors.New("end_date cannot be before start_date")
	}
	return start, end, nil
}

// ValidateAndSaveAudioFile validates an uploaded audio file and saves it to a temporary location.
func ValidateAndSaveAudioFile(c *gin.Context, fieldName string, prefix string) (tempPath string, cleanup func() error, err error) {
	file, header, err := c.Request.FormFile(fieldName)
	if err != nil {
		return "", nil, err
	}

	if err := ValidateAudioFile(header); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn("Failed to close file during validation error: %v", closeErr)
		}
		return "", nil, fmt.Errorf("invalid audio file: %w", err)
	}

	safeFilename := SanitizeFilename(header.Filename)
	tempPath = filepath.Join(os.TempDir(), fmt.Sprintf("%s_%s", prefix, safeFilename))

	if err := saveFileToPath(file, tempPath); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn("Failed to close file during save error: %v", closeErr)
		}
		return "", nil, err
	}

	cleanup = func() error {
		var errs []error
		if err := file.Close(); err != nil {
			logger.Warn("Failed to close uploaded file during cleanup: %v", err)
			errs = append(errs, err)
		}
		if err := os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove temp file %s: %v", tempPath, err)
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
			logger.Error("Failed to close output file: %v", err)
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

// VoiceRequest represents the request for creating and updating voices.
type VoiceRequest struct {
	Name              string  `json:"name" binding:"required,notblank,max=255"`
	ElevenLabsVoiceID *string `json:"elevenlabs_voice_id" binding:"omitempty,max=255"`
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
	Title     string             `json:"title" binding:"required,notblank,max=500"`
	Text      string             `json:"text" binding:"required,notblank"`
	VoiceID   *int64             `json:"voice_id" binding:"omitempty,min=1"`
	Status    string             `json:"status" binding:"omitempty,story_status"`
	StartDate string             `json:"start_date" binding:"required,dateformat"`
	EndDate   string             `json:"end_date" binding:"required,dateformat,dateafter=StartDate"`
	Weekdays  models.Weekdays    `json:"weekdays"` // Bitmask integer (0-127): Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64
	Metadata  *datatypes.JSONMap `json:"metadata,omitempty"`
}

// StoryUpdateRequest represents the request for updating existing stories.
type StoryUpdateRequest struct {
	Title     *string            `json:"title" binding:"omitempty,notblank,max=500"`
	Text      *string            `json:"text" binding:"omitempty,notblank"`
	VoiceID   *int64             `json:"voice_id" binding:"omitempty,min=1"`
	Status    *string            `json:"status" binding:"omitempty,story_status"`
	StartDate *string            `json:"start_date" binding:"omitempty,dateformat"`
	EndDate   *string            `json:"end_date" binding:"omitempty,dateformat"`
	Weekdays  *models.Weekdays   `json:"weekdays"` // Bitmask integer (0-127): Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64
	Metadata  *datatypes.JSONMap `json:"metadata,omitempty"`
}

// ValidateDateRange validates that end date is not before start date.
func (req *StoryCreateRequest) ValidateDateRange() error {
	if req.StartDate == "" || req.EndDate == "" {
		return nil // Individual date validation will catch required field errors
	}

	_, _, err := ValidateDateRange(req.StartDate, req.EndDate)
	// Ignore parse errors as they will be caught by date format validators
	// Only return range validation errors
	if err != nil && strings.Contains(err.Error(), "end_date cannot be before start_date") {
		return err
	}

	return nil
}

// ValidateDateRange validates that end date is not before start date.
func (req *StoryUpdateRequest) ValidateDateRange() error {
	// Only validate if both dates are provided
	if req.StartDate == nil || req.EndDate == nil {
		return nil
	}

	_, _, err := ValidateDateRange(*req.StartDate, *req.EndDate)
	// Ignore parse errors as they will be caught by date format validators
	// Only return range validation errors
	if err != nil && strings.Contains(err.Error(), "end_date cannot be before start_date") {
		return err
	}

	return nil
}

// BindAndValidate binds and validates a JSON request.
func BindAndValidate(c *gin.Context, req any) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		validationErrors := convertValidationErrors(err)
		ProblemValidationError(c, "The request contains invalid data", validationErrors)
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
		return fmt.Sprintf("%s must be one of: %s, %s, %s", field, models.StoryStatusDraft, models.StoryStatusActive, models.StoryStatusExpired)
	case "dateformat":
		return fmt.Sprintf("%s must be in YYYY-MM-DD format", field)
	case "dateafter":
		return fmt.Sprintf("%s must be after or equal to %s", field, param)
	default:
		return fmt.Sprintf("%s failed validation (%s)", field, tag)
	}
}

// convertValidationErrors converts Go validator errors into structured error messages.
func convertValidationErrors(err error) []ValidationError {
	var validationErrs []ValidationError

	if validationErrors, ok := errors.AsType[validator.ValidationErrors](err); ok {
		for _, e := range validationErrors {
			validationErrs = append(validationErrs, ValidationError{
				Field:   e.Field(),
				Message: formatValidationMessage(e.Field(), e.Tag(), e.Param()),
			})
		}
	} else {
		validationErrs = append(validationErrs, ValidationError{
			Field:   "request",
			Message: "Invalid request format",
		})
	}

	return validationErrs
}
