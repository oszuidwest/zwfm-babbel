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
	"gorm.io/gorm"
)

// IDParam extracts and validates the ID parameter from the request URL.
// Returns the ID as int64 and a boolean indicating success.
// Automatically responds with 400 Bad Request if the ID is invalid or non-positive.
func IDParam(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		ProblemBadRequest(c, "Invalid ID parameter")
		return 0, false
	}
	return id, true
}

// GormValidateStationExists checks if a station exists by ID using GORM.
func GormValidateStationExists(c *gin.Context, db *gorm.DB, id int64) bool {
	var count int64
	if err := db.Model(&models.Station{}).Where("id = ?", id).Count(&count).Error; err != nil || count == 0 {
		ProblemNotFound(c, "Station")
		return false
	}
	return true
}

// GormValidateStoryExists checks if a story exists by ID using GORM.
func GormValidateStoryExists(c *gin.Context, db *gorm.DB, id int64) bool {
	var count int64
	if err := db.Model(&models.Story{}).Where("id = ?", id).Count(&count).Error; err != nil || count == 0 {
		ProblemNotFound(c, "Story")
		return false
	}
	return true
}

// GormValidateBulletinExists checks if a bulletin exists by ID using GORM.
func GormValidateBulletinExists(c *gin.Context, db *gorm.DB, id int64) bool {
	var count int64
	if err := db.Model(&models.Bulletin{}).Where("id = ?", id).Count(&count).Error; err != nil || count == 0 {
		ProblemNotFound(c, "Bulletin")
		return false
	}
	return true
}

// Pagination extracts pagination parameters from query string with validation.
// Returns limit (default 20, max 100) and offset (default 0, min 0).
// Invalid values are ignored and defaults are used instead.
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
func ValidateDateRange(startStr, endStr string) (time.Time, time.Time, error) {
	start, err := time.Parse("2006-01-02", startStr)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid start_date: %w", err)
	}
	end, err := time.Parse("2006-01-02", endStr)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid end_date: %w", err)
	}
	if end.Before(start) {
		return time.Time{}, time.Time{}, errors.New("end_date cannot be before start_date")
	}
	return start, end, nil
}

// ValidateAndSaveAudioFile validates an uploaded audio file and saves it to a temporary location.
// Performs security checks on file type, size, and filename.
// Returns the temporary file path, a cleanup function, and any validation errors.
// The cleanup function should always be called to prevent resource leaks.
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

// ValidateAudioFile validates an uploaded audio file against security and format constraints.
// Checks file size (max 100MB) and allowed extensions (.wav, .mp3, .m4a, .aac, .ogg, .flac, .opus).
// Returns an error if the file fails validation requirements.
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

// SanitizeFilename removes unsafe characters from filenames to prevent security vulnerabilities.
// Strips path separators and replaces spaces with underscores.
// Essential for preventing path traversal attacks when handling user uploads.
func SanitizeFilename(filename string) string {
	// Remove path separators and other unsafe characters
	filename = filepath.Base(filename)
	filename = strings.ReplaceAll(filename, " ", "_")
	return filename
}

// saveFileToPath saves an uploaded multipart file to the specified filesystem path.
// Used internally by ValidateAndSaveAudioFile for secure file operations.
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

// StationRequest represents the request structure for creating and updating radio stations.
// Contains broadcast configuration including content limits and pause intervals.
type StationRequest struct {
	Name               string  `json:"name" binding:"required,notblank,max=255"`
	MaxStoriesPerBlock int     `json:"max_stories_per_block" binding:"gte=1,lte=50"`
	PauseSeconds       float64 `json:"pause_seconds" binding:"gte=0,lte=60"`
}

// VoiceRequest represents the request structure for creating and updating voices.
// Voices are used for text-to-speech generation and jingle association.
type VoiceRequest struct {
	Name string `json:"name" binding:"required,notblank,max=255"`
}

// StationVoiceRequest represents the request structure for creating station-voice relationships.
// Links stations to voices with specific mix points for jingle integration.
// Used for multipart form data when uploading jingle audio files.
type StationVoiceRequest struct {
	StationID int64   `json:"station_id" form:"station_id" binding:"required,min=1"`
	VoiceID   int64   `json:"voice_id" form:"voice_id" binding:"required,min=1"`
	MixPoint  float64 `json:"mix_point" form:"mix_point" binding:"gte=0,lte=300"`
}

// StationVoiceUpdateRequest represents the request structure for updating station-voice relationships.
// All fields are optional pointers to support partial updates.
// Used for multipart form data when updating jingle audio files.
type StationVoiceUpdateRequest struct {
	StationID *int64   `json:"station_id,omitempty" form:"station_id" binding:"omitempty,min=1"`
	VoiceID   *int64   `json:"voice_id,omitempty" form:"voice_id" binding:"omitempty,min=1"`
	MixPoint  *float64 `json:"mix_point,omitempty" form:"mix_point" binding:"omitempty,gte=0,lte=300"`
}

// UserCreateRequest represents the request structure for creating new user accounts.
// Supports local authentication with role-based access control.
// Password field is required and will be bcrypt hashed before storage.
type UserCreateRequest struct {
	Username string  `json:"username" binding:"required,min=3,max=100,alphanum"`
	FullName string  `json:"full_name" binding:"required,notblank,max=255"`
	Password string  `json:"password" binding:"required,min=8,max=128"`
	Email    *string `json:"email" binding:"omitempty,email,max=255"`
	Role     string  `json:"role" binding:"required,oneof=admin editor viewer"`
	Metadata string  `json:"metadata" binding:"omitempty,json"`
}

// UserUpdateRequest represents the request structure for updating existing user accounts.
// All fields are optional to support partial updates.
// Password field, if provided, will be bcrypt hashed before storage.
type UserUpdateRequest struct {
	Username  string  `json:"username" binding:"omitempty,min=3,max=100,alphanum"`
	FullName  string  `json:"full_name" binding:"omitempty,notblank,max=255"`
	Email     *string `json:"email" binding:"omitempty,email,max=255"`
	Password  string  `json:"password" binding:"omitempty,min=8,max=255"`
	Role      string  `json:"role" binding:"omitempty,oneof=admin editor viewer"`
	Metadata  string  `json:"metadata" binding:"omitempty,json"`
	Suspended *bool   `json:"suspended" binding:"omitempty"`
}

// StoryCreateRequest represents the request structure for creating news stories.
// Supports both JSON and multipart form data for text content and optional audio upload.
// Includes scheduling configuration with weekday selection and date ranges.
type StoryCreateRequest struct {
	Title     string          `json:"title" form:"title" binding:"required,notblank,max=500"`
	Text      string          `json:"text" form:"text" binding:"required,notblank"`
	VoiceID   *int64          `json:"voice_id" form:"voice_id" binding:"omitempty,min=1"`
	Status    string          `json:"status" form:"status" binding:"omitempty,story_status"`
	StartDate string          `json:"start_date" form:"start_date" binding:"required,dateformat"`
	EndDate   string          `json:"end_date" form:"end_date" binding:"required,dateformat,dateafter=StartDate"`
	Monday    bool            `json:"monday" form:"monday"`
	Tuesday   bool            `json:"tuesday" form:"tuesday"`
	Wednesday bool            `json:"wednesday" form:"wednesday"`
	Thursday  bool            `json:"thursday" form:"thursday"`
	Friday    bool            `json:"friday" form:"friday"`
	Saturday  bool            `json:"saturday" form:"saturday"`
	Sunday    bool            `json:"sunday" form:"sunday"`
	Weekdays  map[string]bool `json:"weekdays" form:"-"` // Only for JSON, ignored in form data
	Metadata  *string         `json:"metadata" form:"metadata"`
}

// StoryUpdateRequest represents the request structure for updating existing stories.
// All fields are optional pointers to support partial updates.
// Supports both JSON and multipart form data for content and audio updates.
type StoryUpdateRequest struct {
	Title     *string         `json:"title" form:"title" binding:"omitempty,notblank,max=500"`
	Text      *string         `json:"text" form:"text" binding:"omitempty,notblank"`
	VoiceID   *int64          `json:"voice_id" form:"voice_id" binding:"omitempty,min=1"`
	Status    *string         `json:"status" form:"status" binding:"omitempty,story_status"`
	StartDate *string         `json:"start_date" form:"start_date" binding:"omitempty,dateformat"`
	EndDate   *string         `json:"end_date" form:"end_date" binding:"omitempty,dateformat"`
	Monday    *bool           `json:"monday" form:"monday"`
	Tuesday   *bool           `json:"tuesday" form:"tuesday"`
	Wednesday *bool           `json:"wednesday" form:"wednesday"`
	Thursday  *bool           `json:"thursday" form:"thursday"`
	Friday    *bool           `json:"friday" form:"friday"`
	Saturday  *bool           `json:"saturday" form:"saturday"`
	Sunday    *bool           `json:"sunday" form:"sunday"`
	Weekdays  map[string]bool `json:"weekdays" form:"-"` // Only for JSON, ignored in form data
	Metadata  *string         `json:"metadata" form:"metadata"`
}

// ValidateDateRange validates that the story's end date is not before the start date.
// Used for story creation requests to ensure logical date ranges.
// Returns an error if dates are invalid, nil if validation passes or dates are missing.
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

// ValidateDateRange validates date ranges for story update requests.
// Only validates when both start and end dates are provided in the update.
// Returns an error if end date is before start date, nil otherwise.
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

// BindAndValidate handles JSON request binding with comprehensive validation and error reporting.
// Converts validation errors into user-friendly messages with field-level detail.
// Always returns 422 Unprocessable Entity for validation failures with structured error responses.
func BindAndValidate(c *gin.Context, req any) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		validationErrors := convertValidationErrors(err)
		ProblemValidationError(c, "The request contains invalid data", validationErrors)
		return false
	}
	return true
}

// BindFormAndValidate handles both JSON and form data binding with automatic content type detection.
// Supports multipart/form-data, application/x-www-form-urlencoded, and application/json.
// Provides unified validation error handling across all content types.
// Returns 422 Unprocessable Entity for validation failures.
func BindFormAndValidate(c *gin.Context, req any) bool {
	contentType := c.GetHeader("Content-Type")
	var err error

	if strings.Contains(contentType, "application/json") {
		err = c.ShouldBindJSON(req)
	} else {
		// Handle form data (multipart/form-data or application/x-www-form-urlencoded)
		err = c.ShouldBind(req)
	}

	if err != nil {
		validationErrors := convertValidationErrors(err)
		ProblemValidationError(c, "The request contains invalid data", validationErrors)
		return false
	}
	return true
}

// formatValidationMessage generates a user-friendly error message for a specific validation failure.
// Maps validation tags to human-readable descriptions with field and parameter context.
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

// convertValidationErrors converts Go validator errors into structured, user-friendly error messages.
// Maps validation tags to human-readable descriptions with field context.
// Used internally by binding functions to provide consistent error responses.
func convertValidationErrors(err error) []ValidationError {
	var errors []ValidationError

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, e := range validationErrors {
			errors = append(errors, ValidationError{
				Field:   e.Field(),
				Message: formatValidationMessage(e.Field(), e.Tag(), e.Param()),
			})
		}
	} else {
		errors = append(errors, ValidationError{
			Field:   "request",
			Message: "Invalid request format",
		})
	}

	return errors
}
