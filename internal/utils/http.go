// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"database/sql"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// GetIDParam extracts and validates the ID parameter from the request URL.
func GetIDParam(c *gin.Context) (int, bool) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		ProblemBadRequest(c, "Invalid ID parameter")
		return 0, false
	}
	return id, true
}

// ValidateResourceExists checks if a record exists and responds with 404 error if not found.
func ValidateResourceExists(c *gin.Context, db *sqlx.DB, tableName, resourceName string, id int) bool {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM " + tableName + " WHERE id = ?)"
	if err := db.Get(&exists, query, id); err != nil || !exists {
		ProblemNotFound(c, resourceName)
		return false
	}
	return true
}

// CheckUnique validates uniqueness for common fields in database tables.
func CheckUnique(db *sqlx.DB, table, field string, value interface{}, excludeID *int) error {
	var count int
	var err error

	if excludeID != nil {
		condition := fmt.Sprintf("%s = ? AND id != ?", field)
		count, err = CountByCondition(db, table, condition, value, *excludeID)
	} else {
		condition := fmt.Sprintf("%s = ?", field)
		count, err = CountByCondition(db, table, condition, value)
	}

	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("%s already exists", field)
	}
	return nil
}

// GetPagination extracts limit and offset from query parameters with defaults and validation.
func GetPagination(c *gin.Context) (limit, offset int) {
	limit = 20 // default
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	if o, err := strconv.Atoi(c.Query("offset")); err == nil && o >= 0 {
		offset = o
	}
	return
}

// ParseFormDate parses date from form with consistent error handling and returns zero time if empty.
func ParseFormDate(c *gin.Context, fieldName, fieldLabel string) (time.Time, bool) {
	dateStr := c.PostForm(fieldName)
	if dateStr == "" {
		return time.Time{}, true // empty is ok for updates
	}

	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		ProblemValidationError(c, "Date validation failed", []ValidationError{
			{Field: fieldName, Message: fmt.Sprintf("Invalid %s format, use YYYY-MM-DD", strings.ToLower(fieldLabel))},
		})
		return time.Time{}, false
	}

	return date, true
}

// ParseRequiredFormDate parses required date from form with consistent error handling and returns error if empty.
func ParseRequiredFormDate(c *gin.Context, fieldName, fieldLabel string) (time.Time, bool) {
	dateStr := c.PostForm(fieldName)
	if dateStr == "" {
		ProblemValidationError(c, "Date validation failed", []ValidationError{
			{Field: fieldName, Message: fmt.Sprintf("%s is required", fieldLabel)},
		})
		return time.Time{}, false
	}

	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		ProblemValidationError(c, "Date validation failed", []ValidationError{
			{Field: fieldName, Message: fmt.Sprintf("Invalid %s format, use YYYY-MM-DD", strings.ToLower(fieldLabel))},
		})
		return time.Time{}, false
	}

	return date, true
}

// ValidateAndSaveAudioFile validates audio file and saves to temporary location with cleanup function.
func ValidateAndSaveAudioFile(c *gin.Context, fieldName string, prefix string) (tempPath string, cleanup func(), err error) {
	file, header, err := c.Request.FormFile(fieldName)
	if err != nil {
		return "", nil, err
	}

	if err := ValidateAudioFile(header); err != nil {
		_ = file.Close() // Ignore error on cleanup
		return "", nil, fmt.Errorf("invalid audio file: %w", err)
	}

	safeFilename := SanitizeFilename(header.Filename)
	tempPath = filepath.Join("/tmp", fmt.Sprintf("%s_%s", prefix, safeFilename))

	if err := saveFileToPath(file, tempPath); err != nil {
		_ = file.Close() // Ignore error on cleanup
		return "", nil, err
	}

	cleanup = func() {
		_ = file.Close()        // Ignore error on cleanup
		_ = os.Remove(tempPath) // Ignore error on cleanup
	}

	return tempPath, cleanup, nil
}

// ValidateAudioFile validates audio file type and size against allowed formats and limits.
func ValidateAudioFile(header *multipart.FileHeader) error {
	// Check file size (100MB max)
	const maxSize = 100 * 1024 * 1024
	if header.Size > maxSize {
		return fmt.Errorf("file too large (max 100MB)")
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	validExts := []string{".wav", ".mp3", ".m4a", ".aac", ".ogg", ".flac", ".opus"}

	for _, validExt := range validExts {
		if ext == validExt {
			return nil
		}
	}

	return fmt.Errorf("unsupported file type: %s", ext)
}

// SanitizeFilename removes unsafe characters from filename to prevent path traversal attacks.
func SanitizeFilename(filename string) string {
	// Remove path separators and other unsafe characters
	filename = filepath.Base(filename)
	filename = strings.ReplaceAll(filename, " ", "_")
	return filename
}

// SafeMoveFile safely moves a file from source to destination, handling cross-device scenarios
func SafeMoveFile(src, dst string) error {
	// First, try a simple rename (works if on same filesystem)
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// If rename failed, fall back to copy + delete
	// This handles cross-device moves (e.g., /tmp to Docker volume)

	// Open source file
	// #nosec G304 - src path is internally generated and validated
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() {
		_ = srcFile.Close() // Ignore error on cleanup
	}()

	// Create destination file
	// #nosec G304 - dst path is internally generated and validated
	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() {
		_ = dstFile.Close() // Ignore error on cleanup
	}()

	// Copy file contents
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		// If copy failed, clean up destination file
		_ = os.Remove(dst)
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	// Ensure data is written to disk
	if err := dstFile.Sync(); err != nil {
		// If sync failed, clean up destination file
		_ = os.Remove(dst)
		return fmt.Errorf("failed to sync destination file: %w", err)
	}

	// Copy succeeded, now remove source file
	if err := os.Remove(src); err != nil {
		// Log warning but don't fail - the copy succeeded
		// We use fmt.Printf since logger might not be available in utils
		fmt.Printf("Warning: failed to remove source file %s after successful copy: %v\n", src, err)
	}

	return nil
}

// saveFileToPath saves uploaded file to specified path
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

// StationRequest represents the request structure for creating/updating stations
type StationRequest struct {
	Name               string  `json:"name" binding:"required,notblank,max=255"`
	MaxStoriesPerBlock int     `json:"max_stories_per_block" binding:"gte=1,lte=50"`
	PauseSeconds       float64 `json:"pause_seconds" binding:"gte=0,lte=60"`
}

// VoiceRequest represents the request structure for creating/updating voices
type VoiceRequest struct {
	Name string `json:"name" binding:"required,notblank,max=255"`
}

// StationVoiceRequest represents the request structure for creating station-voice relationships
type StationVoiceRequest struct {
	StationID int     `json:"station_id" form:"station_id" binding:"required,min=1"`
	VoiceID   int     `json:"voice_id" form:"voice_id" binding:"required,min=1"`
	MixPoint  float64 `json:"mix_point" form:"mix_point" binding:"gte=0,lte=300"`
}

// StationVoiceUpdateRequest represents the request structure for updating station-voice relationships
type StationVoiceUpdateRequest struct {
	StationID *int     `json:"station_id,omitempty" form:"station_id" binding:"omitempty,min=1"`
	VoiceID   *int     `json:"voice_id,omitempty" form:"voice_id" binding:"omitempty,min=1"`
	MixPoint  *float64 `json:"mix_point,omitempty" form:"mix_point" binding:"omitempty,gte=0,lte=300"`
}

// UserCreateRequest represents the request structure for creating users
type UserCreateRequest struct {
	Username string  `json:"username" binding:"required,min=3,max=100,alphanum"`
	FullName string  `json:"full_name" binding:"required,notblank,max=255"`
	Password string  `json:"password" binding:"required,min=8,max=128"`
	Email    *string `json:"email" binding:"omitempty,email,max=255"`
	Role     string  `json:"role" binding:"required,oneof=admin editor viewer"`
	Metadata string  `json:"metadata" binding:"omitempty,json"`
}

// UserUpdateRequest represents the request structure for updating users
type UserUpdateRequest struct {
	Username  string  `json:"username" binding:"omitempty,min=3,max=100,alphanum"`
	FullName  string  `json:"full_name" binding:"omitempty,notblank,max=255"`
	Email     *string `json:"email" binding:"omitempty,email,max=255"`
	Password  string  `json:"password" binding:"omitempty,min=8,max=255"`
	Role      string  `json:"role" binding:"omitempty,oneof=admin editor viewer"`
	Metadata  string  `json:"metadata" binding:"omitempty,json"`
	Suspended *bool   `json:"suspended" binding:"omitempty"`
}

// StoryCreateRequest represents the request structure for creating stories
type StoryCreateRequest struct {
	Title     string         `json:"title" form:"title" binding:"required,notblank,max=500"`
	Text      string         `json:"text" form:"text" binding:"required,notblank"`
	VoiceID   *int           `json:"voice_id" form:"voice_id" binding:"omitempty,min=1"`
	Status    string         `json:"status" form:"status" binding:"omitempty,story_status"`
	StartDate string         `json:"start_date" form:"start_date" binding:"required,dateformat"`
	EndDate   string         `json:"end_date" form:"end_date" binding:"required,dateformat,dateafter=StartDate"`
	Monday    bool           `json:"monday" form:"monday"`
	Tuesday   bool           `json:"tuesday" form:"tuesday"`
	Wednesday bool           `json:"wednesday" form:"wednesday"`
	Thursday  bool           `json:"thursday" form:"thursday"`
	Friday    bool           `json:"friday" form:"friday"`
	Saturday  bool           `json:"saturday" form:"saturday"`
	Sunday    bool           `json:"sunday" form:"sunday"`
	Weekdays  map[string]bool `json:"weekdays" form:"-"` // Only for JSON, ignored in form data
	Metadata  *string        `json:"metadata" form:"metadata"`
}

// StoryUpdateRequest represents the request structure for updating stories  
type StoryUpdateRequest struct {
	Title     *string         `json:"title" form:"title" binding:"omitempty,notblank,max=500"`
	Text      *string         `json:"text" form:"text" binding:"omitempty,notblank"`
	VoiceID   *int           `json:"voice_id" form:"voice_id" binding:"omitempty,min=1"`
	Status    *string        `json:"status" form:"status" binding:"omitempty,story_status"`
	StartDate *string        `json:"start_date" form:"start_date" binding:"omitempty,dateformat"`
	EndDate   *string        `json:"end_date" form:"end_date" binding:"omitempty,dateformat"`
	Monday    *bool          `json:"monday" form:"monday"`
	Tuesday   *bool          `json:"tuesday" form:"tuesday"`
	Wednesday *bool          `json:"wednesday" form:"wednesday"`
	Thursday  *bool          `json:"thursday" form:"thursday"`
	Friday    *bool          `json:"friday" form:"friday"`
	Saturday  *bool          `json:"saturday" form:"saturday"`
	Sunday    *bool          `json:"sunday" form:"sunday"`
	Weekdays  map[string]bool `json:"weekdays" form:"-"` // Only for JSON, ignored in form data
	Metadata  *string        `json:"metadata" form:"metadata"`
}

// ValidateDateRange validates that EndDate is after or equal to StartDate for story requests
func (req *StoryCreateRequest) ValidateDateRange() error {
	if req.StartDate == "" || req.EndDate == "" {
		return nil // Individual date validation will catch required field errors
	}
	
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return nil // Date format validation will catch this
	}
	
	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		return nil // Date format validation will catch this
	}
	
	if endDate.Before(startDate) {
		return fmt.Errorf("end date cannot be before start date")
	}
	
	return nil
}

// ValidateDateRange validates that EndDate is after or equal to StartDate for story update requests
func (req *StoryUpdateRequest) ValidateDateRange() error {
	// Only validate if both dates are provided
	if req.StartDate == nil || req.EndDate == nil {
		return nil
	}
	
	startDate, err := time.Parse("2006-01-02", *req.StartDate)
	if err != nil {
		return nil // Date format validation will catch this
	}
	
	endDate, err := time.Parse("2006-01-02", *req.EndDate)
	if err != nil {
		return nil // Date format validation will catch this
	}
	
	if endDate.Before(startDate) {
		return fmt.Errorf("end date cannot be before start date")
	}
	
	return nil
}

// BindAndValidate handles JSON binding with developer-friendly error messages and validation.
// Always returns 422 status code for validation errors.
func BindAndValidate(c *gin.Context, req interface{}) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		validationErrors := convertValidationErrors(err)
		ProblemValidationError(c, "The request contains invalid data", validationErrors)
		return false
	}
	return true
}

// BindFormAndValidate handles both JSON and form data binding with unified validation.
// Automatically detects content type and uses appropriate binding method.
// Always returns 422 status code for validation errors.
func BindFormAndValidate(c *gin.Context, req interface{}) bool {
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

// convertValidationErrors converts validation errors to ValidationError struct format
func convertValidationErrors(err error) []ValidationError {
	var errors []ValidationError

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, e := range validationErrors {
			field := e.Field()
			tag := e.Tag()
			param := e.Param()
			var message string

			switch tag {
			case "required":
				message = fmt.Sprintf("%s is required", field)
			case "min":
				if param == "1" {
					message = fmt.Sprintf("%s cannot be empty", field)
				} else {
					message = fmt.Sprintf("%s must be at least %s characters", field, param)
				}
			case "max":
				message = fmt.Sprintf("%s cannot exceed %s characters", field, param)
			case "email":
				message = fmt.Sprintf("%s must be a valid email address", field)
			case "gte":
				message = fmt.Sprintf("%s must be at least %s", field, param)
			case "lte":
				message = fmt.Sprintf("%s must be at most %s", field, param)
			case "oneof":
				message = fmt.Sprintf("%s must be one of: %s", field, param)
			case "alphanum":
				message = fmt.Sprintf("%s can only contain letters and numbers", field)
			case "json":
				message = fmt.Sprintf("%s must be valid JSON", field)
			case "notblank":
				message = fmt.Sprintf("%s cannot be empty or whitespace only", field)
			case "story_status":
				message = fmt.Sprintf("%s must be one of: draft, active, expired", field)
			case "dateformat":
				message = fmt.Sprintf("%s must be in YYYY-MM-DD format", field)
			case "dateafter":
				message = fmt.Sprintf("%s must be after or equal to %s", field, param)
			default:
				message = fmt.Sprintf("%s failed validation (%s)", field, tag)
			}
			
			errors = append(errors, ValidationError{
				Field:   field,
				Message: message,
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

// formatValidationErrors converts validation errors to developer-friendly messages
// Deprecated: Use convertValidationErrors instead for consistent error format
func formatValidationErrors(err error) []string {
	validationErrors := convertValidationErrors(err)
	messages := make([]string, len(validationErrors))
	for i, ve := range validationErrors {
		messages[i] = ve.Message
	}
	return messages
}

// GenericGetByID handles get-by-ID requests for any table with proper error handling.
func GenericGetByID(c *gin.Context, db *sqlx.DB, tableName, resourceName string, result interface{}) {
	id, ok := GetIDParam(c)
	if !ok {
		return
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", tableName)
	if err := db.Get(result, query, id); err != nil {
		if err == sql.ErrNoRows {
			ProblemNotFound(c, resourceName)
		} else {
			ProblemInternalServer(c, fmt.Sprintf("Failed to fetch %s", strings.ToLower(resourceName)))
		}
		return
	}

	Success(c, result)
}

// ParseRequiredIntForm parses required integer from form with consistent error handling and validation.
func ParseRequiredIntForm(c *gin.Context, field string) (int, bool) {
	valueStr := c.PostForm(field)
	if valueStr == "" {
		ProblemBadRequest(c, fmt.Sprintf("%s is required", cases.Title(language.English).String(strings.ReplaceAll(field, "_", " "))))
		return 0, false
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil || value <= 0 {
		ProblemBadRequest(c, fmt.Sprintf("Valid %s is required", strings.ToLower(strings.ReplaceAll(field, "_", " "))))
		return 0, false
	}

	return value, true
}

// ParseOptionalIntForm parses optional integer from form with consistent error handling, returning nil if empty.
func ParseOptionalIntForm(c *gin.Context, field string) (*int, error) {
	valueStr := c.PostForm(field)
	if valueStr == "" {
		return nil, nil // empty is ok for optional fields
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil || value <= 0 {
		return nil, fmt.Errorf("invalid %s", strings.ToLower(strings.ReplaceAll(field, "_", " ")))
	}

	return &value, nil
}

// ParseBoolForm parses boolean from form field with a default value.
func ParseBoolForm(c *gin.Context, field string, defaultValue bool) bool {
	valueStr := strings.ToLower(c.PostForm(field))
	if valueStr == "" {
		return defaultValue
	}

	// Accept various boolean representations
	return valueStr == "true" || valueStr == "1" || valueStr == "yes" || valueStr == "on"
}

// ParseFloatFormWithRange parses optional float from form with range validation between minVal and maxVal values.
func ParseFloatFormWithRange(c *gin.Context, field string, minVal, maxVal float64) (*float64, error) {
	valueStr := c.PostForm(field)
	if valueStr == "" {
		return nil, nil // empty is ok for optional fields
	}

	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid %s format", strings.ToLower(strings.ReplaceAll(field, "_", " ")))
	}

	if value < minVal || value > maxVal {
		return nil, fmt.Errorf("%s must be between %.1f and %.1f", strings.ToLower(strings.ReplaceAll(field, "_", " ")), minVal, maxVal)
	}

	return &value, nil
}
