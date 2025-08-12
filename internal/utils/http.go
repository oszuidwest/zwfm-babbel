package utils

import (
	"database/sql"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// GetIDParam extracts and validates ID parameter
func GetIDParam(c *gin.Context) (int, bool) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID parameter"})
		return 0, false
	}
	return id, true
}

// ValidateResourceExists checks if a record exists and responds with 404 error if not
func ValidateResourceExists(c *gin.Context, db *sqlx.DB, tableName, resourceName string, id int) bool {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM " + tableName + " WHERE id = ?)"
	if err := db.Get(&exists, query, id); err != nil || !exists {
		NotFound(c, resourceName)
		return false
	}
	return true
}

// CheckUnique validates uniqueness for common fields
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

// GetPagination extracts limit and offset from query parameters
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


// ParseFormDate parses date from form with consistent error handling
func ParseFormDate(c *gin.Context, fieldName, fieldLabel string) (time.Time, bool) {
	dateStr := c.PostForm(fieldName)
	if dateStr == "" {
		return time.Time{}, true // empty is ok for updates
	}

	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid %s format", strings.ToLower(fieldLabel))})
		return time.Time{}, false
	}

	return date, true
}

// ParseRequiredFormDate parses required date from form with consistent error handling
func ParseRequiredFormDate(c *gin.Context, fieldName, fieldLabel string) (time.Time, bool) {
	dateStr := c.PostForm(fieldName)
	if dateStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("%s is required", fieldLabel)})
		return time.Time{}, false
	}

	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid %s format", strings.ToLower(fieldLabel))})
		return time.Time{}, false
	}

	return date, true
}

// WeekdayStringToBitmask converts weekday string to bitmask
func WeekdayStringToBitmask(weekday string) uint8 {
	weekdayMap := map[string]uint8{
		"monday":    models.Monday,
		"tuesday":   models.Tuesday,
		"wednesday": models.Wednesday,
		"thursday":  models.Thursday,
		"friday":    models.Friday,
		"saturday":  models.Saturday,
		"sunday":    models.Sunday,
	}
	return weekdayMap[strings.ToLower(weekday)]
}

// ValidateAndSaveAudioFile validates audio file and saves to temp location
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

// ValidateAudioFile validates audio file type and size
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

// SanitizeFilename removes unsafe characters from filename
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
	Name               string  `json:"name" binding:"required,min=1,max=255"`
	MaxStoriesPerBlock int     `json:"max_stories_per_block" binding:"gte=1,lte=50"`
	PauseSeconds       float64 `json:"pause_seconds" binding:"gte=0,lte=60"`
}

// VoiceRequest represents the request structure for creating/updating voices
type VoiceRequest struct {
	Name string `json:"name" binding:"required,min=1,max=255"`
}

// UserCreateRequest represents the request structure for creating users
type UserCreateRequest struct {
	Username string  `json:"username" binding:"required,min=3,max=100,alphanum"`
	FullName string  `json:"full_name" binding:"required,min=1,max=255"`
	Password string  `json:"password" binding:"required,min=8,max=128"`
	Email    *string `json:"email" binding:"omitempty,email,max=255"`
	Role     string  `json:"role" binding:"required,oneof=admin editor viewer"`
	Metadata string  `json:"metadata" binding:"omitempty,json"`
}

// UserUpdateRequest represents the request structure for updating users
type UserUpdateRequest struct {
	Username string  `json:"username" binding:"omitempty,min=3,max=100,alphanum"`
	FullName string  `json:"full_name" binding:"omitempty,min=1,max=255"`
	Email    *string `json:"email" binding:"omitempty,email,max=255"`
	Role     string  `json:"role" binding:"omitempty,oneof=admin editor viewer"`
	Metadata string  `json:"metadata" binding:"omitempty,json"`
}

// StationVoiceRequest represents the request structure for creating/updating station-voice relationships
type StationVoiceRequest struct {
	StationID int     `json:"station_id" binding:"required,min=1"`
	VoiceID   int     `json:"voice_id" binding:"required,min=1"`
	MixPoint  float64 `json:"mix_point" binding:"gte=0,lte=300"`
}

// BindAndValidate handles JSON binding with developer-friendly error messages
func BindAndValidate(c *gin.Context, req interface{}) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		errorDetails := formatValidationErrors(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Validation failed",
			"details": errorDetails,
		})
		return false
	}
	return true
}

// formatValidationErrors converts validation errors to developer-friendly messages
func formatValidationErrors(err error) []string {
	var errors []string

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, e := range validationErrors {
			field := e.Field()
			tag := e.Tag()
			param := e.Param()

			switch tag {
			case "required":
				errors = append(errors, fmt.Sprintf("%s is required", field))
			case "min":
				if param == "1" {
					errors = append(errors, fmt.Sprintf("%s cannot be empty", field))
				} else {
					errors = append(errors, fmt.Sprintf("%s must be at least %s characters", field, param))
				}
			case "max":
				errors = append(errors, fmt.Sprintf("%s cannot exceed %s characters", field, param))
			case "email":
				errors = append(errors, fmt.Sprintf("%s must be a valid email address", field))
			case "gte":
				errors = append(errors, fmt.Sprintf("%s must be at least %s", field, param))
			case "lte":
				errors = append(errors, fmt.Sprintf("%s must be at most %s", field, param))
			case "oneof":
				errors = append(errors, fmt.Sprintf("%s must be one of: %s", field, param))
			case "alphanum":
				errors = append(errors, fmt.Sprintf("%s can only contain letters and numbers", field))
			case "json":
				errors = append(errors, fmt.Sprintf("%s must be valid JSON", field))
			default:
				errors = append(errors, fmt.Sprintf("%s failed validation (%s)", field, tag))
			}
		}
	} else {
		errors = append(errors, "Invalid JSON format")
	}

	return errors
}

// GenericList handles paginated list requests for any table
func GenericList(c *gin.Context, db *sqlx.DB, tableName string, selectFields string, result interface{}) {
	limit, offset := GetPagination(c)

	// Get total count
	total, err := CountRecords(db, tableName, "")
	if err != nil {
		InternalServerError(c, fmt.Sprintf("Failed to count %s", tableName))
		return
	}

	// Get paginated data
	query := fmt.Sprintf("SELECT %s FROM %s ORDER BY name ASC LIMIT ? OFFSET ?", selectFields, tableName)
	if err := db.Select(result, query, limit, offset); err != nil {
		InternalServerError(c, fmt.Sprintf("Failed to fetch %s", tableName))
		return
	}

	PaginatedResponse(c, result, total, limit, offset)
}

// GenericGetByID handles get-by-ID requests for any table
func GenericGetByID(c *gin.Context, db *sqlx.DB, tableName, resourceName string, result interface{}) {
	id, ok := GetIDParam(c)
	if !ok {
		return
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", tableName)
	if err := db.Get(result, query, id); err != nil {
		if err == sql.ErrNoRows {
			NotFound(c, resourceName)
		} else {
			InternalServerError(c, fmt.Sprintf("Failed to fetch %s", strings.ToLower(resourceName)))
		}
		return
	}

	Success(c, result)
}
