// Package utils provides shared helpers for HTTP handlers, database access,
// and query parsing.
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
	"reflect"
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

// ValidateAndSaveAudioFile validates uploaded audio and stores it in a temp path.
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

// ValidateAudioFile enforces the upload size limit and accepted audio
// extensions before the file is written to permanent storage.
func ValidateAudioFile(header *multipart.FileHeader) error {
	const maxSize = 100 * 1024 * 1024
	if header.Size > maxSize {
		return fmt.Errorf("file too large (max 100MB)")
	}

	ext := strings.ToLower(filepath.Ext(header.Filename))
	validExts := []string{".wav", ".mp3", ".m4a", ".aac", ".ogg", ".flac", ".opus"}

	if !slices.Contains(validExts, ext) {
		return fmt.Errorf("unsupported file type: %s", ext)
	}
	return nil
}

// SanitizeFilename removes path components and replaces spaces for storage
// paths derived from user-provided filenames.
func SanitizeFilename(filename string) string {
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

// StationRequest is the JSON body for creating or replacing radio station
// settings.
type StationRequest struct {
	Name               string  `json:"name" binding:"required,notblank,max=255"`
	MaxStoriesPerBlock int     `json:"max_stories_per_block" binding:"gte=1,lte=50"`
	PauseSeconds       float64 `json:"pause_seconds" binding:"gte=0,lte=60"`
}

// VoiceRequest is the JSON body for creating a newsreader voice.
type VoiceRequest struct {
	Name              string  `json:"name" binding:"required,notblank,max=255"`
	ElevenLabsVoiceID *string `json:"elevenlabs_voice_id" binding:"omitempty,notblank,max=255"`
}

// VoiceUpdateRequest is the JSON body for partial voice updates.
// Name is omitted to skip updates; ElevenLabsVoiceID accepts JSON null to clear.
type VoiceUpdateRequest struct {
	Name              *string          `json:"name" binding:"omitempty,notblank,max=255"`
	ElevenLabsVoiceID Optional[string] `json:"elevenlabs_voice_id" binding:"omitempty,notblank,max=255"`
}

// StationVoiceRequest is the JSON body for linking a station to a voice.
type StationVoiceRequest struct {
	StationID int64   `json:"station_id" binding:"required,min=1"`
	VoiceID   int64   `json:"voice_id" binding:"required,min=1"`
	MixPoint  float64 `json:"mix_point" binding:"gte=0,lte=300"`
}

// StationVoiceUpdateRequest is the JSON body for partial station-voice updates.
type StationVoiceUpdateRequest struct {
	StationID *int64   `json:"station_id,omitempty" binding:"omitempty,min=1"`
	VoiceID   *int64   `json:"voice_id,omitempty" binding:"omitempty,min=1"`
	MixPoint  *float64 `json:"mix_point,omitempty" binding:"omitempty,gte=0,lte=300"`
}

// UserCreateRequest is the JSON body for creating local user accounts.
type UserCreateRequest struct {
	Username string             `json:"username" binding:"required,min=3,max=100,alphanum"`
	FullName string             `json:"full_name" binding:"required,notblank,max=255"`
	Password string             `json:"password" binding:"required,min=8,max=128"`
	Email    *string            `json:"email" binding:"omitempty,email,max=255"`
	Role     string             `json:"role" binding:"required,oneof=admin editor viewer"`
	Metadata *datatypes.JSONMap `json:"metadata,omitempty"`
}

// UserUpdateRequest is the JSON body for partial account updates.
type UserUpdateRequest struct {
	Username  string             `json:"username" binding:"omitempty,min=3,max=100,alphanum"`
	FullName  string             `json:"full_name" binding:"omitempty,notblank,max=255"`
	Email     *string            `json:"email" binding:"omitempty,email,max=255"`
	Password  string             `json:"password" binding:"omitempty,min=8,max=255"`
	Role      string             `json:"role" binding:"omitempty,oneof=admin editor viewer"`
	Metadata  *datatypes.JSONMap `json:"metadata,omitempty"`
	Suspended *bool              `json:"suspended" binding:"omitempty"`
}

// StoryCreateRequest is the JSON body for creating scheduled news stories.
type StoryCreateRequest struct {
	Title     string `json:"title" binding:"required,notblank,max=500"`
	Text      string `json:"text" binding:"required,notblank"`
	VoiceID   *int64 `json:"voice_id" binding:"omitempty,min=1"`
	Status    string `json:"status" binding:"omitempty,story_status"`
	StartDate string `json:"start_date" binding:"required,dateformat"`
	EndDate   string `json:"end_date" binding:"required,dateformat,dateafter=StartDate"`
	// Weekdays is a bitmask: Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64.
	Weekdays models.Weekdays `json:"weekdays"`
	// IsBreaking prioritizes the story for bulletin inclusion.
	IsBreaking bool               `json:"is_breaking"`
	Metadata   *datatypes.JSONMap `json:"metadata,omitempty"`
}

// NormalizeText decodes HTML entities in text fields to plain Unicode.
func (r *StoryCreateRequest) NormalizeText() {
	r.Title = html.UnescapeString(r.Title)
	r.Text = html.UnescapeString(r.Text)
}

// StoryUpdateRequest is the JSON body for partial story updates.
type StoryUpdateRequest struct {
	Title     *string `json:"title" binding:"omitempty,notblank,max=500"`
	Text      *string `json:"text" binding:"omitempty,notblank"`
	VoiceID   *int64  `json:"voice_id" binding:"omitempty,min=1"`
	Status    *string `json:"status" binding:"omitempty,story_status"`
	StartDate *string `json:"start_date" binding:"omitempty,dateformat"`
	EndDate   *string `json:"end_date" binding:"omitempty,dateformat"`
	// Weekdays is a bitmask: Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64.
	Weekdays *models.Weekdays `json:"weekdays"`
	// IsBreaking prioritizes the story for bulletin inclusion.
	IsBreaking *bool              `json:"is_breaking"`
	Metadata   *datatypes.JSONMap `json:"metadata,omitempty"`
}

// TTSSettingsUpdateRequest is the JSON body for partial global TTS settings
// updates.
type TTSSettingsUpdateRequest struct {
	Stability              *float64        `json:"stability"`
	SimilarityBoost        *float64        `json:"similarity_boost"`
	Style                  *float64        `json:"style"`
	Speed                  *float64        `json:"speed"`
	ApplyTextNormalization *string         `json:"apply_text_normalization"`
	Seed                   Optional[int64] `json:"seed"`
	TTSStylePrefix         *string         `json:"tts_style_prefix"`
}

// IsEmpty reports whether no update fields were provided.
// Keep in sync with services.UpdateTTSSettingsRequest.IsEmpty.
func (r *TTSSettingsUpdateRequest) IsEmpty() bool {
	return r.Stability == nil &&
		r.SimilarityBoost == nil &&
		r.Style == nil &&
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
	if err := newCappedJSONDecoder(c).Decode(req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			ProblemPayloadTooLarge(c)
			return false
		}
		ProblemValidationError(c, "The request contains invalid data", []apperrors.ValidationError{
			{Field: "request", Message: "Invalid request format"},
		})
		return false
	}

	return normalizeAndValidate(c, req)
}

// BindJSONStrict decodes JSON with unknown-field rejection, then normalizes and validates.
func BindJSONStrict(c *gin.Context, req any) bool {
	dec := newCappedJSONDecoder(c)
	dec.DisallowUnknownFields()

	if err := dec.Decode(req); err != nil {
		handleStrictJSONDecodeError(c, err)
		return false
	}

	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		ProblemBadRequestValidationError(
			c,
			"Request body contains invalid JSON",
			[]apperrors.ValidationError{{Field: "request", Message: "unexpected trailing content"}},
		)
		return false
	}

	return normalizeAndValidate(c, req)
}

func newCappedJSONDecoder(c *gin.Context) *json.Decoder {
	return json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, maxJSONRequestBodyBytes))
}

func normalizeAndValidate(c *gin.Context, req any) bool {
	if n, ok := req.(textNormalizer); ok {
		n.NormalizeText()
	}

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

func handleStrictJSONDecodeError(c *gin.Context, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		ProblemPayloadTooLarge(c)
		return
	}

	if errors.Is(err, io.EOF) {
		ProblemBadRequestValidationError(
			c,
			"Request body contains invalid JSON",
			[]apperrors.ValidationError{{Field: "request", Message: "request body is empty"}},
		)
		return
	}

	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		ProblemBadRequestValidationError(
			c,
			"Request body contains invalid JSON",
			[]apperrors.ValidationError{{Field: "request", Message: "invalid JSON: " + err.Error()}},
		)
		return
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		field := typeErr.Field
		if field == "" {
			field = "request"
		}
		ProblemBadRequestValidationError(
			c,
			"Request body contains invalid JSON",
			[]apperrors.ValidationError{{
				Field:   field,
				Message: fmt.Sprintf("expected %s, got %s", expectedJSONType(typeErr.Type), typeErr.Value),
			}},
		)
		return
	}

	if field, ok := unknownJSONField(err); ok {
		ProblemBadRequestValidationError(
			c,
			"Request body contains unknown fields",
			[]apperrors.ValidationError{{Field: field, Message: "unknown field"}},
		)
		return
	}

	ProblemBadRequestValidationError(
		c,
		"Request body contains invalid JSON",
		[]apperrors.ValidationError{{Field: "request", Message: "invalid JSON: " + err.Error()}},
	)
}

func unknownJSONField(err error) (string, bool) {
	// TODO: switch to typed error if encoding/json/v2 exposes one.
	const prefix = "json: unknown field "
	message := err.Error()
	if !strings.HasPrefix(message, prefix) {
		return "", false
	}
	field := strings.TrimPrefix(message, prefix)
	field = strings.Trim(field, `"`)
	return field, field != ""
}

func expectedJSONType(t reflect.Type) string {
	if t == nil {
		return "value"
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "number"
	case reflect.String:
		return "string"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Map, reflect.Struct:
		return "object"
	default:
		return t.String()
	}
}

// BindOptionalJSON decodes an optional JSON body into req. Empty or
// whitespace-only bodies are accepted (req is left at its zero value). Returns
// false (and writes a Problem response) on oversized bodies, read failures, or
// invalid JSON. Parse failures include the underlying error in the response so
// clients can locate the offending token.
func BindOptionalJSON(c *gin.Context, req any) bool {
	if c == nil {
		panic("utils: BindOptionalJSON requires a non-nil gin context")
	}
	if c.Request == nil || c.Request.Body == nil {
		return true
	}

	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxJSONRequestBodyBytes))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			ProblemPayloadTooLarge(c)
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
