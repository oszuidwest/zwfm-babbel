// Package utils provides shared helpers for HTTP handlers, database access,
// and query parsing.
package utils

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
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
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/datatypes"
)

const maxJSONRequestBodyBytes int64 = 1 << 20

// IDParam parses the positive integer id path parameter. On failure it writes
// a 422 naming the id parameter and returns false.
func IDParam(c *gin.Context) (int64, bool) {
	raw := c.Param("id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err == nil && id > 0 {
		return id, true
	}
	fe := apperrors.FieldError{Field: "id", Code: apperrors.CodeOutOfRange, Message: "must be a positive integer"}
	switch {
	case errors.Is(err, strconv.ErrRange):
		fe.Message = "must be a positive 64-bit integer"
	case err != nil:
		fe.Code, fe.Message = apperrors.CodeInvalidFormat, fmt.Sprintf("expected integer, got %q", raw)
	}
	ProblemValidationError(c, "Invalid path parameter", fe)
	return 0, false
}

const maxAudioUploadBytes = 100 * 1024 * 1024

var audioUploadExtensions = []string{".wav", ".mp3", ".m4a", ".aac", ".ogg", ".flac", ".opus"}

// SaveAudioUpload stores the multipart file in field at a temporary path. On
// failure it writes the response and returns false: 413 above 100 MB, 400 for
// a body that is not multipart form data, 422 for a missing file or an
// unsupported extension, and 500 when the file cannot be stored.
func SaveAudioUpload(c *gin.Context, field, prefix string) (tempPath string, cleanup func() error, ok bool) {
	// Allow form overhead around a file at the size limit.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAudioUploadBytes+1<<20)
	file, header, err := c.Request.FormFile(field)
	if err != nil {
		switch _, tooLarge := errors.AsType[*http.MaxBytesError](err); {
		case tooLarge:
			ProblemPayloadTooLarge(c)
		case errors.Is(err, http.ErrMissingFile):
			ProblemValidationError(c, "The request contains invalid data", apperrors.FieldError{
				Field: field, Code: apperrors.CodeRequired, Message: "file is required",
			})
		default:
			ProblemBadRequestValidationError(c, "Request body is not valid multipart form data", apperrors.FieldError{
				Field: apperrors.FieldRequest, Code: apperrors.CodeInvalidFormat, Message: err.Error(),
			})
		}
		return "", nil, false
	}

	closeFile := func() {
		if err := file.Close(); err != nil {
			logger.Warn("Failed to close uploaded file", "error", err)
		}
	}

	if header.Size > maxAudioUploadBytes {
		closeFile()
		ProblemPayloadTooLarge(c)
		return "", nil, false
	}
	if ext := strings.ToLower(filepath.Ext(header.Filename)); !slices.Contains(audioUploadExtensions, ext) {
		closeFile()
		ProblemValidationError(c, "The request contains invalid data", apperrors.FieldError{
			Field:   field,
			Code:    apperrors.CodeUnsupported,
			Message: fmt.Sprintf("unsupported file type %q; use one of %s", ext, strings.Join(audioUploadExtensions, ", ")),
		})
		return "", nil, false
	}

	tempPath = filepath.Join(os.TempDir(), fmt.Sprintf("%s_%s", prefix, SanitizeFilename(header.Filename)))
	if err := saveFileToPath(file, tempPath); err != nil {
		closeFile()
		logger.Error("Failed to store uploaded audio", "path", tempPath, "error", err)
		ProblemInternalServer(c, "Failed to store the uploaded file")
		return "", nil, false
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
		return errors.Join(errs...)
	}

	return tempPath, cleanup, true
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
	// #nosec G304 - dst is sanitized temp path from SaveAudioUpload
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
// settings. Pointers distinguish omitted fields from explicit zeros: a missing
// MaxStoriesPerBlock is required, a missing PauseSeconds falls back to the
// default pause.
type StationRequest struct {
	Name               string   `json:"name" binding:"required,notblank,max=255"`
	MaxStoriesPerBlock *int     `json:"max_stories_per_block" binding:"required,gte=1,lte=50"`
	PauseSeconds       *float64 `json:"pause_seconds" binding:"omitempty,gte=0,lte=60"`
}

// VoiceRequest is the JSON body for creating a newsreader voice. The service
// validates the ElevenLabs voice ID format.
type VoiceRequest struct {
	Name              string  `json:"name" binding:"required,notblank,max=255"`
	ElevenLabsVoiceID *string `json:"elevenlabs_voice_id"`
}

// VoiceUpdateRequest is the JSON body for partial voice updates.
// Name is omitted to skip updates; ElevenLabsVoiceID accepts JSON null to clear.
type VoiceUpdateRequest struct {
	Name              *string          `json:"name" binding:"omitempty,notblank,max=255"`
	ElevenLabsVoiceID Optional[string] `json:"elevenlabs_voice_id"`
}

// StationVoiceRequest is the JSON body for linking a station to a voice.
// Pointer IDs distinguish a missing ID from an explicit 0.
type StationVoiceRequest struct {
	StationID *int64  `json:"station_id" binding:"required,min=1"`
	VoiceID   *int64  `json:"voice_id" binding:"required,min=1"`
	MixPoint  float64 `json:"mix_point" binding:"gte=0,lte=300"`
}

// StationVoiceUpdateRequest is the JSON body for partial station-voice updates.
type StationVoiceUpdateRequest struct {
	StationID *int64   `json:"station_id,omitempty" binding:"omitempty,min=1"`
	VoiceID   *int64   `json:"voice_id,omitempty" binding:"omitempty,min=1"`
	MixPoint  *float64 `json:"mix_point,omitempty" binding:"omitempty,gte=0,lte=300"`
}

// UserCreateRequest is the JSON body for creating local user accounts. The
// service applies the configured password policy.
type UserCreateRequest struct {
	Username string             `json:"username" binding:"required,min=3,max=100,alphanum"`
	FullName string             `json:"full_name" binding:"required,notblank,max=255"`
	Password string             `json:"password" binding:"required"`
	Email    *string            `json:"email" binding:"omitempty,email,max=255"`
	Role     string             `json:"role" binding:"required,oneof=admin editor viewer"`
	Metadata *datatypes.JSONMap `json:"metadata,omitempty"`
}

// UserUpdateRequest is the JSON body for partial account updates. Nil fields
// are left unchanged; an empty email clears the stored address.
type UserUpdateRequest struct {
	Username  *string            `json:"username" binding:"omitempty,min=3,max=100,alphanum"`
	FullName  *string            `json:"full_name" binding:"omitempty,notblank,max=255"`
	Email     *string            `json:"email" binding:"omitempty,email,max=255"`
	Password  *string            `json:"password"`
	Role      *string            `json:"role" binding:"omitempty,oneof=admin editor viewer"`
	Metadata  *datatypes.JSONMap `json:"metadata,omitempty"`
	Suspended *bool              `json:"suspended" binding:"omitempty"`
}

// StoryCreateRequest is the JSON body for creating scheduled news stories.
type StoryCreateRequest struct {
	Title     string `json:"title" binding:"required,notblank,max=500"`
	Text      string `json:"text" binding:"required,notblank"`
	VoiceID   *int64 `json:"voice_id" binding:"omitempty,min=1"`
	Status    string `json:"status" binding:"omitempty,oneof=draft active expired"`
	StartDate string `json:"start_date" binding:"required,dateformat"`
	EndDate   string `json:"end_date" binding:"required,dateformat"`
	// Weekdays is a bitmask: Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64.
	// 0 selects every day.
	Weekdays int `json:"weekdays" binding:"gte=0,lte=127"`
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
	Status    *string `json:"status" binding:"omitempty,oneof=draft active expired"`
	StartDate *string `json:"start_date" binding:"omitempty,dateformat"`
	EndDate   *string `json:"end_date" binding:"omitempty,dateformat"`
	// Weekdays is a bitmask: Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64.
	Weekdays *int `json:"weekdays" binding:"omitempty,gte=0,lte=127"`
	// IsBreaking prioritizes the story for bulletin inclusion.
	IsBreaking *bool              `json:"is_breaking"`
	Metadata   *datatypes.JSONMap `json:"metadata,omitempty"`
}

// PronunciationRuleUpdateRequest describes one inline-IPA rule. Pointer booleans
// distinguish omitted values from false; validation preserves indexed field errors.
type PronunciationRuleUpdateRequest struct {
	StringToReplace string `json:"string_to_replace"`
	IPA             string `json:"ipa"`
	CaseSensitive   *bool  `json:"case_sensitive,omitempty"`
	WordBoundaries  *bool  `json:"word_boundaries,omitempty"`
}

// PronunciationRulesUpdateRequest is the JSON body for replacing the full
// inline-IPA rule set. An empty Rules array clears the table.
type PronunciationRulesUpdateRequest struct {
	Rules []PronunciationRuleUpdateRequest `json:"rules" binding:"required"`
}

// TTSSettingsUpdateRequest is a partial update to the global TTS settings.
type TTSSettingsUpdateRequest struct {
	Stability              *float64        `json:"stability"`
	ApplyTextNormalization *string         `json:"apply_text_normalization"`
	Seed                   Optional[int64] `json:"seed"`
	TTSStylePrefix         *string         `json:"tts_style_prefix"`
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

type textNormalizer interface {
	NormalizeText()
}

// RequireAnyField responds with HTTP 422 and returns false when the partial
// update request req sets no field.
func RequireAnyField[T comparable](c *gin.Context, req T) bool {
	var zero T
	if req != zero {
		return true
	}
	ProblemValidationError(c, "The request contains invalid data", apperrors.FieldError{
		Field:   apperrors.FieldRequest,
		Code:    apperrors.CodeEmptyUpdate,
		Message: "At least one field must be provided",
	})
	return false
}

// BindJSON decodes a required JSON object body into req, rejecting unknown
// members, then normalizes text fields and validates binding tags. On failure
// it writes the response and returns false: 413 for an oversized body, 400 for
// a body that is not a valid JSON document for req, and 422 for rejected values.
func BindJSON(c *gin.Context, req any) bool {
	return bindJSON(c, req, false)
}

// BindOptionalJSON is [BindJSON] for endpoints that also accept an empty body.
func BindOptionalJSON(c *gin.Context, req any) bool {
	return bindJSON(c, req, true)
}

func bindJSON(c *gin.Context, req any, optional bool) bool {
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxJSONRequestBodyBytes))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			ProblemPayloadTooLarge(c)
			return false
		}
		problemInvalidJSON(c, apperrors.FieldError{Field: apperrors.FieldRequest, Code: apperrors.CodeInvalidJSON, Message: "request body could not be read"})
		return false
	}

	body = bytes.Trim(body, " \t\r\n")
	switch {
	case len(body) == 0 && optional:
	case len(body) == 0:
		problemInvalidJSON(c, apperrors.FieldError{Field: apperrors.FieldRequest, Code: apperrors.CodeRequired, Message: "request body is required"})
		return false
	case body[0] != '{':
		problemInvalidJSON(c, apperrors.FieldError{Field: apperrors.FieldRequest, Code: apperrors.CodeInvalidType, Message: "request body must be a JSON object"})
		return false
	default:
		if err := jsonv2.Unmarshal(body, req, jsonv2.RejectUnknownMembers(true)); err != nil {
			problemInvalidJSON(c, decodeFieldError(err))
			return false
		}
	}

	if n, ok := req.(textNormalizer); ok {
		n.NormalizeText()
	}

	if err := binding.Validator.ValidateStruct(req); err != nil {
		ProblemValidationError(c, "The request contains invalid data", convertValidationErrors(err)...)
		return false
	}
	return true
}

func problemInvalidJSON(c *gin.Context, fe apperrors.FieldError) {
	ProblemBadRequestValidationError(c, "Request body is not valid JSON for this endpoint", fe)
}

// decodeFieldError classifies a JSON decoding error at the JSON path where it
// occurred.
func decodeFieldError(err error) apperrors.FieldError {
	if semantic, ok := errors.AsType[*jsonv2.SemanticError](err); ok {
		field := jsonPath(semantic.JSONPointer)
		if errors.Is(err, jsonv2.ErrUnknownName) {
			return apperrors.FieldError{Field: field, Code: apperrors.CodeUnknownField, Message: "unknown field"}
		}
		goType := semantic.GoType
		// A custom UnmarshalJSON, such as Optional's, reports the inner type.
		if inner, ok := errors.AsType[*json.UnmarshalTypeError](semantic.Err); ok {
			goType = inner.Type
		}
		return apperrors.FieldError{
			Field:   field,
			Code:    apperrors.CodeInvalidType,
			Message: fmt.Sprintf("expected %s", expectedJSONType(goType)),
		}
	}
	if syntactic, ok := errors.AsType[*jsontext.SyntacticError](err); ok && errors.Is(err, jsontext.ErrDuplicateName) {
		return apperrors.FieldError{Field: jsonPath(syntactic.JSONPointer), Code: apperrors.CodeDuplicate, Message: "duplicate field"}
	}
	return apperrors.FieldError{Field: apperrors.FieldRequest, Code: apperrors.CodeInvalidJSON, Message: err.Error()}
}

// jsonPath renders a JSON Pointer as a field path such as "rules[0].ipa".
// Numeric tokens are array indices: request types have no integer-named members.
func jsonPath(pointer jsontext.Pointer) string {
	var b strings.Builder
	for token := range pointer.Tokens() {
		if _, err := strconv.Atoi(token); err == nil {
			b.WriteString("[" + token + "]")
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(token)
	}
	if b.Len() == 0 {
		return apperrors.FieldRequest
	}
	return b.String()
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
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
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

func convertValidationErrors(err error) []apperrors.FieldError {
	validationErrors, ok := errors.AsType[validator.ValidationErrors](err)
	if !ok {
		logger.Error("Unexpected request validation error", "error", err)
		return []apperrors.FieldError{{
			Field:   apperrors.FieldRequest,
			Code:    apperrors.CodeInvalidFormat,
			Message: "Invalid request",
		}}
	}

	errs := make([]apperrors.FieldError, 0, len(validationErrors))
	for _, e := range validationErrors {
		code, message := describeValidationError(e)
		errs = append(errs, apperrors.FieldError{Field: validationPath(e), Code: code, Message: message})
	}
	return errs
}

// validationPath drops the root struct name from the validator namespace,
// which InitializeValidators builds from JSON names.
func validationPath(e validator.FieldError) string {
	if _, path, ok := strings.Cut(e.Namespace(), "."); ok {
		return path
	}
	return e.Field()
}

func describeValidationError(e validator.FieldError) (code, message string) {
	param := e.Param()
	isNumber := e.Kind() >= reflect.Int && e.Kind() <= reflect.Float64
	switch e.Tag() {
	case "required":
		return apperrors.CodeRequired, "is required"
	case "notblank":
		return apperrors.CodeBlank, "cannot be empty or whitespace only"
	case "min":
		if isNumber {
			return apperrors.CodeOutOfRange, "must be at least " + param
		}
		return apperrors.CodeTooShort, "must be at least " + param + " characters"
	case "max":
		if isNumber {
			return apperrors.CodeOutOfRange, "must be at most " + param
		}
		return apperrors.CodeTooLong, "must be at most " + param + " characters"
	case "gte":
		return apperrors.CodeOutOfRange, "must be at least " + param
	case "lte":
		return apperrors.CodeOutOfRange, "must be at most " + param
	case "oneof":
		return apperrors.CodeInvalidChoice, "must be one of: " + strings.ReplaceAll(param, " ", ", ")
	case "email":
		return apperrors.CodeInvalidFormat, "must be a valid email address"
	case "alphanum":
		return apperrors.CodeInvalidFormat, "can only contain letters and numbers"
	case "dateformat":
		return apperrors.CodeInvalidFormat, "must be in YYYY-MM-DD format"
	default:
		return apperrors.CodeInvalidFormat, "failed validation (" + e.Tag() + ")"
	}
}
