// Package apperrors provides typed error handling for the Babbel API.
// It uses struct-based errors with separate user-safe and internal messages.
package apperrors

import "fmt"

// Code categorizes errors for consistent handling across the application.
type Code int

// Error codes for categorizing application errors.
const (
	// CodeUnknown indicates an unspecified error type
	CodeUnknown Code = iota
	// CodeNotFound indicates a requested resource does not exist
	CodeNotFound
	// CodeDuplicate indicates a unique constraint violation
	CodeDuplicate
	// CodeInvalidInput indicates malformed or invalid input
	CodeInvalidInput
	// CodeValidation indicates input failed validation rules
	CodeValidation
	// CodeDependencyExists indicates the resource has dependent records
	CodeDependencyExists
	// CodeNoStoriesAvailable indicates no stories match bulletin criteria
	CodeNoStoriesAvailable
	// CodeAudioProcessing indicates FFmpeg or audio pipeline failure
	CodeAudioProcessing
	// CodeDatabase indicates a database operation failure
	CodeDatabase
	// CodeUnauthorized indicates authentication is required
	CodeUnauthorized
	// CodeForbidden indicates insufficient permissions
	CodeForbidden
)

// Error represents a domain error with separate user-safe and internal messages.
// The Message field is always safe to expose to clients.
// The Internal field contains debugging details and should only be logged.
type Error struct {
	Code     Code   // Error category for handler mapping
	Message  string // User-safe message (always exposable)
	Internal string // Internal details (for logging only)
	Field    string // Optional: which field caused the error
	Err      error  // Wrapped underlying error
}

// Error implements the error interface.
// Returns the user-safe message.
func (e *Error) Error() string {
	return e.Message
}

// Unwrap returns the wrapped error for errors.Is/As support.
func (e *Error) Unwrap() error {
	return e.Err
}

// WithInternal adds internal debugging details to the error.
func (e *Error) WithInternal(format string, args ...any) *Error {
	e.Internal = fmt.Sprintf(format, args...)
	return e
}

// WithField adds field information to the error.
func (e *Error) WithField(field string) *Error {
	e.Field = field
	return e
}

// Wrap wraps an underlying error.
func (e *Error) Wrap(err error) *Error {
	e.Err = err
	return e
}

// String returns the string representation of the error code.
func (c Code) String() string {
	switch c {
	case CodeUnknown:
		return "unknown"
	case CodeNotFound:
		return "not_found"
	case CodeDuplicate:
		return "duplicate"
	case CodeInvalidInput:
		return "invalid_input"
	case CodeValidation:
		return "validation"
	case CodeDependencyExists:
		return "dependency_exists"
	case CodeNoStoriesAvailable:
		return "no_stories_available"
	case CodeAudioProcessing:
		return "audio_processing"
	case CodeDatabase:
		return "database"
	case CodeUnauthorized:
		return "unauthorized"
	case CodeForbidden:
		return "forbidden"
	default:
		return fmt.Sprintf("unknown_code_%d", c)
	}
}

// Is reports whether target matches this error's code.
func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return e.Code == t.Code
	}
	return false
}

// NotFound creates a new not found error with the given message.
func NotFound(message string) *Error {
	return &Error{
		Code:    CodeNotFound,
		Message: message,
	}
}

// Duplicate creates a new duplicate error with the given message.
func Duplicate(message string) *Error {
	return &Error{
		Code:    CodeDuplicate,
		Message: message,
	}
}

// Database creates a new database error with the given message.
func Database(message string) *Error {
	return &Error{
		Code:    CodeDatabase,
		Message: message,
	}
}

// InvalidInput creates a new invalid input error with the given message.
func InvalidInput(message string) *Error {
	return &Error{
		Code:    CodeInvalidInput,
		Message: message,
	}
}
