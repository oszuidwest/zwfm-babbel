// Package apperrors provides typed error handling for the Babbel API.
// It uses struct-based errors with separate user-safe and internal messages.
package apperrors

import "fmt"

// Code categorizes errors for consistent handling across the application.
type Code int

const (
	CodeUnknown Code = iota
	CodeNotFound
	CodeDuplicate
	CodeInvalidInput
	CodeValidation
	CodeDependencyExists
	CodeNoStoriesAvailable
	CodeAudioProcessing
	CodeDatabase
	CodeUnauthorized
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
func (e *Error) WithInternal(format string, args ...interface{}) *Error {
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

// =============================================================================
// Constructor functions - return user-safe errors by default
// =============================================================================

// NotFound creates an error for missing resources.
func NotFound(resource string) *Error {
	return &Error{
		Code:    CodeNotFound,
		Message: fmt.Sprintf("%s not found", resource),
	}
}

// NotFoundWithID creates an error for missing resources with ID context.
func NotFoundWithID(resource string, id int) *Error {
	return &Error{
		Code:     CodeNotFound,
		Message:  fmt.Sprintf("%s not found", resource),
		Internal: fmt.Sprintf("%s with id %d not found", resource, id),
	}
}

// Duplicate creates an error for unique constraint violations.
func Duplicate(resource, field string) *Error {
	return &Error{
		Code:    CodeDuplicate,
		Message: fmt.Sprintf("%s with this %s already exists", resource, field),
		Field:   field,
	}
}

// DuplicateValue creates an error with the duplicate value in internal details.
func DuplicateValue(resource, field string, value interface{}) *Error {
	return &Error{
		Code:     CodeDuplicate,
		Message:  fmt.Sprintf("%s with this %s already exists", resource, field),
		Field:    field,
		Internal: fmt.Sprintf("duplicate %s.%s: %v", resource, field, value),
	}
}

// InvalidInput creates a validation error with a user-safe message.
func InvalidInput(message string) *Error {
	return &Error{
		Code:    CodeInvalidInput,
		Message: message,
	}
}

// InvalidField creates a validation error for a specific field.
func InvalidField(field, message string) *Error {
	return &Error{
		Code:    CodeValidation,
		Message: message,
		Field:   field,
	}
}

// DependencyExists creates an error when a resource cannot be deleted.
func DependencyExists(resource string) *Error {
	return &Error{
		Code:    CodeDependencyExists,
		Message: fmt.Sprintf("Cannot delete %s: it has dependencies", resource),
	}
}

// DependencyExistsDetail creates a dependency error with details.
func DependencyExistsDetail(resource, dependency string, count int) *Error {
	return &Error{
		Code:     CodeDependencyExists,
		Message:  fmt.Sprintf("Cannot delete %s: it has dependencies", resource),
		Internal: fmt.Sprintf("%s has %d %s", resource, count, dependency),
	}
}

// NoStoriesAvailable creates an error for empty bulletin generation.
func NoStoriesAvailable() *Error {
	return &Error{
		Code:    CodeNoStoriesAvailable,
		Message: "No active stories available for the requested date and station",
	}
}

// AudioProcessingFailed creates an error for FFmpeg/audio failures.
func AudioProcessingFailed(internal string) *Error {
	return &Error{
		Code:     CodeAudioProcessing,
		Message:  "Audio processing failed",
		Internal: internal,
	}
}

// Database creates an error for database operations.
// The user sees a generic message; details are in Internal for logging.
func Database(internal string, err error) *Error {
	return &Error{
		Code:     CodeDatabase,
		Message:  "A database error occurred",
		Internal: internal,
		Err:      err,
	}
}

// DatabaseOp creates a database error with operation context.
func DatabaseOp(operation, resource string, err error) *Error {
	return &Error{
		Code:     CodeDatabase,
		Message:  "A database error occurred",
		Internal: fmt.Sprintf("%s %s failed", operation, resource),
		Err:      err,
	}
}

// Unauthorized creates an authentication error.
func Unauthorized(message string) *Error {
	return &Error{
		Code:    CodeUnauthorized,
		Message: message,
	}
}

// Forbidden creates an authorization error.
func Forbidden(message string) *Error {
	return &Error{
		Code:    CodeForbidden,
		Message: message,
	}
}

// =============================================================================
// Error checking helpers
// =============================================================================

// IsNotFound checks if an error is a not found error.
func IsNotFound(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == CodeNotFound
	}
	return false
}

// IsDuplicate checks if an error is a duplicate error.
func IsDuplicate(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == CodeDuplicate
	}
	return false
}

// IsValidation checks if an error is a validation error.
func IsValidation(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == CodeValidation || e.Code == CodeInvalidInput
	}
	return false
}

// GetCode extracts the error code from an Error, or CodeUnknown.
func GetCode(err error) Code {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return CodeUnknown
}
