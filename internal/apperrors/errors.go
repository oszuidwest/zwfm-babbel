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
