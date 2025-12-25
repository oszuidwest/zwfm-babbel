// Package validation provides structured validation for the Babbel API.
package validation

import (
	"fmt"
	"strings"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

// Result holds validation results with multiple field errors.
type Result struct {
	Valid  bool
	Errors []FieldError
}

// FieldError represents a validation error for a specific field.
type FieldError struct {
	Field   string
	Message string
}

// New creates a new valid Result.
func New() *Result {
	return &Result{Valid: true}
}

// AddError adds a field error and marks the result as invalid.
func (r *Result) AddError(field, message string) *Result {
	r.Valid = false
	r.Errors = append(r.Errors, FieldError{Field: field, Message: message})
	return r
}

// AddErrorf adds a formatted field error.
func (r *Result) AddErrorf(field, format string, args ...interface{}) *Result {
	return r.AddError(field, fmt.Sprintf(format, args...))
}

// Merge combines another Result into this one.
func (r *Result) Merge(other *Result) *Result {
	if other == nil {
		return r
	}
	for _, e := range other.Errors {
		r.AddError(e.Field, e.Message)
	}
	return r
}

// ToError converts the Result to an apperrors.Error if invalid.
// Returns nil if the result is valid.
func (r *Result) ToError() *apperrors.Error {
	if r.Valid || len(r.Errors) == 0 {
		return nil
	}
	if len(r.Errors) == 1 {
		return apperrors.InvalidField(r.Errors[0].Field, r.Errors[0].Message)
	}
	// Multiple errors - combine messages
	var messages []string
	for _, e := range r.Errors {
		messages = append(messages, fmt.Sprintf("%s: %s", e.Field, e.Message))
	}
	return apperrors.InvalidInput(strings.Join(messages, "; "))
}

// HasErrors returns true if there are validation errors.
func (r *Result) HasErrors() bool {
	return !r.Valid || len(r.Errors) > 0
}

// FirstError returns the first error message, or empty string.
func (r *Result) FirstError() string {
	if len(r.Errors) > 0 {
		return r.Errors[0].Message
	}
	return ""
}
