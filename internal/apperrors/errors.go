// Package apperrors provides domain-level error definitions for the Babbel API.
package apperrors

import "fmt"

// NotFoundError indicates the requested resource does not exist.
type NotFoundError struct {
	Resource string
	ID       *int64
	cause    error
}

func (e *NotFoundError) Error() string {
	if e.ID != nil {
		return fmt.Sprintf("%s with id %d not found", e.Resource, *e.ID)
	}
	return fmt.Sprintf("%s not found", e.Resource)
}

func (e *NotFoundError) Unwrap() error { return e.cause }

// NotFoundWithID creates a NotFoundError for the given resource and ID.
func NotFoundWithID(resource string, id int64) *NotFoundError {
	return &NotFoundError{Resource: resource, ID: &id}
}

// NotFoundWithCause creates a NotFoundError with an underlying cause.
func NotFoundWithCause(resource string, cause error) *NotFoundError {
	return &NotFoundError{Resource: resource, cause: cause}
}

// DuplicateError indicates a unique constraint violation.
type DuplicateError struct {
	Resource string
	Field    string
	Value    string
	cause    error
}

func (e *DuplicateError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("%s with %s '%s' already exists", e.Resource, e.Field, e.Value)
	}
	if e.Field != "" {
		return fmt.Sprintf("%s with duplicate %s already exists", e.Resource, e.Field)
	}
	return fmt.Sprintf("%s already exists", e.Resource)
}

func (e *DuplicateError) Unwrap() error { return e.cause }

// Duplicate creates a DuplicateError for the given resource, field, and value.
func Duplicate(resource, field, value string) *DuplicateError {
	return &DuplicateError{Resource: resource, Field: field, Value: value}
}

// DuplicateWithCause creates a DuplicateError with an underlying cause.
func DuplicateWithCause(resource, field, value string, cause error) *DuplicateError {
	return &DuplicateError{Resource: resource, Field: field, Value: value, cause: cause}
}

// DependencyError indicates the resource cannot be deleted due to dependencies.
type DependencyError struct {
	Resource   string
	Dependency string
	cause      error
}

func (e *DependencyError) Error() string {
	return fmt.Sprintf("cannot delete %s: has associated %s", e.Resource, e.Dependency)
}

func (e *DependencyError) Unwrap() error { return e.cause }

// Dependency creates a DependencyError for the given resource and dependency type.
func Dependency(resource, dependency string) *DependencyError {
	return &DependencyError{Resource: resource, Dependency: dependency}
}

// DependencyWithCause creates a DependencyError with an underlying cause.
func DependencyWithCause(resource, dependency string, cause error) *DependencyError {
	return &DependencyError{Resource: resource, Dependency: dependency, cause: cause}
}

// ValidationError indicates validation failure on input data.
type ValidationError struct {
	Resource string `json:"-"`
	Field    string `json:"field"`
	Message  string `json:"message"`
	cause    error
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

func (e *ValidationError) Unwrap() error { return e.cause }

// Validation creates a ValidationError for the given resource, field, and message.
func Validation(resource, field, message string) *ValidationError {
	return &ValidationError{Resource: resource, Field: field, Message: message}
}

// ValidationWithCause creates a ValidationError with an underlying cause.
func ValidationWithCause(resource, field, message string, cause error) *ValidationError {
	return &ValidationError{Resource: resource, Field: field, Message: message, cause: cause}
}

// ValidationProblemError aggregates multi-field validation failures for HTTP 422 responses.
type ValidationProblemError struct {
	Resource string
	Detail   string
	Errors   []ValidationError
	cause    error
}

func (e *ValidationProblemError) Error() string {
	return e.Detail
}

func (e *ValidationProblemError) Unwrap() error { return e.cause }

// NewValidationProblemError creates a ValidationProblemError for the given resource.
func NewValidationProblemError(resource, detail string, errs []ValidationError) *ValidationProblemError {
	return &ValidationProblemError{Resource: resource, Detail: detail, Errors: errs}
}

// NewValidationProblemErrorWithCause creates a ValidationProblemError with an underlying cause.
func NewValidationProblemErrorWithCause(
	resource string,
	detail string,
	errs []ValidationError,
	cause error,
) *ValidationProblemError {
	return &ValidationProblemError{Resource: resource, Detail: detail, Errors: errs, cause: cause}
}

// NotInitializedError indicates a required singleton resource is not initialized.
type NotInitializedError struct {
	Resource string
	Code     string
	Detail   string
	Hint     string
	cause    error
}

func (e *NotInitializedError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("%s not initialized", e.Resource)
}

func (e *NotInitializedError) Unwrap() error { return e.cause }

// NotInitialized creates a NotInitializedError for a missing setup prerequisite.
func NotInitialized(resource, hint string, cause error) *NotInitializedError {
	return &NotInitializedError{Resource: resource, Hint: hint, cause: cause}
}

// NotInitializedWithCode creates a NotInitializedError with a specific problem code and detail.
func NotInitializedWithCode(resource, code, detail, hint string, cause error) *NotInitializedError {
	return &NotInitializedError{
		Resource: resource,
		Code:     code,
		Detail:   detail,
		Hint:     hint,
		cause:    cause,
	}
}

// RateLimitedError indicates an upstream or internal rate limit.
type RateLimitedError struct {
	Resource   string
	RetryAfter string
	cause      error
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("%s rate limited", e.Resource)
}

func (e *RateLimitedError) Unwrap() error { return e.cause }

// RateLimited creates a RateLimitedError.
func RateLimited(resource, retryAfter string, cause error) *RateLimitedError {
	return &RateLimitedError{Resource: resource, RetryAfter: retryAfter, cause: cause}
}

// UpstreamError indicates a dependency service failed or rejected service credentials.
type UpstreamError struct {
	Resource string
	Service  string
	Status   int
	Hint     string
	cause    error
}

func (e *UpstreamError) Error() string {
	if e.Service != "" {
		return fmt.Sprintf("%s upstream %s failed", e.Resource, e.Service)
	}
	return fmt.Sprintf("%s upstream failed", e.Resource)
}

func (e *UpstreamError) Unwrap() error { return e.cause }

// Upstream creates an UpstreamError.
func Upstream(resource, service string, status int, hint string, cause error) *UpstreamError {
	return &UpstreamError{
		Resource: resource,
		Service:  service,
		Status:   status,
		Hint:     hint,
		cause:    cause,
	}
}

// DatabaseError indicates an unexpected database error (internal).
type DatabaseError struct {
	Resource  string
	Operation string
	cause     error
}

func (e *DatabaseError) Error() string {
	return fmt.Sprintf("database error during %s %s", e.Operation, e.Resource)
}

func (e *DatabaseError) Unwrap() error { return e.cause }

// Database creates a DatabaseError for the given resource and operation.
func Database(resource, operation string, cause error) *DatabaseError {
	return &DatabaseError{Resource: resource, Operation: operation, cause: cause}
}

// AudioError indicates audio processing failure.
type AudioError struct {
	Resource  string
	Operation string
	cause     error
}

func (e *AudioError) Error() string {
	return fmt.Sprintf("audio %s failed for %s", e.Operation, e.Resource)
}

func (e *AudioError) Unwrap() error { return e.cause }

// Audio creates an AudioError for the given resource and operation.
func Audio(resource, operation string, cause error) *AudioError {
	return &AudioError{Resource: resource, Operation: operation, cause: cause}
}

// NoStoriesError indicates no stories are available for bulletin generation.
type NoStoriesError struct {
	StationID int64
}

func (e *NoStoriesError) Error() string {
	return fmt.Sprintf("no active stories available for station %d", e.StationID)
}

func (e *NoStoriesError) Unwrap() error { return nil }

// NoStories creates a NoStoriesError for the given station ID.
func NoStories(stationID int64) *NoStoriesError {
	return &NoStoriesError{StationID: stationID}
}
