// Package apperrors provides domain-level error definitions for the Babbel API.
package apperrors

import "fmt"

// NotFoundError section.

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

// DuplicateError section.

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

// DependencyError section.

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

// ValidationError section.

// ValidationError indicates validation failure on input data.
type ValidationError struct {
	Resource string
	Field    string
	Message  string
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

// DatabaseError section.

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

// AudioError section.

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

// NoStoriesError section.

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
