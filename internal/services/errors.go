// Package services provides domain services for the Babbel API.
// Services encapsulate business logic and data access, keeping handlers thin.
package services

import "errors"

// Sentinel errors for service layer operations.
// Use errors.Is() to check for these errors and wrap with context using fmt.Errorf("%w", err).
var (
	// ErrNotFound indicates the requested resource does not exist.
	ErrNotFound = errors.New("resource not found")

	// ErrDuplicate indicates a unique constraint violation.
	ErrDuplicate = errors.New("duplicate resource")

	// ErrDependencyExists indicates the resource cannot be deleted due to dependencies.
	ErrDependencyExists = errors.New("resource has dependencies")

	// ErrInvalidInput indicates validation failure on input data.
	ErrInvalidInput = errors.New("invalid input")

	// ErrNoStoriesAvailable indicates no stories match the bulletin criteria.
	ErrNoStoriesAvailable = errors.New("no stories available for requested criteria")

	// ErrAudioProcessingFailed indicates FFmpeg or audio service failure.
	ErrAudioProcessingFailed = errors.New("audio processing failed")

	// ErrDatabaseError indicates an unexpected database error.
	ErrDatabaseError = errors.New("database operation failed")

	// ErrUnauthorized indicates the user is not authenticated.
	ErrUnauthorized = errors.New("authentication required")

	// ErrForbidden indicates the user lacks permission for the operation.
	ErrForbidden = errors.New("permission denied")
)
