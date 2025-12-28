// Package apperrors provides domain-level error definitions for the Babbel API.
// These sentinel errors are used throughout the service layer and mapped to
// RFC 9457 Problem Details responses at the handler layer.
package apperrors

import "errors"

// Domain sentinel errors.
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

	// ErrDataTooLong indicates data exceeds database column capacity.
	// Maps to HTTP 422 Unprocessable Entity.
	ErrDataTooLong = errors.New("data exceeds maximum length")
)
