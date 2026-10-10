package utils

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

// ProblemDetail represents an RFC 9457 Problem Details response for HTTP APIs.
// See RFC 9457: https://datatracker.ietf.org/doc/html/rfc9457.
type ProblemDetail struct {
	// Type is a URI that identifies the problem type.
	Type string `json:"type"`

	// Title is a short, human-readable summary of the problem type.
	Title string `json:"title"`

	// Status is the HTTP status code for this occurrence of the problem.
	Status int `json:"status"`

	// Detail is a human-readable explanation specific to this occurrence of the problem.
	Detail string `json:"detail"`

	// Instance is a URI that identifies the specific occurrence of the problem.
	Instance string `json:"instance,omitempty"`

	// Timestamp is the time when the problem occurred in ISO 8601 format.
	Timestamp string `json:"timestamp"`

	// Code is a machine-readable error code in "resource.error" format (e.g., "station.not_found").
	Code string `json:"code,omitempty"`

	// Hint provides a user-friendly suggestion for resolving the error.
	Hint string `json:"hint,omitempty"`

	// DeletedAt is the deletion time for story.deleted responses.
	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	// Errors contains field-level errors for validation and strict parsing responses.
	Errors []apperrors.ValidationError `json:"errors,omitempty"`
}

// Problem type URIs for common error types.
const (
	// ProblemTypeValidationError identifies invalid request data.
	ProblemTypeValidationError = "https://babbel.api/problems/validation-error"
	// ProblemTypeResourceNotFound identifies a missing resource.
	ProblemTypeResourceNotFound = "https://babbel.api/problems/resource-not-found"
	// ProblemTypeAuthenticationRequired identifies missing or invalid credentials.
	ProblemTypeAuthenticationRequired = "https://babbel.api/problems/authentication-required"
	// ProblemTypeInsufficientPermissions identifies an authorization failure.
	ProblemTypeInsufficientPermissions = "https://babbel.api/problems/insufficient-permissions"
	// ProblemTypeInternalServerError identifies an unexpected server failure.
	ProblemTypeInternalServerError = "https://babbel.api/problems/internal-server-error"
	// ProblemTypeBadRequest identifies a malformed request.
	ProblemTypeBadRequest = "https://babbel.api/problems/bad-request"
	// ProblemTypePayloadTooLarge identifies a request body that exceeds the API limit.
	ProblemTypePayloadTooLarge = "https://babbel.api/problems/payload-too-large"
	// ProblemTypeNotAcceptable identifies an Accept header that excludes the response media type.
	ProblemTypeNotAcceptable = "https://babbel.api/problems/not-acceptable"
	// ProblemTypeRangeNotSatisfiable identifies an invalid or non-overlapping byte range.
	ProblemTypeRangeNotSatisfiable = "https://babbel.api/problems/range-not-satisfiable"
)

// NewProblemDetail builds an RFC 9457 response with a UTC timestamp.
// SendProblem fills Instance with the request path.
func NewProblemDetail(problemType, title string, status int, detail string) *ProblemDetail {
	return &ProblemDetail{
		Type:      problemType,
		Title:     title,
		Status:    status,
		Detail:    detail,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// SendProblem sends an RFC 9457 problem details response.
func SendProblem(c *gin.Context, problem *ProblemDetail) {
	c.Header("Content-Type", "application/problem+json")

	if problem.Instance == "" {
		problem.Instance = c.Request.URL.Path
	}

	c.JSON(problem.Status, problem)
}
