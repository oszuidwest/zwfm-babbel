package utils

import (
	"fmt"
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
	Detail string `json:"detail,omitempty"`

	// Instance is a URI that identifies the specific occurrence of the problem.
	Instance string `json:"instance,omitempty"`

	// Timestamp is the time when the problem occurred in ISO 8601 format.
	Timestamp string `json:"timestamp"`

	// Code is a machine-readable error code in "resource.error" format (e.g., "station.not_found").
	Code string `json:"code,omitempty"`

	// Hint provides a user-friendly suggestion for resolving the error.
	Hint string `json:"hint,omitempty"`

	// Errors contains field-level errors for validation and strict parsing responses.
	Errors []apperrors.ValidationError `json:"errors,omitempty"`

	// TraceID can be used for request tracing and debugging.
	TraceID string `json:"trace_id,omitempty"`
}

// Problem type URIs for common error types.
const (
	// ProblemTypeValidationError identifies invalid request data.
	ProblemTypeValidationError = "https://babbel.api/problems/validation-error"
	// ProblemTypeResourceNotFound identifies a missing resource.
	ProblemTypeResourceNotFound = "https://babbel.api/problems/resource-not-found"
	// ProblemTypeDuplicateResource identifies a uniqueness conflict.
	ProblemTypeDuplicateResource = "https://babbel.api/problems/duplicate-resource"
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
)

// NewProblemDetail builds an RFC 9457 response with a UTC timestamp.
func NewProblemDetail(problemType, title string, status int, detail, instance string) *ProblemDetail {
	return &ProblemDetail{
		Type:      problemType,
		Title:     title,
		Status:    status,
		Detail:    detail,
		Instance:  instance,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// NewValidationProblem creates a 422 response for validation errors.
func NewValidationProblem(detail, instance string, errors []apperrors.ValidationError) *ProblemDetail {
	problem := NewProblemDetail(
		ProblemTypeValidationError,
		"Validation Error",
		422,
		detail,
		instance,
	)
	problem.Errors = errors
	return problem
}

// NewBadRequestValidationProblem creates a 400 response with field-level parse errors.
func NewBadRequestValidationProblem(detail string, errors []apperrors.ValidationError, instance string) *ProblemDetail {
	problem := NewProblemDetail(
		ProblemTypeBadRequest,
		"Bad Request",
		400,
		detail,
		instance,
	)
	problem.Errors = errors
	return problem
}

// NewNotFoundProblem creates a 404 response for missing resources.
func NewNotFoundProblem(resource, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeResourceNotFound,
		"Resource Not Found",
		404,
		fmt.Sprintf("%s not found", resource),
		instance,
	)
}

// NewAuthenticationProblem creates a 401 response for authentication failures.
func NewAuthenticationProblem(detail, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeAuthenticationRequired,
		"Authentication Required",
		401,
		detail,
		instance,
	)
}

// NewInternalServerProblem creates a 500 response for server-side errors.
func NewInternalServerProblem(detail, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeInternalServerError,
		"Internal Server Error",
		500,
		detail,
		instance,
	)
}

// NewBadRequestProblem creates a 400 response for malformed requests.
func NewBadRequestProblem(detail, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeBadRequest,
		"Bad Request",
		400,
		detail,
		instance,
	)
}

// WithTraceID adds a trace ID to the problem detail.
func (p *ProblemDetail) WithTraceID(traceID string) *ProblemDetail {
	p.TraceID = traceID
	return p
}

// SendProblem sends an RFC 9457 problem details response.
func SendProblem(c *gin.Context, problem *ProblemDetail) {
	c.Header("Content-Type", "application/problem+json")

	if problem.Instance == "" {
		problem.Instance = c.Request.URL.Path
	}

	c.JSON(problem.Status, problem)
}

// getTraceID extracts the trace ID from the Gin context.
func getTraceID(c *gin.Context) string {
	if traceID, exists := c.Get("trace_id"); exists {
		if id, ok := traceID.(string); ok {
			return id
		}
	}
	return ""
}
