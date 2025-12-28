// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

// ProblemDetail represents an RFC 9457 Problem Details response for HTTP APIs.
// See: https://datatracker.ietf.org/doc/html/rfc9457
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

	// Errors contains validation errors for 422 responses.
	Errors []ValidationError `json:"errors,omitempty"`

	// TraceID can be used for request tracing and debugging.
	TraceID string `json:"trace_id,omitempty"`
}

// ValidationError represents a single validation error for a specific field.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Problem type URIs for common error types
const (
	ProblemTypeValidationError         = "https://babbel.api/problems/validation-error"
	ProblemTypeResourceNotFound        = "https://babbel.api/problems/resource-not-found"
	ProblemTypeDuplicateResource       = "https://babbel.api/problems/duplicate-resource"
	ProblemTypeAuthenticationRequired  = "https://babbel.api/problems/authentication-required"
	ProblemTypeInsufficientPermissions = "https://babbel.api/problems/insufficient-permissions"
	ProblemTypeInternalServerError     = "https://babbel.api/problems/internal-server-error"
	ProblemTypeBadRequest              = "https://babbel.api/problems/bad-request"
)

// NewProblemDetail creates a new RFC 9457 compliant problem detail response.
// Automatically sets the timestamp to the current UTC time in RFC3339 format.
// Used as the base constructor for all problem types.
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

// NewValidationProblem creates a standardized 422 Unprocessable Entity response for validation errors.
// Includes detailed field-level error information in the errors array.
// Used when request data fails validation constraints.
func NewValidationProblem(detail, instance string, errors []ValidationError) *ProblemDetail {
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

// NewNotFoundProblem creates a standardized 404 Not Found response for missing resources.
// Automatically formats the detail message to indicate which resource was not found.
func NewNotFoundProblem(resource, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeResourceNotFound,
		"Resource Not Found",
		404,
		fmt.Sprintf("%s not found", resource),
		instance,
	)
}

// NewDuplicateProblem creates a standardized 409 Conflict response for resource conflicts.
// Used when attempting to create resources that already exist or violate uniqueness constraints.
func NewDuplicateProblem(resource, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeDuplicateResource,
		"Duplicate Resource",
		409,
		fmt.Sprintf("%s already exists", resource),
		instance,
	)
}

// NewAuthenticationProblem creates a standardized 401 Unauthorized response for authentication failures.
// Used when credentials are invalid, missing, or authentication has failed.
func NewAuthenticationProblem(detail, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeAuthenticationRequired,
		"Authentication Required",
		401,
		detail,
		instance,
	)
}

// NewInternalServerProblem creates a standardized 500 Internal Server Error response.
// Used for unexpected server-side failures that are not the client's fault.
func NewInternalServerProblem(detail, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeInternalServerError,
		"Internal Server Error",
		500,
		detail,
		instance,
	)
}

// NewBadRequestProblem creates a standardized 400 Bad Request response for malformed requests.
// Used when the request syntax is invalid or cannot be processed.
func NewBadRequestProblem(detail, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeBadRequest,
		"Bad Request",
		400,
		detail,
		instance,
	)
}

// WithTraceID adds a trace ID to the problem detail for distributed tracing support.
// Returns the same problem detail instance for method chaining.
func (p *ProblemDetail) WithTraceID(traceID string) *ProblemDetail {
	p.TraceID = traceID
	return p
}

// SendProblem sends an RFC 9457 compliant problem details response with proper HTTP headers.
// Sets the Content-Type to 'application/problem+json' and automatically populates
// the instance field with the request path if not already set.
func SendProblem(c *gin.Context, problem *ProblemDetail) {
	// Set the correct content type for RFC 9457
	c.Header("Content-Type", "application/problem+json")

	// Set the instance if not already set
	if problem.Instance == "" {
		problem.Instance = c.Request.URL.Path
	}

	c.JSON(problem.Status, problem)
}

// getTraceID extracts the trace ID from the Gin context.
// Returns an empty string if no trace ID is found or if it's not a string type.
func getTraceID(c *gin.Context) string {
	// Check for trace_id in context
	if traceID, exists := c.Get("trace_id"); exists {
		if id, ok := traceID.(string); ok {
			return id
		}
	}
	return ""
}
