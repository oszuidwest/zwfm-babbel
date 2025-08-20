package utils

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

// ProblemDetail represents an RFC 9457 Problem Details for HTTP APIs response.
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

// NewProblemDetail creates a new ProblemDetail with the specified parameters.
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

// NewValidationProblem creates a new ProblemDetail for validation errors.
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

// NewNotFoundProblem creates a new ProblemDetail for resource not found errors.
func NewNotFoundProblem(resource, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeResourceNotFound,
		"Resource Not Found",
		404,
		fmt.Sprintf("%s not found", resource),
		instance,
	)
}

// NewDuplicateProblem creates a new ProblemDetail for duplicate resource errors.
func NewDuplicateProblem(resource, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeDuplicateResource,
		"Duplicate Resource",
		409,
		fmt.Sprintf("%s already exists", resource),
		instance,
	)
}

// NewAuthenticationProblem creates a new ProblemDetail for authentication errors.
func NewAuthenticationProblem(detail, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeAuthenticationRequired,
		"Authentication Required",
		401,
		detail,
		instance,
	)
}

// NewAuthorizationProblem creates a new ProblemDetail for authorization errors.
func NewAuthorizationProblem(detail, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeInsufficientPermissions,
		"Insufficient Permissions",
		403,
		detail,
		instance,
	)
}


// NewInternalServerProblem creates a new ProblemDetail for internal server errors.
func NewInternalServerProblem(detail, instance string) *ProblemDetail {
	return NewProblemDetail(
		ProblemTypeInternalServerError,
		"Internal Server Error",
		500,
		detail,
		instance,
	)
}

// NewBadRequestProblem creates a new ProblemDetail for bad request errors.
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

// SendProblem sends an RFC 9457 Problem Details response with the correct content type.
func SendProblem(c *gin.Context, problem *ProblemDetail) {
	// Set the correct content type for RFC 9457
	c.Header("Content-Type", "application/problem+json")

	// Set the instance if not already set
	if problem.Instance == "" {
		problem.Instance = c.Request.URL.Path
	}

	c.JSON(problem.Status, problem)
}

// Helper function to extract trace ID from context (if available)
func getTraceID(c *gin.Context) string {
	// This can be customized based on your tracing implementation
	if traceID, exists := c.Get("trace_id"); exists {
		if id, ok := traceID.(string); ok {
			return id
		}
	}
	return ""
}
