// Package utils provides shared utility functions.
package utils

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// MessageResponse represents a simple message response (typed alternative to gin.H).
type MessageResponse struct {
	Message string `json:"message"`
}

// IDMessageResponse represents a response with an ID and message (typed alternative to gin.H).
type IDMessageResponse struct {
	ID      int64  `json:"id"`
	Message string `json:"message"`
}

// ListResponse represents a paginated list response (typed alternative to gin.H).
type ListResponse struct {
	Data   any   `json:"data"`
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

// Success responds with HTTP 200 OK status and the provided data.
func Success(c *gin.Context, data any) {
	if c == nil {
		return
	}
	c.JSON(http.StatusOK, data)
}

// NoContent responds with HTTP 204 No Content.
func NoContent(c *gin.Context) {
	if c == nil {
		return
	}
	c.Status(http.StatusNoContent)
}

// PaginatedResponse responds with paginated data in a consistent format.
func PaginatedResponse(c *gin.Context, data any, total int64, limit, offset int) {
	if c == nil {
		return
	}
	c.JSON(http.StatusOK, ListResponse{
		Data:   data,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

// CreatedWithLocation responds with HTTP 201 Created status including the new resource ID
// and sets the Location header per RFC 7231.
// The resourcePath should be the base path (e.g., "/api/v1/stations"), the ID will be appended.
func CreatedWithLocation(c *gin.Context, id int64, resourcePath, message string) {
	if c == nil {
		return
	}
	location := fmt.Sprintf("%s/%d", resourcePath, id)
	c.Header("Location", location)
	c.JSON(http.StatusCreated, IDMessageResponse{
		ID:      id,
		Message: message,
	})
}

// CreatedWithMessage responds with HTTP 201 Created status and a success message.
func CreatedWithMessage(c *gin.Context, message string) {
	if c == nil {
		return
	}
	c.JSON(http.StatusCreated, MessageResponse{Message: message})
}

// RFC 9457 Problem Details compatible error response functions.

// ProblemValidationError responds with HTTP 422 for input validation failures.
func ProblemValidationError(c *gin.Context, detail string, errors []ValidationError) {
	if c == nil {
		return
	}
	problem := NewValidationProblem(detail, c.Request.URL.Path, errors)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemNotFound responds with HTTP 404 Not Found.
func ProblemNotFound(c *gin.Context, resource string) {
	if c == nil {
		return
	}
	problem := NewNotFoundProblem(resource, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemAuthentication responds with HTTP 401 Unauthorized.
// Per RFC 7235, includes WWW-Authenticate header.
func ProblemAuthentication(c *gin.Context, detail string) {
	if c == nil {
		return
	}
	c.Header("WWW-Authenticate", `Session realm="Babbel API"`)
	problem := NewAuthenticationProblem(detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemInternalServer responds with HTTP 500 Internal Server Error.
func ProblemInternalServer(c *gin.Context, detail string) {
	if c == nil {
		return
	}
	problem := NewInternalServerProblem(detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemBadRequest responds with HTTP 400 Bad Request.
func ProblemBadRequest(c *gin.Context, detail string) {
	if c == nil {
		return
	}
	problem := NewBadRequestProblem(detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemCustom responds with a custom problem type.
func ProblemCustom(c *gin.Context, problemType, title string, status int, detail string) {
	if c == nil {
		return
	}
	problem := NewProblemDetail(problemType, title, status, detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemExtended responds with an RFC 9457 problem including code and hint fields.
// This is used by handleServiceError for typed error responses.
func ProblemExtended(c *gin.Context, status int, detail, code, hint string) {
	if c == nil {
		return
	}
	problem := NewProblemDetail(
		"https://babbel.api/problems/"+code,
		http.StatusText(status),
		status,
		detail,
		c.Request.URL.Path,
	)
	problem.Code = code
	problem.Hint = hint
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}
