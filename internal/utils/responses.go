// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Modern response functions using consistent formats

// Success responds with a 200 OK status and the provided data payload.
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, data)
}

// NoContent responds with a 204 No Content status for successful operations with no response body.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// PaginatedResponse responds with paginated data in consistent format including total count and pagination metadata.
func PaginatedResponse(c *gin.Context, data interface{}, total int64, limit, offset int) {
	c.JSON(http.StatusOK, gin.H{
		"data":   data,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// CreatedWithID responds with 201 Created status including the new resource ID and success message.
func CreatedWithID(c *gin.Context, id int64, message string) {
	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"message": message,
	})
}

// SuccessWithMessage responds with 200 OK status and a success message.
func SuccessWithMessage(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{"message": message})
}

// RFC 9457 Problem Details compatible error response functions
// These functions provide standardized error responses following RFC 9457 specification

// ProblemValidationError responds with a 422 Unprocessable Entity using RFC 9457 Problem Details format.
func ProblemValidationError(c *gin.Context, detail string, errors []ValidationError) {
	problem := NewValidationProblem(detail, c.Request.URL.Path, errors)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemNotFound responds with a 404 Not Found using RFC 9457 Problem Details format.
func ProblemNotFound(c *gin.Context, resource string) {
	problem := NewNotFoundProblem(resource, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemDuplicate responds with a 409 Conflict using RFC 9457 Problem Details format.
func ProblemDuplicate(c *gin.Context, resource string) {
	problem := NewDuplicateProblem(resource, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemAuthentication responds with a 401 Unauthorized using RFC 9457 Problem Details format.
func ProblemAuthentication(c *gin.Context, detail string) {
	problem := NewAuthenticationProblem(detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemInternalServer responds with a 500 Internal Server Error using RFC 9457 Problem Details format.
func ProblemInternalServer(c *gin.Context, detail string) {
	problem := NewInternalServerProblem(detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemBadRequest responds with a 400 Bad Request using RFC 9457 Problem Details format.
func ProblemBadRequest(c *gin.Context, detail string) {
	problem := NewBadRequestProblem(detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemCustom responds with a custom problem type using RFC 9457 Problem Details format.
func ProblemCustom(c *gin.Context, problemType, title string, status int, detail string) {
	problem := NewProblemDetail(problemType, title, status, detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}
