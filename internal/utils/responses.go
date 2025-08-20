// Package utils provides shared utility functions.
package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)


// Success responds with HTTP 200 OK status and the provided data.
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, data)
}

// NoContent responds with HTTP 204 No Content.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// PaginatedResponse responds with paginated data in a consistent format.
func PaginatedResponse(c *gin.Context, data interface{}, total int64, limit, offset int) {
	c.JSON(http.StatusOK, gin.H{
		"data":   data,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// CreatedWithID responds with HTTP 201 Created status including the new resource ID.
func CreatedWithID(c *gin.Context, id int64, message string) {
	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"message": message,
	})
}

// SuccessWithMessage responds with HTTP 200 OK status and a success message.
func SuccessWithMessage(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{"message": message})
}

// RFC 9457 Problem Details compatible error response functions.

// ProblemValidationError responds with HTTP 422 for input validation failures.
func ProblemValidationError(c *gin.Context, detail string, errors []ValidationError) {
	problem := NewValidationProblem(detail, c.Request.URL.Path, errors)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemNotFound responds with HTTP 404 Not Found.
func ProblemNotFound(c *gin.Context, resource string) {
	problem := NewNotFoundProblem(resource, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemDuplicate responds with HTTP 409 Conflict.
func ProblemDuplicate(c *gin.Context, resource string) {
	problem := NewDuplicateProblem(resource, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemAuthentication responds with HTTP 401 Unauthorized.
func ProblemAuthentication(c *gin.Context, detail string) {
	problem := NewAuthenticationProblem(detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemInternalServer responds with HTTP 500 Internal Server Error.
func ProblemInternalServer(c *gin.Context, detail string) {
	problem := NewInternalServerProblem(detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemBadRequest responds with HTTP 400 Bad Request.
func ProblemBadRequest(c *gin.Context, detail string) {
	problem := NewBadRequestProblem(detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}

// ProblemCustom responds with a custom problem type.
func ProblemCustom(c *gin.Context, problemType, title string, status int, detail string) {
	problem := NewProblemDetail(problemType, title, status, detail, c.Request.URL.Path)
	if traceID := getTraceID(c); traceID != "" {
		problem.WithTraceID(traceID)
	}
	SendProblem(c, problem)
}
