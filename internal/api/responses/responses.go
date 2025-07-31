// Package responses provides standardized HTTP response helpers for the API.
package responses

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorResponse represents a standard error response format.
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// PaginatedResponse represents a paginated list response.
type PaginatedResponse struct {
	Data   interface{} `json:"data"`
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

// Success responds with a 200 OK status and the provided data.
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, data)
}

// Created responds with a 201 Created status and the provided data.
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, data)
}

// NoContent responds with a 204 No Content status.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// BadRequest responds with a 400 Bad Request status and error message.
func BadRequest(c *gin.Context, message string, details ...map[string]interface{}) {
	response := ErrorResponse{
		Error:   "bad_request",
		Message: message,
	}
	if len(details) > 0 {
		response.Details = details[0]
	}
	c.JSON(http.StatusBadRequest, response)
}

// NotFound responds with a 404 Not Found status and error message.
func NotFound(c *gin.Context, message string) {
	c.JSON(http.StatusNotFound, ErrorResponse{
		Error:   "not_found",
		Message: message,
	})
}

// InternalServerError responds with a 500 Internal Server Error status.
func InternalServerError(c *gin.Context, message string) {
	c.JSON(http.StatusInternalServerError, ErrorResponse{
		Error:   "internal_server_error",
		Message: message,
	})
}

// Paginated responds with paginated data including total count and pagination info.
func Paginated(c *gin.Context, data interface{}, total int64, limit, offset int) {
	c.Header("X-Total-Count", fmt.Sprintf("%d", total))
	c.Header("X-Limit", fmt.Sprintf("%d", limit))
	c.Header("X-Offset", fmt.Sprintf("%d", offset))
	c.JSON(http.StatusOK, PaginatedResponse{
		Data:   data,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}
