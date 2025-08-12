// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// InternalServerError responds with a 500 Internal Server Error and custom message.
func InternalServerError(c *gin.Context, message string) {
	c.JSON(http.StatusInternalServerError, gin.H{"error": message})
}

// NotFound responds with a 404 Not Found error for the specified resource.
func NotFound(c *gin.Context, resource string) {
	c.JSON(http.StatusNotFound, gin.H{"error": resource + " not found"})
}

// BadRequest responds with a 400 Bad Request error and custom message.
func BadRequest(c *gin.Context, message string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": message})
}

// Success responds with a 200 OK status and the provided data payload.
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, data)
}

// Created responds with a 201 Created status and the provided data payload.
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, data)
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
