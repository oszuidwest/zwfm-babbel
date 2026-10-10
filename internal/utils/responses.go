package utils

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
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
	c.JSON(http.StatusOK, data)
}

// NoContent responds with HTTP 204 No Content.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// PaginatedResponse responds with paginated data in a consistent format.
func PaginatedResponse(c *gin.Context, data any, total int64, limit, offset int) {
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
	location := fmt.Sprintf("%s/%d", resourcePath, id)
	c.Header("Location", location)
	c.JSON(http.StatusCreated, IDMessageResponse{
		ID:      id,
		Message: message,
	})
}

// AcceptedWithLocation responds with HTTP 202 Accepted and a Location header
// pointing at the resource to poll for completion.
func AcceptedWithLocation(c *gin.Context, id int64, resourcePath string, body any) {
	c.Header("Location", fmt.Sprintf("%s/%d", resourcePath, id))
	c.JSON(http.StatusAccepted, body)
}

// CreatedWithMessage responds with HTTP 201 Created status and a success message.
func CreatedWithMessage(c *gin.Context, message string) {
	c.JSON(http.StatusCreated, MessageResponse{Message: message})
}

// RFC 9457 Problem Details compatible error response functions.

// ProblemValidationError responds with HTTP 422 for input validation failures.
func ProblemValidationError(c *gin.Context, detail string, errors []apperrors.FieldError) {
	ProblemCustom(c, ProblemTypeValidationError, "Validation Error", http.StatusUnprocessableEntity, detail, errors...)
}

// ProblemNotFound responds with HTTP 404 Not Found.
func ProblemNotFound(c *gin.Context, resource string) {
	ProblemCustom(c, ProblemTypeResourceNotFound, "Resource Not Found", http.StatusNotFound, resource+" not found")
}

// ProblemAuthentication responds with HTTP 401 Unauthorized.
// Per RFC 7235, includes WWW-Authenticate header.
func ProblemAuthentication(c *gin.Context, detail string) {
	c.Header("WWW-Authenticate", `Session realm="Babbel API"`)
	ProblemCustom(c, ProblemTypeAuthenticationRequired, "Authentication Required", http.StatusUnauthorized, detail)
}

// ProblemInternalServer responds with HTTP 500 Internal Server Error.
func ProblemInternalServer(c *gin.Context, detail string) {
	ProblemCustom(c, ProblemTypeInternalServerError, "Internal Server Error", http.StatusInternalServerError, detail)
}

// ProblemBadRequestValidationError responds with HTTP 400 and field-level parse errors.
func ProblemBadRequestValidationError(c *gin.Context, detail string, errors []apperrors.FieldError) {
	ProblemCustom(c, ProblemTypeBadRequest, "Bad Request", http.StatusBadRequest, detail, errors...)
}

// ProblemPayloadTooLarge responds with HTTP 413 for JSON request bodies above the size cap.
func ProblemPayloadTooLarge(c *gin.Context) {
	ProblemCustom(
		c,
		ProblemTypePayloadTooLarge,
		"Payload Too Large",
		http.StatusRequestEntityTooLarge,
		"Request body too large",
	)
}

// ProblemNotAcceptable responds with HTTP 406 when the Accept header excludes the response media type.
func ProblemNotAcceptable(c *gin.Context, detail string) {
	ProblemCustom(
		c,
		ProblemTypeNotAcceptable,
		"Not Acceptable",
		http.StatusNotAcceptable,
		detail,
	)
}

// ProblemCustom responds with a custom problem type and optional field errors.
func ProblemCustom(c *gin.Context, problemType, title string, status int, detail string, errors ...apperrors.FieldError) {
	problem := NewProblemDetail(problemType, title, status, detail)
	problem.Errors = errors
	SendProblem(c, problem)
}

// ProblemExtended responds with an RFC 9457 problem including code and hint fields.
// This is used by handleServiceError for typed error responses.
func ProblemExtended(c *gin.Context, status int, detail, code, hint string) {
	SendProblem(c, NewExtendedProblem(status, detail, code, hint))
}

// NewExtendedProblem builds the problem sent by ProblemExtended for callers
// that add extension fields before sending.
func NewExtendedProblem(status int, detail, code, hint string) *ProblemDetail {
	problem := NewProblemDetail("https://babbel.api/problems/"+code, http.StatusText(status), status, detail)
	problem.Code = code
	problem.Hint = hint
	return problem
}
