package utils

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProblemDetail(t *testing.T) {
	problem := NewProblemDetail(
		ProblemTypeValidationError,
		"Validation Error",
		422,
		"The request contains invalid data",
		"/api/v1/test",
	)

	assert.Equal(t, ProblemTypeValidationError, problem.Type)
	assert.Equal(t, "Validation Error", problem.Title)
	assert.Equal(t, 422, problem.Status)
	assert.Equal(t, "The request contains invalid data", problem.Detail)
	assert.Equal(t, "/api/v1/test", problem.Instance)
	assert.NotEmpty(t, problem.Timestamp)

	// Verify timestamp is valid ISO 8601
	_, err := time.Parse(time.RFC3339, problem.Timestamp)
	assert.NoError(t, err)
}

func TestNewValidationProblem(t *testing.T) {
	errors := []ValidationError{
		{Field: "name", Message: "Name is required"},
		{Field: "email", Message: "Email must be valid"},
	}

	problem := NewValidationProblem(
		"Multiple validation errors occurred",
		"/api/v1/users",
		errors,
	)

	assert.Equal(t, ProblemTypeValidationError, problem.Type)
	assert.Equal(t, "Validation Error", problem.Title)
	assert.Equal(t, 422, problem.Status)
	assert.Equal(t, "Multiple validation errors occurred", problem.Detail)
	assert.Equal(t, "/api/v1/users", problem.Instance)
	assert.Len(t, problem.Errors, 2)
	assert.Equal(t, "name", problem.Errors[0].Field)
	assert.Equal(t, "Name is required", problem.Errors[0].Message)
}

func TestProblemDetailHelpers(t *testing.T) {
	tests := []struct {
		name           string
		constructor    func() *ProblemDetail
		expectedType   string
		expectedStatus int
	}{
		{
			name: "NotFound",
			constructor: func() *ProblemDetail {
				return NewNotFoundProblem("User", "/api/v1/users/123")
			},
			expectedType:   ProblemTypeResourceNotFound,
			expectedStatus: 404,
		},
		{
			name: "Duplicate",
			constructor: func() *ProblemDetail {
				return NewDuplicateProblem("Username", "/api/v1/users")
			},
			expectedType:   ProblemTypeDuplicateResource,
			expectedStatus: 409,
		},
		{
			name: "Authentication",
			constructor: func() *ProblemDetail {
				return NewAuthenticationProblem("Invalid credentials", "/api/v1/auth/login")
			},
			expectedType:   ProblemTypeAuthenticationRequired,
			expectedStatus: 401,
		},
		{
			name: "Authorization",
			constructor: func() *ProblemDetail {
				return NewAuthorizationProblem("Insufficient permissions", "/api/v1/admin")
			},
			expectedType:   ProblemTypeInsufficientPermissions,
			expectedStatus: 403,
		},
		{
			name: "InternalServer",
			constructor: func() *ProblemDetail {
				return NewInternalServerProblem("Database connection failed", "/api/v1/test")
			},
			expectedType:   ProblemTypeInternalServerError,
			expectedStatus: 500,
		},
		{
			name: "BadRequest",
			constructor: func() *ProblemDetail {
				return NewBadRequestProblem("Invalid JSON format", "/api/v1/test")
			},
			expectedType:   ProblemTypeBadRequest,
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problem := tt.constructor()
			assert.Equal(t, tt.expectedType, problem.Type)
			assert.Equal(t, tt.expectedStatus, problem.Status)
			assert.NotEmpty(t, problem.Title)
			assert.NotEmpty(t, problem.Detail)
		})
	}
}

func TestWithTraceID(t *testing.T) {
	problem := NewBadRequestProblem("Test error", "/api/v1/test")
	traceID := "trace-123456"

	problem.WithTraceID(traceID)
	assert.Equal(t, traceID, problem.TraceID)
}

func TestSendProblem(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/test", nil)

	problem := NewValidationProblem("Test validation error", "", []ValidationError{
		{Field: "name", Message: "Name is required"},
	})

	SendProblem(c, problem)

	// Check status code
	assert.Equal(t, 422, w.Code)

	// Check content type
	assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))

	// Check response body
	var response ProblemDetail
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, ProblemTypeValidationError, response.Type)
	assert.Equal(t, "Validation Error", response.Title)
	assert.Equal(t, 422, response.Status)
	assert.Equal(t, "/api/v1/test", response.Instance) // Should be set from request path
	assert.Len(t, response.Errors, 1)
}

func TestProblemValidationErrorResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/stories", nil)

	errors := []ValidationError{
		{Field: "title", Message: "Title is required"},
		{Field: "text", Message: "Text is required"},
	}

	ProblemValidationError(c, "The request contains invalid data", errors)

	// Verify response
	assert.Equal(t, 422, w.Code)
	assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))

	var response ProblemDetail
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, ProblemTypeValidationError, response.Type)
	assert.Equal(t, "Validation Error", response.Title)
	assert.Equal(t, 422, response.Status)
	assert.Equal(t, "The request contains invalid data", response.Detail)
	assert.Equal(t, "/api/v1/stories", response.Instance)
	assert.NotEmpty(t, response.Timestamp)
	assert.Len(t, response.Errors, 2)
}

func TestProblemNotFoundResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/stations/999", nil)

	ProblemNotFound(c, "Station")

	// Verify response
	assert.Equal(t, 404, w.Code)
	assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))

	var response ProblemDetail
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, ProblemTypeResourceNotFound, response.Type)
	assert.Equal(t, "Resource Not Found", response.Title)
	assert.Equal(t, 404, response.Status)
	assert.Equal(t, "Station not found", response.Detail)
	assert.Equal(t, "/api/v1/stations/999", response.Instance)
}
