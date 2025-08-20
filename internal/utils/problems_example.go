// This file contains example JSON responses for RFC 9457 Problem Details
// These are included for documentation purposes and demonstrate the format

package utils

// Example RFC 9457 Problem Details responses:

/*
// Validation Error (422)
{
  "type": "https://babbel.api/problems/validation-error",
  "title": "Validation Error",
  "status": 422,
  "detail": "The request contains invalid data",
  "instance": "/api/v1/stories",
  "timestamp": "2025-08-13T10:30:00Z",
  "errors": [
    {
      "field": "title",
      "message": "Title is required"
    },
    {
      "field": "text",
      "message": "Text is required"
    }
  ]
}

// Resource Not Found (404)
{
  "type": "https://babbel.api/problems/resource-not-found",
  "title": "Resource Not Found",
  "status": 404,
  "detail": "Station not found",
  "instance": "/api/v1/stations/999",
  "timestamp": "2025-08-13T10:30:00Z"
}

// Duplicate Resource (409)
{
  "type": "https://babbel.api/problems/duplicate-resource",
  "title": "Duplicate Resource",
  "status": 409,
  "detail": "Station name already exists",
  "instance": "/api/v1/stations",
  "timestamp": "2025-08-13T10:30:00Z"
}

// Authentication Required (401)
{
  "type": "https://babbel.api/problems/authentication-required",
  "title": "Authentication Required",
  "status": 401,
  "detail": "Invalid username or password",
  "instance": "/api/v1/auth/login",
  "timestamp": "2025-08-13T10:30:00Z"
}

// Insufficient Permissions (403)
{
  "type": "https://babbel.api/problems/insufficient-permissions",
  "title": "Insufficient Permissions",
  "status": 403,
  "detail": "You do not have permission to access this resource",
  "instance": "/api/v1/admin/users",
  "timestamp": "2025-08-13T10:30:00Z"
}

// Internal Server Error (500)
{
  "type": "https://babbel.api/problems/internal-server-error",
  "title": "Internal Server Error",
  "status": 500,
  "detail": "Failed to create station due to database error",
  "instance": "/api/v1/stations",
  "timestamp": "2025-08-13T10:30:00Z",
  "trace_id": "req-12345-67890"
}

// Bad Request (400)
{
  "type": "https://babbel.api/problems/bad-request",
  "title": "Bad Request",
  "status": 400,
  "detail": "Invalid login request format",
  "instance": "/api/v1/auth/login",
  "timestamp": "2025-08-13T10:30:00Z"
}
*/
