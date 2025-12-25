package utils

import (
	"database/sql"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// HandleDBError processes common database errors and sends appropriate RFC 9457 problem responses.
// Returns true if an error was handled (response sent), false if no error or unhandled.
// Use this for consistent error handling across all handlers.
//
// Example usage:
//
//	result, err := h.db.ExecContext(ctx, query, args...)
//	if HandleDBError(c, err, "Station") {
//	    return
//	}
func HandleDBError(c *gin.Context, err error, resource string) bool {
	if err == nil {
		return false
	}

	// Log the error for debugging
	logger.Error("Database error for %s: %v", resource, err)

	errStr := err.Error()

	switch {
	case err == sql.ErrNoRows:
		ProblemNotFound(c, resource)

	case strings.Contains(errStr, "Duplicate entry"):
		ProblemDuplicate(c, resource)

	case strings.Contains(errStr, "foreign key constraint fails"):
		// Foreign key constraint on INSERT/UPDATE (referenced record doesn't exist)
		ProblemBadRequest(c, "Referenced "+resource+" does not exist")

	case strings.Contains(errStr, "Cannot delete or update a parent row"):
		// Foreign key constraint on DELETE (record is referenced by others)
		ProblemDependencyConstraint(c, resource)

	case strings.Contains(errStr, "Data too long"):
		ProblemValidationError(c, "Data exceeds maximum length for "+resource, nil)

	case strings.Contains(errStr, "Incorrect"):
		// Handles "Incorrect integer value", "Incorrect datetime value", etc.
		ProblemValidationError(c, "Invalid data format for "+resource, nil)

	case strings.Contains(errStr, "Out of range"):
		ProblemValidationError(c, "Value out of range for "+resource, nil)

	default:
		ProblemInternalServer(c, "Database operation failed for "+resource)
	}

	return true
}

// HandleDBErrorWithContext is like HandleDBError but allows custom context message.
func HandleDBErrorWithContext(c *gin.Context, err error, resource, context string) bool {
	if err == nil {
		return false
	}

	logger.Error("Database error for %s (%s): %v", resource, context, err)

	if err == sql.ErrNoRows {
		ProblemNotFound(c, resource)
		return true
	}

	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "Duplicate entry"):
		ProblemDuplicate(c, resource)

	case strings.Contains(errStr, "foreign key constraint"):
		ProblemBadRequest(c, context)

	default:
		ProblemInternalServer(c, context)
	}

	return true
}
