// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// CountRecords returns the total number of records in the specified table with optional WHERE clause.
func CountRecords(db *sqlx.DB, tableName string, whereClause string, args ...interface{}) (int64, error) {
	var count int64
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)

	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	if err := db.Get(&count, query, args...); err != nil {
		return 0, err
	}

	return count, nil
}

// CountWithJoins returns the count of records using complex query with joins and custom conditions.
func CountWithJoins(db *sqlx.DB, query string, args ...interface{}) (int64, error) {
	var count int64

	if err := db.Get(&count, query, args...); err != nil {
		return 0, err
	}

	return count, nil
}

// CountDependencies counts records that depend on a specific foreign key for cascade delete validation.
func CountDependencies(db *sqlx.DB, tableName, foreignKeyColumn string, id int) (int, error) {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s = ?", tableName, foreignKeyColumn)

	if err := db.Get(&count, query, id); err != nil {
		return 0, err
	}

	return count, nil
}

// CountByCondition counts records that meet a specific condition with parameterized arguments.
func CountByCondition(db *sqlx.DB, tableName, condition string, args ...interface{}) (int, error) {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s", tableName, condition)

	if err := db.Get(&count, query, args...); err != nil {
		return 0, err
	}

	return count, nil
}

// CountActivesExcludingID counts active records (not suspended/deleted) excluding a specific ID for uniqueness validation.
func CountActivesExcludingID(db *sqlx.DB, tableName, condition string, id int) (int, error) {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s AND id != ?", tableName, condition)

	if err := db.Get(&count, query, id); err != nil {
		return 0, err
	}

	return count, nil
}

// HandleDatabaseError provides user-friendly error messages for common database errors
// while logging the actual error for debugging purposes
func HandleDatabaseError(c *gin.Context, err error, operation string) {
	if err == nil {
		return
	}

	// Log the actual error for debugging
	logger.Error("Database error during %s: %v", operation, err)

	// Provide user-friendly error messages based on error type
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "Data too long"):
		BadRequest(c, "One or more fields exceed maximum length")
	case strings.Contains(errStr, "Duplicate entry"):
		BadRequest(c, "A resource with these details already exists")
	case strings.Contains(errStr, "foreign key constraint"):
		BadRequest(c, "Cannot complete operation: resource is referenced by other data")
	case strings.Contains(errStr, "cannot be null"):
		BadRequest(c, "Required field is missing")
	case strings.Contains(errStr, "Out of range"):
		BadRequest(c, "Numeric value is out of acceptable range")
	case strings.Contains(errStr, "Incorrect datetime"):
		BadRequest(c, "Invalid date or time format")
	default:
		InternalServerError(c, fmt.Sprintf("Failed to %s due to database error", operation))
	}
}
