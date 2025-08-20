// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

// Story query constants for common JOIN operations
const (
	StoryWithVoiceQuery = `
        SELECT s.*, COALESCE(v.name, '') as voice_name
        FROM stories s 
        LEFT JOIN voices v ON s.voice_id = v.id`

	StoryWithVoiceWhereActive = StoryWithVoiceQuery + ` WHERE s.deleted_at IS NULL`
)

// BuildStoryQuery creates story queries with common joins and conditions for filtering deleted records.
func BuildStoryQuery(baseWhere string, includeDeleted bool) string {
	query := StoryWithVoiceQuery

	conditions := []string{}
	if baseWhere != "" {
		conditions = append(conditions, baseWhere)
	}
	if !includeDeleted {
		conditions = append(conditions, "s.deleted_at IS NULL")
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	return query
}

// FilterConfig defines configuration for a single filter
type FilterConfig struct {
	Column   string      // Database column name
	Value    interface{} // Filter value
	Operator string      // Comparison operator: "=", "IN", "IS NULL", "IS NOT NULL", ">=", "<=", etc.
	Table    string      // Optional table alias/prefix (e.g. "s" for "s.status")
}

// PostProcessor defines a function to modify results after querying but before response
type PostProcessor func(result interface{})

// QueryConfig defines configuration for GenericListWithJoins
type QueryConfig struct {
	BaseQuery     string         // SELECT ... FROM ... JOIN ... part
	CountQuery    string         // SELECT COUNT(*) FROM ... JOIN ... part
	Filters       []FilterConfig // Dynamic filters to apply
	DefaultOrder  string         // Default ORDER BY clause (without ORDER BY keyword)
	AllowedArgs   []interface{}  // Base arguments for the queries
	PostProcessor PostProcessor  // Optional function to process results after query
}

// BuildWhereClause builds WHERE clause and arguments from filter configurations for dynamic querying.
func BuildWhereClause(filters []FilterConfig) (whereClause string, args []interface{}) {
	if len(filters) == 0 {
		return "", nil
	}

	var conditions []string
	args = make([]interface{}, 0)

	for _, filter := range filters {
		column := filter.Column
		// Only add table prefix if column doesn't already contain parentheses (expression)
		if filter.Table != "" && !strings.Contains(filter.Column, "(") {
			column = filter.Table + "." + filter.Column
		}

		switch filter.Operator {
		case "IS NULL":
			conditions = append(conditions, column+" IS NULL")
		case "IS NOT NULL":
			conditions = append(conditions, column+" IS NOT NULL")
		case "IN":
			// Expecting Value to be a slice
			if slice, ok := filter.Value.([]interface{}); ok && len(slice) > 0 {
				placeholders := make([]string, len(slice))
				for i := range slice {
					placeholders[i] = "?"
				}
				conditions = append(conditions, column+" IN ("+strings.Join(placeholders, ", ")+")")
				args = append(args, slice...)
			}
		case "BETWEEN":
			// Expecting Value to be a slice with 2 elements
			if slice, ok := filter.Value.([]interface{}); ok && len(slice) == 2 {
				conditions = append(conditions, column+" BETWEEN ? AND ?")
				args = append(args, slice[0], slice[1])
			}
		case "LIKE":
			conditions = append(conditions, column+" LIKE ?")
			args = append(args, filter.Value)
		case "ILIKE":
			// Case-insensitive LIKE for databases that support it
			conditions = append(conditions, column+" ILIKE ?")
			args = append(args, filter.Value)
		case ">=", "<=", ">", "<", "!=", "<>":
			conditions = append(conditions, column+" "+filter.Operator+" ?")
			args = append(args, filter.Value)
		default:
			// Default to equality or custom operator
			operator := filter.Operator
			if operator == "" {
				operator = "="
			}
			conditions = append(conditions, column+" "+operator+" ?")
			args = append(args, filter.Value)
		}
	}

	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	return whereClause, args
}

// GenericListWithJoins handles paginated list requests with complex JOINs and filtering configurations.
func GenericListWithJoins(c *gin.Context, db *sqlx.DB, config QueryConfig, result interface{}) {
	limit, offset := GetPagination(c)

	// Build WHERE clause from filters
	whereClause, filterArgs := BuildWhereClause(config.Filters)

	// Combine base arguments with filter arguments
	var allArgs []interface{}
	allArgs = append(allArgs, config.AllowedArgs...)
	allArgs = append(allArgs, filterArgs...)

	// Build count query
	countQuery := config.CountQuery
	if whereClause != "" {
		countQuery += " " + whereClause
	}

	// Get total count
	total, err := CountWithJoins(db, countQuery, allArgs...)
	if err != nil {
		ProblemInternalServer(c, "Failed to count records")
		return
	}

	// Build main query
	mainQuery := config.BaseQuery
	if whereClause != "" {
		mainQuery += " " + whereClause
	}

	// Add ORDER BY clause
	if config.DefaultOrder != "" {
		mainQuery += " ORDER BY " + config.DefaultOrder
	}

	// Add pagination
	mainQuery += " LIMIT ? OFFSET ?"
	allArgs = append(allArgs, limit, offset)

	// Execute query
	if err := db.Select(result, mainQuery, allArgs...); err != nil {
		ProblemInternalServer(c, "Failed to fetch records")
		return
	}

	// Apply post-processing if provided
	if config.PostProcessor != nil {
		config.PostProcessor(result)
	}

	PaginatedResponse(c, result, total, limit, offset)
}



