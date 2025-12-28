// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// GormListConfig defines configuration for GORM list queries.
type GormListConfig struct {
	SearchFields []string          // Fields to search in (e.g., "name", "title")
	FieldMapping map[string]string // Maps API field names to DB columns
	DefaultSort  string            // Default ORDER BY clause (e.g., "name ASC")
	SoftDelete   bool              // Whether to filter deleted_at IS NULL
}

// GormListWithQuery handles paginated list requests using GORM.
// Uses Go generics for type safety and returns RFC 9457 errors on failure.
func GormListWithQuery[T any](c *gin.Context, db *gorm.DB, config GormListConfig) {
	params := ParseQueryParams(c)
	if params == nil {
		ProblemInternalServer(c, "Failed to parse query parameters")
		return
	}

	// Start building the query
	query := db.Model(new(T))

	// Apply soft delete filter
	if config.SoftDelete {
		query = query.Where("deleted_at IS NULL")
	}

	// Apply search
	query = applyGormSearch(query, params.Search, config.SearchFields)

	// Apply filters
	query = applyGormFilters(query, params.Filters, config.FieldMapping)

	// Count total before pagination
	var total int64
	if err := query.Count(&total).Error; err != nil {
		ProblemInternalServer(c, "Failed to count records")
		return
	}

	// Apply sorting
	query = applyGormSorting(query, params.Sort, config.FieldMapping, config.DefaultSort)

	// Apply pagination
	query = query.Offset(params.Offset).Limit(params.Limit)

	// Execute query
	var results []T
	if err := query.Find(&results).Error; err != nil {
		ProblemInternalServer(c, "Failed to fetch records")
		return
	}

	// Apply field filtering if requested
	var responseData any = results
	if len(params.Fields) > 0 {
		responseData = FilterStructFields(results, params.Fields)
	}

	PaginatedResponse(c, responseData, total, params.Limit, params.Offset)
}

// applyGormSearch applies search conditions across multiple fields.
func applyGormSearch(query *gorm.DB, search string, fields []string) *gorm.DB {
	if search == "" || len(fields) == 0 {
		return query
	}

	searchPattern := "%" + search + "%"
	conditions := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields))

	for _, field := range fields {
		conditions = append(conditions, field+" LIKE ?")
		args = append(args, searchPattern)
	}

	return query.Where(strings.Join(conditions, " OR "), args...)
}

// applyGormFilters applies filter conditions from query parameters.
func applyGormFilters(query *gorm.DB, filters map[string]FilterOperation, fieldMapping map[string]string) *gorm.DB {
	if len(filters) == 0 || fieldMapping == nil {
		return query
	}

	for field, filter := range filters {
		// Only allow fields in the mapping (security: prevents SQL injection)
		dbField, ok := fieldMapping[field]
		if !ok {
			continue
		}

		switch filter.Operator {
		case "IN":
			if len(filter.Values) > 0 {
				query = query.Where(dbField+" IN ?", filter.Values)
			}
		case "BETWEEN":
			if len(filter.Values) == 2 {
				query = query.Where(dbField+" BETWEEN ? AND ?", filter.Values[0], filter.Values[1])
			}
		case "LIKE":
			query = query.Where(dbField+" LIKE ?", filter.Value)
		default:
			// Handle =, !=, >, >=, <, <=
			query = query.Where(dbField+" "+filter.Operator+" ?", filter.Value)
		}
	}

	return query
}

// applyGormSorting applies sorting from query parameters.
func applyGormSorting(query *gorm.DB, sortFields []SortField, fieldMapping map[string]string, defaultSort string) *gorm.DB {
	if len(sortFields) == 0 {
		if defaultSort != "" {
			return query.Order(defaultSort)
		}
		return query
	}

	if fieldMapping == nil {
		if defaultSort != "" {
			return query.Order(defaultSort)
		}
		return query
	}

	for _, sf := range sortFields {
		// Only allow fields in the mapping (security: prevents SQL injection)
		dbField, ok := fieldMapping[sf.Field]
		if !ok {
			continue
		}

		direction := "ASC"
		if strings.ToUpper(sf.Direction) == "DESC" {
			direction = "DESC"
		}

		query = query.Order(dbField + " " + direction)
	}

	return query
}
