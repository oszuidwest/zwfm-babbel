// Package repository provides data access abstractions.
package repository

import (
	"strings"

	"gorm.io/gorm"
)

// SortDirection represents ascending or descending sort order.
type SortDirection string

const (
	SortAsc  SortDirection = "asc"
	SortDesc SortDirection = "desc"
)

// SortField represents a field to sort by with direction.
type SortField struct {
	Field     string
	Direction SortDirection
}

// FilterOperator represents comparison operators for filtering.
type FilterOperator string

const (
	FilterEquals      FilterOperator = "eq"
	FilterNotEquals   FilterOperator = "neq"
	FilterGreaterThan FilterOperator = "gt"
	FilterGreaterOrEq FilterOperator = "gte"
	FilterLessThan    FilterOperator = "lt"
	FilterLessOrEq    FilterOperator = "lte"
	FilterLike        FilterOperator = "like"
	FilterIn          FilterOperator = "in"
)

// FilterCondition represents a single filter condition.
type FilterCondition struct {
	Field    string
	Operator FilterOperator
	Value    any
}

// ListQuery contains parameters for listing entities.
type ListQuery struct {
	Limit   int
	Offset  int
	Sort    []SortField
	Filters []FilterCondition
	Search  string
	// Status filter for soft-delete support: "active", "deleted", "all"
	Status string
}

// ListResult contains paginated results.
type ListResult[T any] struct {
	Data   []T
	Total  int64
	Limit  int
	Offset int
}

// NewListQuery creates a ListQuery with sensible defaults.
func NewListQuery() *ListQuery {
	return &ListQuery{
		Limit:  20,
		Offset: 0,
		Status: "active",
	}
}

// applySearch applies search conditions across multiple fields using LIKE.
func applySearch(db *gorm.DB, search string, fields []string) *gorm.DB {
	if search == "" || len(fields) == 0 {
		return db
	}

	searchPattern := "%" + search + "%"
	conditions := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields))

	for _, field := range fields {
		conditions = append(conditions, field+" LIKE ?")
		args = append(args, searchPattern)
	}

	return db.Where(strings.Join(conditions, " OR "), args...)
}

// applyFilterWithMapping applies a single filter condition to the query with field mapping.
// Use this when you need to map API field names to database column names.
func applyFilterWithMapping(db *gorm.DB, filter FilterCondition, fieldMapping map[string]string) *gorm.DB {
	// Validate field name to prevent SQL injection
	dbField, ok := fieldMapping[filter.Field]
	if !ok {
		return db
	}

	switch filter.Operator {
	case FilterEquals:
		return db.Where(dbField+" = ?", filter.Value)
	case FilterNotEquals:
		return db.Where(dbField+" != ?", filter.Value)
	case FilterGreaterThan:
		return db.Where(dbField+" > ?", filter.Value)
	case FilterGreaterOrEq:
		return db.Where(dbField+" >= ?", filter.Value)
	case FilterLessThan:
		return db.Where(dbField+" < ?", filter.Value)
	case FilterLessOrEq:
		return db.Where(dbField+" <= ?", filter.Value)
	case FilterLike:
		if s, ok := filter.Value.(string); ok {
			return db.Where(dbField+" LIKE ?", "%"+s+"%")
		}
		return db
	case FilterIn:
		return db.Where(dbField+" IN ?", filter.Value)
	default:
		return db.Where(dbField+" = ?", filter.Value)
	}
}

// applySorting applies sorting from query parameters with field mapping.
func applySorting(db *gorm.DB, sortFields []SortField, fieldMapping map[string]string, defaultSort string) *gorm.DB {
	if len(sortFields) == 0 {
		if defaultSort != "" {
			return db.Order(defaultSort)
		}
		return db
	}

	for _, sf := range sortFields {
		// Validate field name to prevent SQL injection
		dbField, ok := fieldMapping[sf.Field]
		if !ok {
			continue
		}

		direction := "ASC"
		if sf.Direction == SortDesc {
			direction = "DESC"
		}

		db = db.Order(dbField + " " + direction)
	}

	return db
}
