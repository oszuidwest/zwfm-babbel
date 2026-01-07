// Package repository provides data access abstractions.
package repository

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// FieldMapping maps API field names to database column names for security.
type FieldMapping map[string]string

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
	FilterBitwiseAnd  FilterOperator = "band"
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
	// Trashed controls soft-delete filtering: "" (default, active only), "only", "with"
	Trashed string
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
		// Trashed defaults to empty string (show only active/non-deleted)
	}
}

// prefixSortColumns adds table prefix to columns in a sort string that don't already have a prefix.
// E.g., prefixSortColumns("created_at DESC, id ASC", "bulletins") returns "bulletins.created_at DESC, bulletins.id ASC"
func prefixSortColumns(sortStr, tableName string) string {
	if tableName == "" || sortStr == "" {
		return sortStr
	}

	// Split by comma for multiple sort fields
	parts := strings.Split(sortStr, ",")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		// Split into column and direction (e.g., "created_at DESC" -> ["created_at", "DESC"])
		tokens := strings.Fields(part)
		if len(tokens) >= 1 {
			column := tokens[0]
			// Only prefix if column doesn't already have a table prefix
			if !strings.Contains(column, ".") {
				tokens[0] = tableName + "." + column
			}
			parts[i] = strings.Join(tokens, " ")
		}
	}

	return strings.Join(parts, ", ")
}

// ApplyListQuery applies pagination, filtering, sorting, and search to a GORM query.
// Returns a ListResult with the data and pagination info.
// The fieldMapping is used to validate and map field names to prevent SQL injection.
// searchFields are the database columns to search in when query.Search is set.
// defaultSort is used when no sort fields are provided (e.g., "created_at DESC").
// tableName is the primary table name used to prefix columns in defaultSort to avoid
// ambiguous column errors when JOINs are used (e.g., "bulletins", "stories").
func ApplyListQuery[T any](db *gorm.DB, query *ListQuery, fieldMapping FieldMapping, searchFields []string, defaultSort string, tableName string) (*ListResult[T], error) {
	if query == nil {
		query = NewListQuery()
	}

	// Apply search - use string join for proper OR grouping
	if query.Search != "" && len(searchFields) > 0 {
		searchPattern := "%" + query.Search + "%"
		conditions := make([]string, len(searchFields))
		args := make([]any, len(searchFields))
		for i, field := range searchFields {
			conditions[i] = field + " LIKE ?"
			args[i] = searchPattern
		}
		db = db.Where(strings.Join(conditions, " OR "), args...)
	}

	// Apply filters
	for _, filter := range query.Filters {
		db = applyFilterCondition(db, filter, fieldMapping)
	}

	// Count total before pagination
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	// Apply sorting
	if len(query.Sort) > 0 {
		for _, sf := range query.Sort {
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
	} else if defaultSort != "" {
		db = db.Order(prefixSortColumns(defaultSort, tableName))
	}

	// Apply pagination
	if query.Limit > 0 {
		db = db.Limit(query.Limit)
	}
	if query.Offset > 0 {
		db = db.Offset(query.Offset)
	}

	// Execute query
	var data []T
	if err := db.Find(&data).Error; err != nil {
		return nil, err
	}

	return &ListResult[T]{
		Data:   data,
		Total:  total,
		Limit:  query.Limit,
		Offset: query.Offset,
	}, nil
}

// bitwiseAllowedFields restricts bitwise operators to specific fields for security.
var bitwiseAllowedFields = map[string]bool{
	"weekdays": true,
}

// operatorFormats maps filter operators to their SQL format strings.
var operatorFormats = map[FilterOperator]string{
	FilterEquals:      "%s = ?",
	FilterNotEquals:   "%s != ?",
	FilterGreaterThan: "%s > ?",
	FilterGreaterOrEq: "%s >= ?",
	FilterLessThan:    "%s < ?",
	FilterLessOrEq:    "%s <= ?",
	FilterIn:          "%s IN ?",
	FilterBitwiseAnd:  "(%s & ?) != 0",
}

// applyFilterCondition applies a single filter condition to the query.
func applyFilterCondition(db *gorm.DB, filter FilterCondition, fieldMapping FieldMapping) *gorm.DB {
	// Validate field name to prevent SQL injection
	dbField, ok := fieldMapping[filter.Field]
	if !ok {
		return db
	}

	// Restrict bitwise operators to allowed fields only
	if filter.Operator == FilterBitwiseAnd && !bitwiseAllowedFields[filter.Field] {
		return db
	}

	// Special case for LIKE operator (needs pattern wrapping)
	if filter.Operator == FilterLike {
		if s, ok := filter.Value.(string); ok {
			return db.Where(dbField+" LIKE ?", "%"+s+"%")
		}
		return db
	}

	// Use map lookup for standard operators
	if format, ok := operatorFormats[filter.Operator]; ok {
		return db.Where(fmt.Sprintf(format, dbField), filter.Value)
	}

	return db
}
