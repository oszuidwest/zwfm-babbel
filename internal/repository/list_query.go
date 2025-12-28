// Package repository provides data access abstractions.
package repository

import (
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

// ApplyListQuery applies pagination, filtering, sorting, and search to a GORM query.
// Returns a ListResult with the data and pagination info.
// The fieldMapping is used to validate and map field names to prevent SQL injection.
// searchFields are the database columns to search in when query.Search is set.
// defaultSort is used when no sort fields are provided (e.g., "name ASC").
func ApplyListQuery[T any](db *gorm.DB, query *ListQuery, fieldMapping FieldMapping, searchFields []string, defaultSort string) (*ListResult[T], error) {
	if query == nil {
		query = NewListQuery()
	}

	// Apply search
	if query.Search != "" && len(searchFields) > 0 {
		searchPattern := "%" + query.Search + "%"
		for i, field := range searchFields {
			if i == 0 {
				db = db.Where(field+" LIKE ?", searchPattern)
			} else {
				db = db.Or(field+" LIKE ?", searchPattern)
			}
		}
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
		db = db.Order(defaultSort)
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

// applyFilterCondition applies a single filter condition to the query.
func applyFilterCondition(db *gorm.DB, filter FilterCondition, fieldMapping FieldMapping) *gorm.DB {
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
		return db
	}
}
