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
	// SortAsc orders query results from lowest to highest value.
	SortAsc SortDirection = "asc"
	// SortDesc orders query results from highest to lowest value.
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
	// FilterEquals selects records whose field equals the supplied value.
	FilterEquals FilterOperator = "eq"
	// FilterNotEquals selects records whose field differs from the supplied value.
	FilterNotEquals FilterOperator = "neq"
	// FilterGreaterThan selects records whose field is greater than the supplied value.
	FilterGreaterThan FilterOperator = "gt"
	// FilterGreaterOrEq selects records whose field is greater than or equal to the supplied value.
	FilterGreaterOrEq FilterOperator = "gte"
	// FilterLessThan selects records whose field is less than the supplied value.
	FilterLessThan FilterOperator = "lt"
	// FilterLessOrEq selects records whose field is less than or equal to the supplied value.
	FilterLessOrEq FilterOperator = "lte"
	// FilterLike selects records whose field matches a SQL LIKE pattern.
	FilterLike FilterOperator = "like"
	// FilterIn selects records whose field is one of the supplied values.
	FilterIn FilterOperator = "in"
	// FilterBetween selects records whose field falls within the supplied range.
	FilterBetween FilterOperator = "between"
	// FilterBitwiseAnd selects records whose bitmask field overlaps the supplied mask.
	FilterBitwiseAnd FilterOperator = "band"
	// FilterIsNull selects records whose field is NULL.
	FilterIsNull FilterOperator = "null"
	// FilterIsNotNull selects records whose field is not NULL.
	FilterIsNotNull FilterOperator = "not_null"
)

// FilterCondition represents a single filter condition.
type FilterCondition struct {
	Field    string
	Operator FilterOperator
	Value    any
}

// UnknownFieldError indicates a query referenced a field that is not in the
// resource's FieldMapping. Surfaced through handleServiceError as a structured
// 422 response so the handler does not silently drop the clause.
type UnknownFieldError struct {
	Kind  string // "filter" or "sort"
	Field string
}

// Error formats the unknown-field message used by repository list queries.
func (e *UnknownFieldError) Error() string {
	return fmt.Sprintf("unknown %s field %q", e.Kind, e.Field)
}

// InvalidFilterError indicates a filter condition could not be applied because
// the value shape does not match the operator (e.g. LIKE with a non-string
// value, BETWEEN without two values, BAND on a non-allowlisted field).
type InvalidFilterError struct {
	Field    string
	Operator FilterOperator
	Reason   string
}

// Error formats the invalid-filter message returned for malformed filter clauses.
func (e *InvalidFilterError) Error() string {
	return fmt.Sprintf("invalid filter[%s][%s]: %s", e.Field, e.Operator, e.Reason)
}

// ListQuery contains parameters for listing entities.
type ListQuery struct {
	Limit   int
	Offset  int
	Sort    []SortField
	Filters []FilterCondition
	Search  string
	// Trashed controls soft-delete filtering: "" (default, active only), "only", or "with".
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

// ApplyListQuery applies pagination, filtering, sorting, and search to a GORM query.
// Returns a ListResult with the data and pagination info.
// The fieldMapping is used to validate and map field names to prevent SQL injection.
// searchFields are the database columns to search in when query.Search is set.
// defaultSort specifies the default sort order when no user-provided sort fields are given.
// It uses the same SortField type as user sorts and is validated against fieldMapping.
func ApplyListQuery[T any](db *gorm.DB, query *ListQuery, fieldMapping FieldMapping, searchFields []string, defaultSort []SortField) (*ListResult[T], error) {
	if query == nil {
		query = NewListQuery()
	}

	db = applySearch(db, query.Search, searchFields)

	for _, filter := range query.Filters {
		next, err := applyFilterCondition(db, filter, fieldMapping)
		if err != nil {
			return nil, err
		}
		db = next
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	sortedDB, err := applySorting(db, query.Sort, defaultSort, fieldMapping)
	if err != nil {
		return nil, err
	}
	db = applyPagination(sortedDB, query.Limit, query.Offset)

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

// likePatternEscaper escapes the LIKE metacharacters so user input is matched
// literally. MySQL's LIKE treats % and _ as wildcards and \ as the default
// escape character, so all three must be escaped. Backslash is listed first so
// the replacer never re-escapes the escapes it just inserted.
var likePatternEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// escapeLikePattern escapes LIKE wildcards in user input so a search for
// "50%" or "a_b" matches literally instead of being interpreted as a pattern.
func escapeLikePattern(s string) string {
	return likePatternEscaper.Replace(s)
}

// likeEscapeClause makes the backslash escape character explicit so LIKE
// matching does not depend on the server's default ESCAPE setting. The doubled
// backslash is a MySQL string literal that resolves to a single backslash,
// matching the escape character inserted by escapeLikePattern.
const likeEscapeClause = ` ESCAPE '\\'`

// applySearch attaches a search WHERE clause across all search fields.
func applySearch(db *gorm.DB, search string, searchFields []string) *gorm.DB {
	if search == "" || len(searchFields) == 0 {
		return db
	}
	searchPattern := "%" + escapeLikePattern(search) + "%"
	conditions := make([]string, len(searchFields))
	args := make([]any, len(searchFields))
	for i, field := range searchFields {
		conditions[i] = field + " LIKE ?" + likeEscapeClause
		args[i] = searchPattern
	}
	return db.Where(strings.Join(conditions, " OR "), args...)
}

// applySorting applies user sort with whitelist validation, falling back to
// defaultSort when no user sort was provided. Default sort comes from trusted
// server code and may legally reference columns that the API does not expose.
func applySorting(db *gorm.DB, userSort, defaultSort []SortField, fieldMapping FieldMapping) (*gorm.DB, error) {
	if len(userSort) == 0 {
		for _, sf := range defaultSort {
			dbField, ok := fieldMapping[sf.Field]
			if !ok {
				continue
			}
			db = db.Order(dbField + " " + sortDirectionSQL(sf.Direction))
		}
		return db, nil
	}
	for _, sf := range userSort {
		dbField, ok := fieldMapping[sf.Field]
		if !ok {
			return nil, &UnknownFieldError{Kind: "sort", Field: sf.Field}
		}
		db = db.Order(dbField + " " + sortDirectionSQL(sf.Direction))
	}
	return db, nil
}

// applyPagination attaches LIMIT/OFFSET. Zero or negative values are skipped.
func applyPagination(db *gorm.DB, limit, offset int) *gorm.DB {
	if limit > 0 {
		db = db.Limit(limit)
	}
	if offset > 0 {
		db = db.Offset(offset)
	}
	return db
}

// sortDirectionSQL maps a SortDirection to its SQL token.
func sortDirectionSQL(d SortDirection) string {
	if d == SortDesc {
		return "DESC"
	}
	return "ASC"
}

// applyFilterCondition applies a single filter condition to the query.
// Returns an *UnknownFieldError or *InvalidFilterError when the condition
// cannot be applied, so the caller can surface a 422 instead of silently
// dropping the clause and returning an unfiltered result set.
func applyFilterCondition(db *gorm.DB, filter FilterCondition, fieldMapping FieldMapping) (*gorm.DB, error) {
	// Map public field names through a whitelist because SQL identifiers cannot
	// be parameterized.
	dbField, ok := fieldMapping[filter.Field]
	if !ok {
		return nil, &UnknownFieldError{Kind: "filter", Field: filter.Field}
	}

	// Restrict bitwise operators to allowed fields only.
	if filter.Operator == FilterBitwiseAnd && !bitwiseAllowedFields[filter.Field] {
		return nil, &InvalidFilterError{
			Field:    filter.Field,
			Operator: filter.Operator,
			Reason:   "bitwise operator not allowed on this field",
		}
	}

	// Special case for LIKE operator (needs pattern wrapping)
	if filter.Operator == FilterLike {
		s, ok := filter.Value.(string)
		if !ok {
			return nil, &InvalidFilterError{
				Field:    filter.Field,
				Operator: filter.Operator,
				Reason:   "expected string value",
			}
		}
		return db.Where(dbField+" LIKE ?"+likeEscapeClause, "%"+escapeLikePattern(s)+"%"), nil
	}

	if filter.Operator == FilterBetween {
		values, ok := filter.Value.([]string)
		if !ok || len(values) != 2 {
			return nil, &InvalidFilterError{
				Field:    filter.Field,
				Operator: filter.Operator,
				Reason:   "expected two comma-separated values",
			}
		}
		return db.Where(fmt.Sprintf("%s BETWEEN ? AND ?", dbField), values[0], values[1]), nil
	}

	// dbField comes from fieldMapping, so these identifier fragments remain whitelist-bound.
	if filter.Operator == FilterIsNull {
		return db.Where(dbField + " IS NULL"), nil
	}

	if filter.Operator == FilterIsNotNull {
		return db.Where(dbField + " IS NOT NULL"), nil
	}

	if format, ok := operatorFormats[filter.Operator]; ok {
		return db.Where(fmt.Sprintf(format, dbField), filter.Value), nil
	}

	return nil, &InvalidFilterError{
		Field:    filter.Field,
		Operator: filter.Operator,
		Reason:   "unsupported operator",
	}
}
