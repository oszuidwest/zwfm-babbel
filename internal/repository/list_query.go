package repository

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// FieldMapping maps API field names to trusted columns and filter types.
type FieldMapping map[string]FilterField

// FilterField describes a list field's column and filter value contract.
type FilterField struct {
	Column   string
	Type     filterType
	Nullable bool
	Enum     []string // accepted values of a filterEnum field
}

// filterType selects how filter values are validated and bound.
type filterType string

const (
	filterString   filterType = "string"
	filterInteger  filterType = "integer"
	filterNumber   filterType = "number"
	filterDate     filterType = "date"
	filterDateTime filterType = "date-time"
	filterBoolean  filterType = "boolean"
	// filterBitmask is a 7-bit weekday mask and the only type that allows band.
	filterBitmask filterType = "bitmask"
	// filterEnum accepts only the field's Enum values.
	filterEnum filterType = "enum"
	// filterPresence is a virtual boolean over a string column: true selects
	// rows whose column is non-empty ("" means absent). It accepts only eq/ne
	// and is not sortable, since ordering by the backing column is meaningless.
	filterPresence filterType = "presence"
)

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
	// The value must match the public `ne` syntax: it is rendered verbatim in
	// 422 error field labels like filter[has_audio][ne].
	FilterNotEquals FilterOperator = "ne"
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

// FilterCondition represents a single filter condition. Values holds the raw
// query strings: none for null/not_null, one for scalar operators, two for
// between and one or more for in.
type FilterCondition struct {
	Field    string
	Operator FilterOperator
	Values   []string
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
// value or operator does not match the field type or expected value shape.
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

// dateTimeLayouts are the accepted filterDateTime value formats.
var dateTimeLayouts = []string{time.RFC3339, time.DateTime, time.DateOnly}

// operatorFormats maps filter operators to their SQL format strings.
var operatorFormats = map[FilterOperator]string{
	FilterEquals:      "%s = ?",
	FilterNotEquals:   "%s != ?",
	FilterGreaterThan: "%s > ?",
	FilterGreaterOrEq: "%s >= ?",
	FilterLessThan:    "%s < ?",
	FilterLessOrEq:    "%s <= ?",
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
			db = db.Order(dbField.Column + " " + sortDirectionSQL(sf.Direction))
		}
		return db, nil
	}
	for _, sf := range userSort {
		field, ok := fieldMapping[sf.Field]
		if !ok || field.Type == filterPresence {
			return nil, &UnknownFieldError{Kind: "sort", Field: sf.Field}
		}
		db = db.Order(field.Column + " " + sortDirectionSQL(sf.Direction))
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
	field, ok := fieldMapping[filter.Field]
	if !ok {
		return nil, &UnknownFieldError{Kind: "filter", Field: filter.Field}
	}
	if err := field.validate(filter); err != nil {
		return nil, err
	}

	col, args := field.Column, field.bindValues(filter.Values)
	switch filter.Operator {
	case FilterIsNull:
		return db.Where(col + " IS NULL"), nil
	case FilterIsNotNull:
		return db.Where(col + " IS NOT NULL"), nil
	case FilterLike:
		return db.Where(col+" LIKE ?"+likeEscapeClause, "%"+escapeLikePattern(filter.Values[0])+"%"), nil
	case FilterIn:
		return db.Where(col+" IN ?", args), nil
	case FilterBetween:
		return db.Where(col+" BETWEEN ? AND ?", args[0], args[1]), nil
	case FilterBitwiseAnd:
		// Bind the validated mask as an integer so MySQL does not apply string
		// semantics to the & operand.
		mask, _ := strconv.ParseUint(filter.Values[0], 10, 7)
		return db.Where("("+col+" & ?) != 0", mask), nil
	}
	if field.Type == filterPresence {
		present := args[0].(bool)
		if filter.Operator == FilterNotEquals {
			present = !present
		}
		return applyPresenceFilter(db, col, present), nil
	}
	return db.Where(fmt.Sprintf(operatorFormats[filter.Operator], col), args[0]), nil
}

// validate checks the operator, the value count and every value before binding.
func (f FilterField) validate(filter FilterCondition) error {
	invalid := func(reason string) error {
		return &InvalidFilterError{Field: filter.Field, Operator: filter.Operator, Reason: reason}
	}
	if !f.allowsOperator(filter.Operator) {
		return invalid("operator not allowed on this field")
	}
	n := len(filter.Values)
	switch filter.Operator {
	case FilterIsNull, FilterIsNotNull:
		return nil
	case FilterIn:
		if n == 0 {
			return invalid("expected comma-separated values")
		}
	case FilterBetween:
		if n != 2 {
			return invalid("expected two comma-separated values")
		}
	default:
		if n != 1 {
			return invalid("expected a single value")
		}
	}
	for _, value := range filter.Values {
		if !f.validValue(value) {
			return invalid("expected " + f.hint())
		}
	}
	return nil
}

func (f FilterField) allowsOperator(op FilterOperator) bool {
	switch op {
	case FilterEquals, FilterNotEquals:
		return true
	case FilterIsNull, FilterIsNotNull:
		return f.Nullable
	case FilterBitwiseAnd:
		return f.Type == filterBitmask
	case FilterLike:
		return f.Type == filterString
	case FilterIn:
		return f.Type != filterBitmask && f.Type != filterPresence
	case FilterGreaterThan, FilterGreaterOrEq, FilterLessThan, FilterLessOrEq, FilterBetween:
		switch f.Type {
		case filterInteger, filterNumber, filterDate, filterDateTime:
			return true
		}
	}
	return false
}

func (f FilterField) validValue(raw string) bool {
	switch f.Type {
	case filterString:
		return true
	case filterInteger:
		_, err := strconv.ParseInt(raw, 10, 64)
		return err == nil
	case filterNumber:
		value, err := strconv.ParseFloat(raw, 64)
		// ParseFloat also accepts non-finite values and Go hex/underscore syntax.
		return err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) && !strings.ContainsAny(raw, "xXpP_")
	case filterDate:
		_, err := time.Parse(time.DateOnly, raw)
		return err == nil
	case filterDateTime:
		for _, layout := range dateTimeLayouts {
			if _, err := time.Parse(layout, raw); err == nil {
				return true
			}
		}
		return false
	case filterBoolean, filterPresence:
		_, err := strconv.ParseBool(raw)
		return err == nil
	case filterBitmask:
		_, err := strconv.ParseUint(raw, 10, 7)
		return err == nil
	case filterEnum:
		return slices.Contains(f.Enum, raw)
	}
	return false
}

// hint names the accepted value shape in InvalidFilterError reasons.
func (f FilterField) hint() string {
	switch f.Type {
	case filterBitmask:
		return "integer between 0 and 127"
	case filterEnum:
		return "one of " + strings.Join(f.Enum, ", ")
	case filterPresence:
		return "boolean"
	}
	return string(f.Type)
}

// bindValues converts validated raw values to SQL bind values. Boolean columns
// are TINYINT and MySQL coerces non-numeric strings to 0 in numeric
// comparisons, so "true" is bound as a bool rather than matching FALSE rows.
func (f FilterField) bindValues(raw []string) []any {
	args := make([]any, len(raw))
	for i, value := range raw {
		if f.Type == filterBoolean || f.Type == filterPresence {
			args[i], _ = strconv.ParseBool(value)
		} else {
			args[i] = value
		}
	}
	return args
}

// applyPresenceFilter selects rows by whether the backing column is non-empty.
func applyPresenceFilter(db *gorm.DB, col string, present bool) *gorm.DB {
	if present {
		return db.Where(col+" != ?", "")
	}
	// COALESCE: stories.audio_file is nullable, and a NULL row must land in
	// the "absent" partition rather than escaping both.
	return db.Where("COALESCE("+col+", '') = ?", "")
}
