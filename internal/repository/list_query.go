package repository

import (
	"errors"
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

// FilterField defines a list field's database column and accepted filter values.
type FilterField struct {
	Column   string
	Type     filterType
	Nullable bool
	Enum     []string // Accepted values for filterEnum.
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
	// filterPresence is a boolean SQL expression that treats NULL and "" as
	// absent. Only eq/ne apply, and applySorting rejects it.
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

// FilterOperator names a filter operator. Values equal the public query
// operator names.
type FilterOperator string

const (
	// FilterEquals selects records whose field equals the supplied value.
	FilterEquals FilterOperator = "eq"
	// FilterNotEquals selects records whose field differs from the supplied value.
	FilterNotEquals FilterOperator = "ne"
	// FilterGreaterThan selects records whose field is greater than the supplied value.
	FilterGreaterThan FilterOperator = "gt"
	// FilterGreaterOrEq selects records whose field is greater than or equal to the supplied value.
	FilterGreaterOrEq FilterOperator = "gte"
	// FilterLessThan selects records whose field is less than the supplied value.
	FilterLessThan FilterOperator = "lt"
	// FilterLessOrEq selects records whose field is less than or equal to the supplied value.
	FilterLessOrEq FilterOperator = "lte"
	// FilterLike selects records whose field contains the supplied literal substring.
	FilterLike FilterOperator = "like"
	// FilterIn selects records whose field is one of the supplied values.
	FilterIn FilterOperator = "in"
	// FilterBetween selects records whose field falls within the inclusive range.
	FilterBetween FilterOperator = "between"
	// FilterBitwiseAnd selects records whose bitmask field overlaps the supplied mask.
	FilterBitwiseAnd FilterOperator = "band"
	// FilterIsNull selects NULL records for value "true" and non-NULL records for "false".
	FilterIsNull FilterOperator = "null"
)

// FilterCondition holds a field, operator, and raw query values.
type FilterCondition struct {
	// Key is the literal query key, such as filter[status][eq], used to label errors.
	Key      string
	Field    string
	Operator FilterOperator
	// Values holds the raw query values: one for scalar operators, two for
	// between, one or more for in. FilterField.bind enforces the count.
	Values []string
}

// UnknownFieldError reports a field that is unavailable for filtering or sorting.
type UnknownFieldError struct {
	Kind  string // "filter" or "sort"
	Key   string // literal query key: "sort" or the filter key
	Field string
}

// Error returns the unknown field message.
func (e *UnknownFieldError) Error() string {
	return fmt.Sprintf("unknown %s field %q", e.Kind, e.Field)
}

// InvalidFilterError reports an unsupported operator or invalid filter values.
type InvalidFilterError struct {
	Key      string // literal query key
	Field    string
	Operator FilterOperator
	// Code is the API field-error code: "unsupported", "invalid_format",
	// "invalid_choice" or "out_of_range".
	Code   string
	Reason string
}

// Error returns the invalid filter message.
func (e *InvalidFilterError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Key, e.Reason)
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

// ApplyListQuery returns a filtered, sorted page and the total matching count.
// Field names and filter values are validated against fieldMapping;
// searchFields must contain trusted database columns.
// defaultSort applies when query.Sort is empty, skipping unmapped fields.
func ApplyListQuery[T any](db *gorm.DB, query *ListQuery, fieldMapping FieldMapping, searchFields []string, defaultSort []SortField) (*ListResult[T], error) {
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

// dateTimeLayouts are the accepted date-time filter formats. Keep in sync
// with DateTimeValue and "Dates and times" in openapi.yaml.
var dateTimeLayouts = []string{time.RFC3339, time.DateTime, time.DateOnly}

// comparisonSQL holds the WHERE fragments for the scalar operators that
// applyFilterCondition does not special-case. Every operator allowsOperator
// admits must appear here or in that switch.
var comparisonSQL = map[FilterOperator]string{
	FilterEquals:      " = ?",
	FilterNotEquals:   " != ?",
	FilterGreaterThan: " > ?",
	FilterGreaterOrEq: " >= ?",
	FilterLessThan:    " < ?",
	FilterLessOrEq:    " <= ?",
}

// likePatternEscaper escapes MySQL's LIKE wildcards and escape character.
var likePatternEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func escapeLikePattern(s string) string {
	return likePatternEscaper.Replace(s)
}

// likeEscapeClause names the escape character explicitly. In a MySQL string
// literal '\\' is a single backslash, the character likePatternEscaper inserts.
const likeEscapeClause = ` ESCAPE '\\'`

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

// applySorting validates user sort fields or applies defaultSort when none are
// given. Unmapped default fields are skipped.
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
			return nil, &UnknownFieldError{Kind: "sort", Key: "sort", Field: sf.Field}
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

func sortDirectionSQL(d SortDirection) string {
	if d == SortDesc {
		return "DESC"
	}
	return "ASC"
}

// applyFilterCondition validates and applies a filter, returning
// [UnknownFieldError] or [InvalidFilterError] for invalid input.
func applyFilterCondition(db *gorm.DB, filter FilterCondition, fieldMapping FieldMapping) (*gorm.DB, error) {
	// SQL identifiers cannot be parameterized, so only mapped columns are allowed.
	field, ok := fieldMapping[filter.Field]
	if !ok {
		return nil, &UnknownFieldError{Kind: "filter", Key: filter.Key, Field: filter.Field}
	}
	args, err := field.bind(filter)
	if err != nil {
		return nil, err
	}

	col := field.Column
	switch filter.Operator {
	case FilterIsNull:
		if args[0].(bool) {
			return db.Where(col + " IS NULL"), nil
		}
		return db.Where(col + " IS NOT NULL"), nil
	case FilterLike:
		return db.Where(col+" LIKE ?"+likeEscapeClause, "%"+escapeLikePattern(filter.Values[0])+"%"), nil
	case FilterIn:
		return db.Where(col+" IN ?", args), nil
	case FilterBetween:
		return db.Where(col+" BETWEEN ? AND ?", args[0], args[1]), nil
	case FilterBitwiseAnd:
		return db.Where("("+col+" & ?) != 0", args[0]), nil
	}
	return db.Where(col+comparisonSQL[filter.Operator], args[0]), nil
}

// bind checks the operator and value count, then parses every value into its
// bind argument.
func (f FilterField) bind(filter FilterCondition) ([]any, error) {
	invalid := func(code, reason string) error {
		return &InvalidFilterError{Key: filter.Key, Field: filter.Field, Operator: filter.Operator, Code: code, Reason: reason}
	}
	if !f.allowsOperator(filter.Operator) {
		return nil, invalid("unsupported", "operator not allowed on this field")
	}
	n := len(filter.Values)
	switch filter.Operator {
	case FilterIn:
		if n == 0 {
			return nil, invalid("invalid_format", "expected comma-separated values")
		}
	case FilterBetween:
		if n != 2 {
			return nil, invalid("invalid_format", "expected two comma-separated values")
		}
	default:
		if n != 1 {
			return nil, invalid("invalid_format", "expected a single value")
		}
	}
	args := make([]any, n)
	for i, raw := range filter.Values {
		var err error
		if filter.Operator == FilterIsNull {
			args[i], err = parseBool(raw)
		} else {
			args[i], err = f.parseValue(raw)
		}
		if err != nil {
			code := "invalid_format"
			if valueErr, ok := errors.AsType[*filterValueError](err); ok {
				code = valueErr.code
			}
			return nil, invalid(code, err.Error())
		}
	}
	return args, nil
}

// filterValueError is a well-formed filter value outside the allowed values;
// code is the API field-error code. Other value errors are format errors.
type filterValueError struct {
	code, message string
}

func (e *filterValueError) Error() string { return e.message }

func (f FilterField) allowsOperator(op FilterOperator) bool {
	switch op {
	case FilterEquals, FilterNotEquals:
		return true
	case FilterIsNull:
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

// parseValue validates raw and returns its bind argument. Booleans bind as
// bool because MySQL coerces non-numeric strings such as "true" to 0 in
// numeric comparisons. Bitmasks bind as integers. Date-times bind as
// time.Time because MySQL, with only a warning, reads an RFC 3339 "Z" suffix
// as local time and truncates a comma fraction. Strings, integers, numbers,
// dates and enums bind the validated string.
func (f FilterField) parseValue(raw string) (any, error) {
	switch f.Type {
	case filterBoolean, filterPresence:
		return parseBool(raw)
	case filterDateTime:
		return parseDateTime(raw, time.Local)
	case filterBitmask:
		mask, err := strconv.ParseUint(raw, 10, 64)
		switch {
		case err != nil && !errors.Is(err, strconv.ErrRange):
			return nil, errors.New("expected integer between 0 and 127")
		case err != nil || mask > 127:
			return nil, &filterValueError{code: "out_of_range", message: "expected integer between 0 and 127"}
		}
		return mask, nil
	case filterEnum:
		if slices.Contains(f.Enum, raw) {
			return raw, nil
		}
		return nil, &filterValueError{code: "invalid_choice", message: "expected one of " + strings.Join(f.Enum, ", ")}
	}
	if !validLiteral(f.Type, raw) {
		return nil, errors.New("expected " + string(f.Type))
	}
	return raw, nil
}

// validLiteral reports whether raw is a well-formed string, integer, number
// or date literal. These types bind the raw string.
func validLiteral(t filterType, raw string) bool {
	switch t {
	case filterString:
		return true
	case filterInteger:
		_, err := strconv.ParseInt(raw, 10, 64)
		return err == nil
	case filterNumber:
		value, err := strconv.ParseFloat(raw, 64)
		// ParseFloat also accepts non-finite values and Go hex/underscore syntax.
		return err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) && !strings.ContainsAny(raw, "xX_")
	case filterDate:
		_, err := time.Parse(time.DateOnly, raw)
		return err == nil
	}
	return false
}

// parseDateTime parses raw, reading layouts without a zone in loc, and returns
// the time in loc. The MySQL driver binds that representation and cannot bind
// years outside 1 to 9999.
func parseDateTime(raw string, loc *time.Location) (any, error) {
	for _, layout := range dateTimeLayouts {
		if t, err := time.ParseInLocation(layout, raw, loc); err == nil {
			t = t.In(loc)
			if t.Year() < 1 || t.Year() > 9999 {
				break
			}
			return t, nil
		}
	}
	return nil, errors.New("expected date-time")
}

func parseBool(raw string) (any, error) {
	if value, err := strconv.ParseBool(raw); err == nil {
		return value, nil
	}
	return nil, errors.New("expected boolean")
}
