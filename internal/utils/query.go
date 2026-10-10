package utils

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// QueryParamError identifies an invalid query parameter for validation responses.
type QueryParamError struct {
	Field   string
	Message string
}

// Error returns the parameter name and validation message.
func (e *QueryParamError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Message)
}

// QueryParams holds parsed list options plus the sparse fieldset.
type QueryParams struct {
	repository.ListQuery
	// Fields lists the JSON field names requested with ?fields=.
	Fields []string
}

// ParseQueryParams parses list options and validates query syntax, operator
// names, duplicate keys, pagination, and trashed. The repository validates
// field names, operator applicability, and values.
func ParseQueryParams(c *gin.Context) (*QueryParams, error) {
	if c == nil {
		return nil, errors.New("missing request context")
	}

	var query url.Values
	if c.Request != nil && c.Request.URL != nil {
		query = c.Request.URL.Query()
	}

	if err := rejectDuplicateSingleValueParams(query); err != nil {
		return nil, err
	}

	params := &QueryParams{}

	limit, offset, err := Pagination(c)
	if err != nil {
		return nil, err
	}
	params.Limit, params.Offset = limit, offset

	sortFields, err := parseSorting(c)
	if err != nil {
		return nil, err
	}
	params.Sort = sortFields

	params.Fields = parseFields(c)

	filters, err := parseFilters(query)
	if err != nil {
		return nil, err
	}
	params.Filters = filters

	params.Trashed = c.Query("trashed")
	if params.Trashed != "" && params.Trashed != "only" && params.Trashed != "with" {
		return nil, &QueryParamError{Field: "trashed", Message: "expected only or with"}
	}

	params.Search = c.Query("search")

	return params, nil
}

func parseSorting(c *gin.Context) ([]repository.SortField, error) {
	sortParam := c.Query("sort")
	if sortParam == "" {
		return nil, nil
	}

	parts := strings.Split(sortParam, ",")
	sortFields := make([]repository.SortField, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		var field string
		direction := repository.SortAsc

		switch {
		case strings.HasPrefix(part, "-"):
			field, _ = strings.CutPrefix(part, "-")
			direction = repository.SortDesc
		case strings.HasPrefix(part, "+"):
			field, _ = strings.CutPrefix(part, "+")
		case strings.Contains(part, ":"):
			before, after, _ := strings.Cut(part, ":")
			field = strings.TrimSpace(before)
			direction = repository.SortDirection(strings.ToLower(strings.TrimSpace(after)))
			if direction != repository.SortAsc && direction != repository.SortDesc {
				return nil, &QueryParamError{
					Field:   "sort",
					Message: fmt.Sprintf("invalid direction %q for field %q; use asc or desc", after, field),
				}
			}
		default:
			field = part
		}

		if field != "" {
			sortFields = append(sortFields, repository.SortField{
				Field:     field,
				Direction: direction,
			})
		}
	}

	return sortFields, nil
}

func parseFields(c *gin.Context) []string {
	fieldsParam := c.Query("fields")
	if fieldsParam == "" {
		return nil
	}

	parts := strings.Split(fieldsParam, ",")
	fields := make([]string, 0, len(parts))

	for _, part := range parts {
		field := strings.TrimSpace(part)
		if field != "" {
			fields = append(fields, field)
		}
	}

	return fields
}

// filterOperators maps query operator names to repository operators.
var filterOperators = map[string]repository.FilterOperator{
	"":        repository.FilterEquals,
	"eq":      repository.FilterEquals,
	"ne":      repository.FilterNotEquals,
	"not":     repository.FilterNotEquals,
	"gt":      repository.FilterGreaterThan,
	"gte":     repository.FilterGreaterOrEq,
	"lt":      repository.FilterLessThan,
	"lte":     repository.FilterLessOrEq,
	"like":    repository.FilterLike,
	"band":    repository.FilterBitwiseAnd,
	"null":    repository.FilterIsNull,
	"in":      repository.FilterIn,
	"between": repository.FilterBetween,
}

// rejectDuplicateSingleValueParams rejects repeated non-filter keys before
// c.Query can discard extra values. parseFilters checks duplicate filter keys.
func rejectDuplicateSingleValueParams(query url.Values) error {
	for key, values := range query {
		if strings.HasPrefix(key, "filter[") {
			continue
		}
		if len(values) > 1 {
			return &QueryParamError{
				Field:   key,
				Message: "received multiple values; only one is allowed",
			}
		}
	}
	return nil
}

func parseFilters(queryValues url.Values) ([]repository.FilterCondition, error) {
	var filters []repository.FilterCondition

	filterKeys := make([]string, 0, len(queryValues))
	for key := range queryValues {
		if strings.HasPrefix(key, "filter[") {
			filterKeys = append(filterKeys, key)
		}
	}
	// Stable filter ordering produces reproducible WHERE clauses.
	sort.Strings(filterKeys)

	for _, key := range filterKeys {
		values := queryValues[key]
		if len(values) > 1 {
			return nil, &QueryParamError{
				Field:   key,
				Message: "received multiple values; only one is allowed per filter key",
			}
		}

		field, operator := parseFilterKey(key)
		if field == "" {
			return nil, &QueryParamError{
				Field:   key,
				Message: "expected filter[field] or filter[field][operator]",
			}
		}

		op, ok := filterOperators[operator]
		if !ok {
			return nil, &QueryParamError{
				Field:   key,
				Message: fmt.Sprintf("unknown operator %q", operator),
			}
		}

		raw := []string{values[0]}
		if op == repository.FilterIn || op == repository.FilterBetween {
			raw = strings.Split(values[0], ",")
			for i, v := range raw {
				raw[i] = strings.TrimSpace(v)
			}
		}
		filters = append(filters, repository.FilterCondition{Field: field, Operator: op, Values: raw})
	}

	return filters, nil
}

func parseFilterKey(key string) (field, operator string) {
	content, found := strings.CutPrefix(key, "filter[")
	if !found {
		return "", ""
	}
	content, found = strings.CutSuffix(content, "]")
	if !found {
		return "", ""
	}

	if before, after, found := strings.Cut(content, "]["); found {
		return before, after
	}

	return content, ""
}

// FilterStructFields projects a struct or slice of structs to requested JSON
// field names.
func FilterStructFields(data any, fields []string) any {
	if len(fields) == 0 {
		return data
	}

	value := reflect.Indirect(reflect.ValueOf(data))
	if !value.IsValid() {
		return data
	}

	fieldSet := make(map[string]bool, len(fields))
	for _, field := range fields {
		fieldSet[field] = true
	}

	if value.Kind() == reflect.Slice {
		result := make([]map[string]any, value.Len())
		for i := range value.Len() {
			result[i] = structToFilteredMap(value.Index(i), fieldSet)
		}
		return result
	}

	return structToFilteredMap(reflect.ValueOf(data), fieldSet)
}

func structToFilteredMap(value reflect.Value, fieldSet map[string]bool) map[string]any {
	result := make(map[string]any)

	if value.Kind() == reflect.Interface {
		value = value.Elem()
	}
	value = reflect.Indirect(value)
	if value.Kind() != reflect.Struct {
		return result
	}

	for field, fieldVal := range value.Fields() {
		if fieldName, visible := jsonFieldName(field); visible && fieldSet[fieldName] {
			result[fieldName] = fieldVal.Interface()
		}
	}

	return result
}

// jsonFieldName returns the JSON tag name or Go field name.
// Fields tagged json:"-" are not visible.
func jsonFieldName(field reflect.StructField) (name string, visible bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false
	}
	name = field.Name
	if tag != "" {
		if before, _, _ := strings.Cut(tag, ","); before != "" {
			name = before
		}
	}
	return name, true
}

// ParseListQuery parses list options. On parse errors it writes an RFC 9457
// response and returns false. The embedded ListQuery is ready for the repository.
func ParseListQuery(c *gin.Context) (*QueryParams, bool) {
	params, err := ParseQueryParams(c)
	if err != nil {
		emitQueryError(c, err)
		return nil, false
	}
	return params, true
}

// ParsePaginationOnly parses limit and offset, rejecting search, sort, filter,
// fields, and trashed options with a 422 response.
func ParsePaginationOnly(c *gin.Context) (limit, offset int, ok bool) {
	params, err := ParseQueryParams(c)
	if err != nil {
		emitQueryError(c, err)
		return 0, 0, false
	}
	var unsupported []apperrors.ValidationError
	if params.Search != "" {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "search", Message: "not supported on this endpoint"})
	}
	if len(params.Sort) > 0 {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "sort", Message: "not supported on this endpoint"})
	}
	if len(params.Filters) > 0 {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "filter", Message: "not supported on this endpoint"})
	}
	if len(params.Fields) > 0 {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "fields", Message: "not supported on this endpoint"})
	}
	if params.Trashed != "" {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "trashed", Message: "not supported on this endpoint"})
	}
	if len(unsupported) > 0 {
		ProblemValidationError(c, "Endpoint only supports limit and offset", unsupported)
		return 0, 0, false
	}
	return params.Limit, params.Offset, true
}

func emitQueryError(c *gin.Context, err error) {
	if qpe, ok := errors.AsType[*QueryParamError](err); ok {
		ProblemValidationError(c, "Invalid query parameter", []apperrors.ValidationError{
			{Field: qpe.Field, Message: qpe.Message},
		})
		return
	}
	ProblemBadRequest(c, err.Error())
}

// PaginatedListResponse writes a page with optional sparse fieldsets.
// For struct types, unknown field names produce a 422 response.
func PaginatedListResponse[T any](c *gin.Context, params *QueryParams, result *repository.ListResult[T]) {
	var data any = result.Data
	if params != nil && len(params.Fields) > 0 {
		if valid := jsonFieldNames[T](); valid != nil {
			var unknown []apperrors.ValidationError
			for _, f := range params.Fields {
				if _, ok := valid[f]; !ok {
					unknown = append(unknown, apperrors.ValidationError{
						Field:   "fields",
						Message: fmt.Sprintf("unknown field %q", f),
					})
				}
			}
			if len(unknown) > 0 {
				ProblemValidationError(c, "Invalid query parameter", unknown)
				return
			}
		}
		data = FilterStructFields(result.Data, params.Fields)
	}
	PaginatedResponse(c, data, result.Total, result.Limit, result.Offset)
}

// jsonFieldNames returns exported JSON field names, dereferencing pointer types.
// It returns nil for non-struct types, disabling field-name validation.
func jsonFieldNames[T any]() map[string]struct{} {
	var zero T
	typ := reflect.TypeOf(zero)
	if typ == nil {
		return nil
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil
	}
	names := make(map[string]struct{}, typ.NumField())
	for field := range typ.Fields() {
		if !field.IsExported() {
			continue
		}
		name, visible := jsonFieldName(field)
		if !visible {
			continue
		}
		names[name] = struct{}{}
	}
	return names
}
