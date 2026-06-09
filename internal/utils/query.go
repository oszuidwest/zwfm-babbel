package utils

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// QueryParamError describes a single invalid query parameter. Carrying the
// field name separately from the message lets ParseListQuery surface a
// structured RFC 9457 validation response that clients can parse
// programmatically rather than a flat detail string.
type QueryParamError struct {
	Field   string
	Message string
}

func (e *QueryParamError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Message)
}

// QueryParams holds parsed filtering, sorting, pagination, fieldset, and search options.
type QueryParams struct {
	// Pagination
	Limit  int `json:"limit"`
	Offset int `json:"offset"`

	// Sorting
	Sort []SortField `json:"sort"`

	// Field Selection (sparse fieldsets)
	Fields []string `json:"fields"`

	// Filtering
	Filters []ParsedFilter `json:"filters"`

	// Trashed controls soft-delete filtering: "" (default, active only), "only", "with"
	Trashed string `json:"trashed"`

	// Search
	Search string `json:"search"`
}

// SortField represents a single sort criterion.
type SortField struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // "asc" or "desc"
}

// ParsedFilter represents a single parsed filter condition. It intentionally
// carries the field alongside the operator so same-field filters such as
// filter[created_at][gte] + filter[created_at][lte] cannot collapse into one
// slice entry before reaching the repository layer. Operator values come from
// repository.Filter* constants so handlers do not translate between vocabularies.
type ParsedFilter struct {
	Field    string                    `json:"field"`
	Operator repository.FilterOperator `json:"operator"`
	Value    any                       `json:"value"`
	Values   []string                  `json:"values"` // For "in" and "between" operations
}

// ParseQueryParams extracts and validates modern query parameters from the request.
func ParseQueryParams(c *gin.Context) (*QueryParams, error) {
	if c == nil {
		return nil, errors.New("missing request context")
	}

	if err := rejectDuplicateSingleValueParams(c); err != nil {
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
	if sortFields != nil {
		params.Sort = sortFields
	}

	if fields := parseFields(c); fields != nil {
		params.Fields = fields
	}

	filters, err := parseFilters(c)
	if err != nil {
		return nil, err
	}
	if filters != nil {
		params.Filters = filters
	}

	params.Trashed = c.Query("trashed")

	params.Search = c.Query("search")

	return params, nil
}

// parseSorting parses the sort query parameter into sort fields.
func parseSorting(c *gin.Context) ([]SortField, error) {
	if c == nil {
		return nil, errors.New("missing request context")
	}

	sortParam := c.Query("sort")
	if sortParam == "" {
		return nil, nil
	}

	parts := strings.Split(sortParam, ",")
	sortFields := make([]SortField, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		var field, direction string

		switch {
		case strings.HasPrefix(part, "-"):
			field, _ = strings.CutPrefix(part, "-")
			direction = "desc"
		case strings.HasPrefix(part, "+"):
			field, _ = strings.CutPrefix(part, "+")
			direction = "asc"
		case strings.Contains(part, ":"):
			if before, after, found := strings.Cut(part, ":"); found {
				field = strings.TrimSpace(before)
				direction = strings.ToLower(strings.TrimSpace(after))
				if direction != "asc" && direction != "desc" {
					return nil, &QueryParamError{
						Field:   "sort",
						Message: fmt.Sprintf("invalid direction %q for field %q; use asc or desc", after, field),
					}
				}
			}
		default:
			field = part
			direction = "asc"
		}

		if field != "" {
			sortFields = append(sortFields, SortField{
				Field:     field,
				Direction: direction,
			})
		}
	}

	return sortFields, nil
}

// parseFields parses the fields query parameter for sparse fieldsets.
func parseFields(c *gin.Context) []string {
	if c == nil {
		return nil
	}

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

// filterOperatorHandler parses a raw operator value into a ParsedFilter. The
// Field on the returned ParsedFilter is filled in by parseFilters.
type filterOperatorHandler func(value string) (ParsedFilter, error)

// filterOperatorHandlers maps operator names to their handler functions.
var filterOperatorHandlers = map[string]filterOperatorHandler{
	"eq": func(value string) (ParsedFilter, error) {
		return ParsedFilter{Operator: repository.FilterEquals, Value: value}, nil
	},
	"in": func(value string) (ParsedFilter, error) {
		filterValues := strings.Split(value, ",")
		for i, v := range filterValues {
			filterValues[i] = strings.TrimSpace(v)
		}
		return ParsedFilter{Operator: repository.FilterIn, Values: filterValues}, nil
	},
	"between": func(value string) (ParsedFilter, error) {
		betweenValues := strings.Split(value, ",")
		if len(betweenValues) != 2 {
			return ParsedFilter{}, errors.New("expected two comma-separated values")
		}
		lower := strings.TrimSpace(betweenValues[0])
		upper := strings.TrimSpace(betweenValues[1])
		if lower == "" || upper == "" {
			return ParsedFilter{}, errors.New("expected two non-empty values")
		}
		return ParsedFilter{Operator: repository.FilterBetween, Values: []string{lower, upper}}, nil
	},
	"like": func(value string) (ParsedFilter, error) {
		return ParsedFilter{Operator: repository.FilterLike, Value: value}, nil
	},
	"gte": func(value string) (ParsedFilter, error) {
		return ParsedFilter{Operator: repository.FilterGreaterOrEq, Value: value}, nil
	},
	"gt": func(value string) (ParsedFilter, error) {
		return ParsedFilter{Operator: repository.FilterGreaterThan, Value: value}, nil
	},
	"lte": func(value string) (ParsedFilter, error) {
		return ParsedFilter{Operator: repository.FilterLessOrEq, Value: value}, nil
	},
	"lt": func(value string) (ParsedFilter, error) {
		return ParsedFilter{Operator: repository.FilterLessThan, Value: value}, nil
	},
	"ne": func(value string) (ParsedFilter, error) {
		return ParsedFilter{Operator: repository.FilterNotEquals, Value: value}, nil
	},
	"not": func(value string) (ParsedFilter, error) {
		return ParsedFilter{Operator: repository.FilterNotEquals, Value: value}, nil
	},
	"null": func(value string) (ParsedFilter, error) {
		isNull, err := strconv.ParseBool(value)
		if err != nil {
			return ParsedFilter{}, errors.New("expected boolean")
		}
		if isNull {
			return ParsedFilter{Operator: repository.FilterIsNull}, nil
		}
		return ParsedFilter{Operator: repository.FilterIsNotNull}, nil
	},
	"band": func(value string) (ParsedFilter, error) {
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return ParsedFilter{}, errors.New("expected integer between 0 and 255")
		}
		return ParsedFilter{Operator: repository.FilterBitwiseAnd, Value: uint8(val)}, nil
	},
	"": func(value string) (ParsedFilter, error) {
		return ParsedFilter{Operator: repository.FilterEquals, Value: value}, nil
	},
}

// rejectDuplicateSingleValueParams enforces that every non-filter query key
// appears at most once. Gin's c.Query() silently returns values[0] on a
// duplicate, which masks client bugs (e.g. ?limit=1&limit=2 used to slip
// past the latest-shortcut guard because only the first value was checked).
// filter[...] keys are excluded because parseFilters validates them with
// richer per-operator context.
func rejectDuplicateSingleValueParams(c *gin.Context) error {
	if c == nil || c.Request == nil || c.Request.URL == nil {
		return nil
	}
	for key, values := range c.Request.URL.Query() {
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

// parseFilters parses the filter query parameters into filter conditions.
func parseFilters(c *gin.Context) ([]ParsedFilter, error) {
	var filters []ParsedFilter

	if c == nil || c.Request == nil || c.Request.URL == nil {
		return filters, nil
	}

	queryValues := c.Request.URL.Query()
	filterKeys := make([]string, 0, len(queryValues))
	for key := range queryValues {
		if strings.HasPrefix(key, "filter[") {
			filterKeys = append(filterKeys, key)
		}
	}
	// Go map iteration order is randomized, so sort the keys so that multiple
	// operators on the same field (e.g. gte + lte) reach the repository in a
	// deterministic order. Required for reproducible WHERE clauses and tests.
	sort.Strings(filterKeys)

	for _, key := range filterKeys {
		values := queryValues[key]
		if len(values) == 0 {
			continue
		}

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

		handler, exists := filterOperatorHandlers[operator]
		if !exists {
			return nil, &QueryParamError{
				Field:   key,
				Message: fmt.Sprintf("unknown operator %q", operator),
			}
		}

		filter, err := handler(values[0])
		if err != nil {
			return nil, &QueryParamError{
				Field:   filterKeyLabel(field, operator),
				Message: err.Error(),
			}
		}

		filter.Field = field
		filters = append(filters, filter)
	}

	return filters, nil
}

// parseFilterKey extracts field name and operator from a filter key.
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

func filterKeyLabel(field, operator string) string {
	if operator == "" {
		return fmt.Sprintf("filter[%s]", field)
	}
	return fmt.Sprintf("filter[%s][%s]", field, operator)
}

// FilterStructFields projects a struct or slice of structs to requested JSON
// field names.
func FilterStructFields(data any, fields []string) any {
	if len(fields) == 0 {
		return data
	}

	value := reflect.ValueOf(data)
	if !value.IsValid() {
		return data
	}

	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return data
		}
		value = value.Elem()
	}

	if !value.IsValid() {
		return data
	}

	if value.Kind() == reflect.Slice {
		result := make([]map[string]any, value.Len())
		for i := 0; i < value.Len(); i++ {
			result[i] = structToFilteredMap(value.Index(i).Interface(), fields)
		}
		return result
	}

	return structToFilteredMap(data, fields)
}

// structToFilteredMap converts a struct to a map containing only requested
// JSON field names.
func structToFilteredMap(data any, fields []string) map[string]any {
	result := make(map[string]any)

	value := reflect.ValueOf(data)
	if !value.IsValid() {
		return result
	}

	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return result
		}
		value = value.Elem()
	}

	if !value.IsValid() || value.Kind() != reflect.Struct {
		return result
	}

	fieldSet := make(map[string]bool)
	for _, field := range fields {
		fieldSet[field] = true
	}

	for field, fieldVal := range value.Fields() {
		jsonTag := field.Tag.Get("json")

		if jsonTag == "-" {
			continue
		}

		fieldName := field.Name
		if jsonTag != "" {
			fieldName, _, _ = strings.Cut(jsonTag, ",")
		}

		if fieldSet[fieldName] {
			result[fieldName] = fieldVal.Interface()
		}
	}

	return result
}

// supportedFilterOperators is the set of repository.FilterOperator values that
// ParsedFilter may carry. Keeping a single source of truth here lets us
// validate Operator without re-translating between vocabularies.
var supportedFilterOperators = map[repository.FilterOperator]bool{
	repository.FilterEquals:      true,
	repository.FilterNotEquals:   true,
	repository.FilterGreaterThan: true,
	repository.FilterGreaterOrEq: true,
	repository.FilterLessThan:    true,
	repository.FilterLessOrEq:    true,
	repository.FilterLike:        true,
	repository.FilterIn:          true,
	repository.FilterBetween:     true,
	repository.FilterBitwiseAnd:  true,
	repository.FilterIsNull:      true,
	repository.FilterIsNotNull:   true,
}

// QueryParamsToListQuery converts QueryParams to a repository.ListQuery.
func QueryParamsToListQuery(params *QueryParams) (*repository.ListQuery, error) {
	if params == nil {
		return repository.NewListQuery(), nil
	}

	query := &repository.ListQuery{
		Limit:   params.Limit,
		Offset:  params.Offset,
		Search:  params.Search,
		Trashed: params.Trashed,
	}

	for _, sf := range params.Sort {
		direction := repository.SortAsc
		if strings.ToLower(sf.Direction) == "desc" {
			direction = repository.SortDesc
		}
		query.Sort = append(query.Sort, repository.SortField{
			Field:     sf.Field,
			Direction: direction,
		})
	}

	for _, filter := range params.Filters {
		if !supportedFilterOperators[filter.Operator] {
			return nil, &QueryParamError{
				Field:   fmt.Sprintf("filter[%s]", filter.Field),
				Message: fmt.Sprintf("unsupported operator %q", filter.Operator),
			}
		}
		condition := repository.FilterCondition{
			Field:    filter.Field,
			Operator: filter.Operator,
			Value:    filter.Value,
		}
		if filter.Operator == repository.FilterIn || filter.Operator == repository.FilterBetween {
			condition.Value = filter.Values
		}
		query.Filters = append(query.Filters, condition)
	}

	return query, nil
}

// ParseListQuery parses query parameters and converts them into a repository ListQuery.
// On invalid input it emits an RFC 9457 problem response and returns ok=false.
// QueryParamError instances are surfaced as a structured validation response so
// clients can pinpoint the failing parameter.
func ParseListQuery(c *gin.Context) (*QueryParams, *repository.ListQuery, bool) {
	params, err := ParseQueryParams(c)
	if err != nil {
		emitQueryError(c, err)
		return nil, nil, false
	}
	query, err := QueryParamsToListQuery(params)
	if err != nil {
		emitQueryError(c, err)
		return nil, nil, false
	}
	return params, query, true
}

// ParsePaginationOnly parses query parameters for an endpoint that only
// supports limit and offset. Any of search/sort/filter/fields trigger a 422
// so a typo on a pagination-only endpoint is not silently ignored.
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
	var qpe *QueryParamError
	if errors.As(err, &qpe) {
		ProblemValidationError(c, "Invalid query parameter", []apperrors.ValidationError{
			{Field: qpe.Field, Message: qpe.Message},
		})
		return
	}
	ProblemBadRequest(c, err.Error())
}

// PaginatedListResponse writes a paginated response, applying sparse-fieldset
// filtering when params.Fields is non-empty. Unknown field names in
// params.Fields are rejected with a 422 so a client typo does not silently
// produce a truncated response.
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

// jsonFieldNames returns the set of JSON-visible field names for T. Pointer
// types are dereferenced; fields tagged json:"-" are skipped. Returns nil when
// T does not resolve to a struct so callers fall back to the legacy filtering
// behavior rather than rejecting every request.
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
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := field.Name
		if tag != "" {
			if before, _, _ := strings.Cut(tag, ","); before != "" {
				name = before
			}
		}
		names[name] = struct{}{}
	}
	return names
}
