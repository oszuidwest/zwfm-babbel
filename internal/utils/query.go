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

// QueryParamError identifies an invalid query parameter for validation responses.
type QueryParamError struct {
	Field   string
	Message string
}

// Error returns the parameter name and validation message.
func (e *QueryParamError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Message)
}

// QueryParams holds parsed filtering, sorting, pagination, fieldset, and search options.
type QueryParams struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`

	Sort []SortField `json:"sort"`

	// Fields controls sparse fieldsets.
	Fields []string `json:"fields"`

	Filters []ParsedFilter `json:"filters"`

	// Trashed controls soft-delete filtering: "" (default, active only), "only", or "with".
	Trashed string `json:"trashed"`

	// Search matches literal substrings in the resource's searchable columns.
	Search string `json:"search"`
}

// SortField represents a single sort criterion.
type SortField struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // "asc" or "desc"
}

// ParsedFilter holds a field, operator, and raw values for repository validation.
type ParsedFilter struct {
	Field    string                    `json:"field"`
	Operator repository.FilterOperator `json:"operator"`
	Values   []string                  `json:"values"`
}

// ParseQueryParams parses list options and validates query syntax and pagination.
// The repository validates filter fields, operators, and values.
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
	params.Sort = sortFields

	params.Fields = parseFields(c)

	filters, err := parseFilters(c)
	if err != nil {
		return nil, err
	}
	params.Filters = filters

	params.Trashed = c.Query("trashed")

	params.Search = c.Query("search")

	return params, nil
}

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

// simpleFilterOperators maps single-value query operators to repository operators.
var simpleFilterOperators = map[string]repository.FilterOperator{
	"":     repository.FilterEquals,
	"eq":   repository.FilterEquals,
	"ne":   repository.FilterNotEquals,
	"not":  repository.FilterNotEquals,
	"gt":   repository.FilterGreaterThan,
	"gte":  repository.FilterGreaterOrEq,
	"lt":   repository.FilterLessThan,
	"lte":  repository.FilterLessOrEq,
	"like": repository.FilterLike,
	"band": repository.FilterBitwiseAnd,
}

// buildFilter parses an operator and value, leaving Field unset.
// It returns known=false for unrecognized operators.
func buildFilter(operator, value string) (filter ParsedFilter, known bool, err error) {
	if op, ok := simpleFilterOperators[operator]; ok {
		return ParsedFilter{Operator: op, Values: []string{value}}, true, nil
	}

	switch operator {
	case "in", "between":
		values := strings.Split(value, ",")
		for i, v := range values {
			values[i] = strings.TrimSpace(v)
		}
		op := repository.FilterIn
		if operator == "between" {
			op = repository.FilterBetween
		}
		return ParsedFilter{Operator: op, Values: values}, true, nil
	case "null":
		isNull, err := strconv.ParseBool(value)
		if err != nil {
			return ParsedFilter{}, true, errors.New("expected boolean")
		}
		if isNull {
			return ParsedFilter{Operator: repository.FilterIsNull}, true, nil
		}
		return ParsedFilter{Operator: repository.FilterIsNotNull}, true, nil
	default:
		return ParsedFilter{}, false, nil
	}
}

// rejectDuplicateSingleValueParams rejects repeated non-filter keys before
// c.Query can discard extra values. parseFilters checks duplicate filter keys.
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
	// Stable filter ordering produces reproducible WHERE clauses.
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

		filter, known, err := buildFilter(operator, values[0])
		if !known {
			return nil, &QueryParamError{
				Field:   key,
				Message: fmt.Sprintf("unknown operator %q", operator),
			}
		}
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
		for i := range value.Len() {
			result[i] = structToFilteredMap(value.Index(i).Interface(), fields)
		}
		return result
	}

	return structToFilteredMap(data, fields)
}

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
		fieldName, visible := jsonFieldName(field)
		if !visible {
			continue
		}

		if fieldSet[fieldName] {
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

// supportedFilterOperators lists the operators accepted in ParsedFilter.
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
		query.Filters = append(query.Filters, repository.FilterCondition{
			Field:    filter.Field,
			Operator: filter.Operator,
			Values:   filter.Values,
		})
	}

	return query, nil
}

// ParseListQuery parses list options into a [repository.ListQuery].
// On parse errors it writes an RFC 9457 response and returns false.
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
