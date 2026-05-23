package utils

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// QueryParams represents parsed query parameters for modern filtering, sorting, pagination, and field selection.
type QueryParams struct {
	// Pagination
	Limit  int `json:"limit"`
	Offset int `json:"offset"`

	// Sorting
	Sort []SortField `json:"sort"`

	// Field Selection (sparse fieldsets)
	Fields []string `json:"fields"`

	// Filtering
	Filters map[string]FilterOperation `json:"filters"`

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

// FilterOperation represents a filter operation on a field. Operator values come
// from repository.Filter* constants so callers do not translate between vocabularies.
type FilterOperation struct {
	Operator repository.FilterOperator `json:"operator"`
	Value    any                       `json:"value"`
	Values   []string                  `json:"values"` // For "in" and "between" operations
}

// ParseQueryParams extracts and validates modern query parameters from the request.
func ParseQueryParams(c *gin.Context) (*QueryParams, error) {
	if c == nil {
		return nil, errors.New("missing request context")
	}

	params := &QueryParams{
		Filters: make(map[string]FilterOperation),
	}

	// Parse pagination
	params.Limit, params.Offset = Pagination(c)

	sortFields, err := parseSorting(c)
	if err != nil {
		return nil, err
	}
	if sortFields != nil {
		params.Sort = sortFields
	}

	// Parse field selection - handle nil safely
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

	// Parse trashed (soft-delete filter): "only", "with", or empty
	params.Trashed = c.Query("trashed")

	// Parse search
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

		// Check for prefix notation (-field or +field) or colon notation
		switch {
		case strings.HasPrefix(part, "-"):
			field, _ = strings.CutPrefix(part, "-")
			direction = "desc"
		case strings.HasPrefix(part, "+"):
			field, _ = strings.CutPrefix(part, "+")
			direction = "asc"
		case strings.Contains(part, ":"):
			// Check for colon notation (field:direction)
			if before, after, found := strings.Cut(part, ":"); found {
				field = strings.TrimSpace(before)
				direction = strings.ToLower(strings.TrimSpace(after))
				if direction != "asc" && direction != "desc" {
					return nil, fmt.Errorf("invalid sort direction %q for field %q; use asc or desc", after, field)
				}
			}
		default:
			// No direction specified, default to asc
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

// filterOperatorHandler defines a function that creates a FilterOperation from a value.
type filterOperatorHandler func(value string) (FilterOperation, error)

// filterOperatorHandlers maps operator names to their handler functions.
var filterOperatorHandlers = map[string]filterOperatorHandler{
	"eq": func(value string) (FilterOperation, error) {
		return FilterOperation{Operator: repository.FilterEquals, Value: value}, nil
	},
	"in": func(value string) (FilterOperation, error) {
		filterValues := strings.Split(value, ",")
		for i, v := range filterValues {
			filterValues[i] = strings.TrimSpace(v)
		}
		return FilterOperation{Operator: repository.FilterIn, Values: filterValues}, nil
	},
	"between": func(value string) (FilterOperation, error) {
		betweenValues := strings.Split(value, ",")
		if len(betweenValues) != 2 {
			return FilterOperation{}, errors.New("expected two comma-separated values")
		}
		lower := strings.TrimSpace(betweenValues[0])
		upper := strings.TrimSpace(betweenValues[1])
		if lower == "" || upper == "" {
			return FilterOperation{}, errors.New("expected two non-empty values")
		}
		return FilterOperation{Operator: repository.FilterBetween, Values: []string{lower, upper}}, nil
	},
	"like": func(value string) (FilterOperation, error) {
		return FilterOperation{Operator: repository.FilterLike, Value: "%" + value + "%"}, nil
	},
	"gte": func(value string) (FilterOperation, error) {
		return FilterOperation{Operator: repository.FilterGreaterOrEq, Value: value}, nil
	},
	"gt": func(value string) (FilterOperation, error) {
		return FilterOperation{Operator: repository.FilterGreaterThan, Value: value}, nil
	},
	"lte": func(value string) (FilterOperation, error) {
		return FilterOperation{Operator: repository.FilterLessOrEq, Value: value}, nil
	},
	"lt": func(value string) (FilterOperation, error) {
		return FilterOperation{Operator: repository.FilterLessThan, Value: value}, nil
	},
	"ne": func(value string) (FilterOperation, error) {
		return FilterOperation{Operator: repository.FilterNotEquals, Value: value}, nil
	},
	"not": func(value string) (FilterOperation, error) {
		return FilterOperation{Operator: repository.FilterNotEquals, Value: value}, nil
	},
	"null": func(value string) (FilterOperation, error) {
		isNull, err := strconv.ParseBool(value)
		if err != nil {
			return FilterOperation{}, errors.New("expected boolean")
		}
		if isNull {
			return FilterOperation{Operator: repository.FilterIsNull}, nil
		}
		return FilterOperation{Operator: repository.FilterIsNotNull}, nil
	},
	"band": func(value string) (FilterOperation, error) {
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return FilterOperation{}, errors.New("expected integer between 0 and 255")
		}
		return FilterOperation{Operator: repository.FilterBitwiseAnd, Value: uint8(val)}, nil
	},
	"": func(value string) (FilterOperation, error) {
		return FilterOperation{Operator: repository.FilterEquals, Value: value}, nil
	},
}

// parseFilters parses the filter query parameters into filter operations.
func parseFilters(c *gin.Context) (map[string]FilterOperation, error) {
	filters := make(map[string]FilterOperation)

	if c == nil || c.Request == nil || c.Request.URL == nil {
		return filters, nil
	}

	for key, values := range c.Request.URL.Query() {
		if !strings.HasPrefix(key, "filter[") || len(values) == 0 {
			continue
		}

		field, operator := parseFilterKey(key)
		if field == "" {
			return nil, fmt.Errorf("invalid filter parameter %q; expected filter[field] or filter[field][operator]", key)
		}

		handler, exists := filterOperatorHandlers[operator]
		if !exists {
			return nil, fmt.Errorf("invalid filter operator %q for field %q", operator, field)
		}

		filter, err := handler(values[0])
		if err != nil {
			return nil, fmt.Errorf("invalid filter value for %s: %w", filterKeyLabel(field, operator), err)
		}

		filters[field] = filter
	}

	return filters, nil
}

// parseFilterKey extracts field name and operator from a filter key.
func parseFilterKey(key string) (field, operator string) {
	// Remove "filter[" prefix and "]" suffix
	content, found := strings.CutPrefix(key, "filter[")
	if !found {
		return "", ""
	}
	content, found = strings.CutSuffix(content, "]")
	if !found {
		return "", ""
	}

	// Check for nested structure: field][operator
	if before, after, found := strings.Cut(content, "]["); found {
		return before, after
	}

	// Simple field filter
	return content, ""
}

func filterKeyLabel(field, operator string) string {
	if operator == "" {
		return fmt.Sprintf("filter[%s]", field)
	}
	return fmt.Sprintf("filter[%s][%s]", field, operator)
}

// FilterStructFields filters struct fields to return only requested fields.
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

	// Handle slices
	if value.Kind() == reflect.Slice {
		result := make([]map[string]any, value.Len())
		for i := 0; i < value.Len(); i++ {
			result[i] = structToFilteredMap(value.Index(i).Interface(), fields)
		}
		return result
	}

	// Handle single struct
	return structToFilteredMap(data, fields)
}

// structToFilteredMap converts struct to map with only requested fields.
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

		// Skip fields explicitly excluded from JSON serialization
		if jsonTag == "-" {
			continue
		}

		// Parse JSON tag to get field name
		fieldName := field.Name
		if jsonTag != "" {
			fieldName, _, _ = strings.Cut(jsonTag, ",")
		}

		// Include field if it's in the requested fields
		if fieldSet[fieldName] {
			result[fieldName] = fieldVal.Interface()
		}
	}

	return result
}

// supportedFilterOperators is the set of repository.FilterOperator values that
// FilterOperation may carry. Keeping a single source of truth here lets us
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

	for field, filter := range params.Filters {
		if !supportedFilterOperators[filter.Operator] {
			return nil, fmt.Errorf("unsupported filter operator %q", filter.Operator)
		}
		condition := repository.FilterCondition{
			Field:    field,
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
func ParseListQuery(c *gin.Context) (*QueryParams, *repository.ListQuery, bool) {
	params, err := ParseQueryParams(c)
	if err != nil {
		ProblemBadRequest(c, err.Error())
		return nil, nil, false
	}
	query, err := QueryParamsToListQuery(params)
	if err != nil {
		ProblemBadRequest(c, err.Error())
		return nil, nil, false
	}
	return params, query, true
}

// PaginatedListResponse writes a paginated response, applying sparse-fieldset
// filtering when params.Fields is non-empty.
func PaginatedListResponse[T any](c *gin.Context, params *QueryParams, result *repository.ListResult[T]) {
	if c == nil || result == nil {
		return
	}
	var data any = result.Data
	if params != nil && len(params.Fields) > 0 {
		data = FilterStructFields(result.Data, params.Fields)
	}
	PaginatedResponse(c, data, result.Total, result.Limit, result.Offset)
}
