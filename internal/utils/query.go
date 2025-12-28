// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"reflect"
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

	// Status filtering
	Status string `json:"status"`

	// Search
	Search string `json:"search"`
}

// SortField represents a single sort criterion.
type SortField struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // "asc" or "desc"
}

// FilterOperation represents a filter operation on a field.
type FilterOperation struct {
	Operator string   `json:"operator"` // "eq", "ne", "gt", "gte", "lt", "lte", "in", "like", "between"
	Value    any      `json:"value"`
	Values   []string `json:"values"` // For "in" and "between" operations
}

// ParseQueryParams extracts and validates modern query parameters from the request.
func ParseQueryParams(c *gin.Context) *QueryParams {
	if c == nil {
		return nil
	}

	params := &QueryParams{
		Filters: make(map[string]FilterOperation),
	}

	// Parse pagination
	params.Limit, params.Offset = Pagination(c)

	// Parse sorting - handle nil safely
	if sortFields := parseSorting(c); sortFields != nil {
		params.Sort = sortFields
	}

	// Parse field selection - handle nil safely
	if fields := parseFields(c); fields != nil {
		params.Fields = fields
	}

	// Parse filters - handle nil safely
	if filters := parseFilters(c); filters != nil {
		params.Filters = filters
	}

	// Parse status
	params.Status = c.Query("status")

	// Parse search
	params.Search = c.Query("search")

	return params
}

// parseSorting handles both modern sorting formats.
// - ?sort=created_at:desc,name:asc
// - ?sort=-created_at,+name (or just -created_at,name)
func parseSorting(c *gin.Context) []SortField {
	if c == nil {
		return nil
	}

	sortParam := c.Query("sort")
	if sortParam == "" {
		return nil
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
					direction = "asc" // Default to asc for invalid direction
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

	return sortFields
}

// parseFields handles field selection for sparse fieldsets.
// ?fields=id,name,created_at
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
type filterOperatorHandler func(value string) FilterOperation

// filterOperatorHandlers maps operator names to their handler functions.
var filterOperatorHandlers = map[string]filterOperatorHandler{
	"in": func(value string) FilterOperation {
		filterValues := strings.Split(value, ",")
		for i, v := range filterValues {
			filterValues[i] = strings.TrimSpace(v)
		}
		return FilterOperation{Operator: "IN", Values: filterValues}
	},
	"between": func(value string) FilterOperation {
		betweenValues := strings.Split(value, ",")
		if len(betweenValues) == 2 {
			return FilterOperation{
				Operator: "BETWEEN",
				Values:   []string{strings.TrimSpace(betweenValues[0]), strings.TrimSpace(betweenValues[1])},
			}
		}
		return FilterOperation{} // Invalid between, return empty
	},
	"like": func(value string) FilterOperation {
		return FilterOperation{Operator: "LIKE", Value: "%" + value + "%"}
	},
	"gte": func(value string) FilterOperation {
		return FilterOperation{Operator: ">=", Value: value}
	},
	"gt": func(value string) FilterOperation {
		return FilterOperation{Operator: ">", Value: value}
	},
	"lte": func(value string) FilterOperation {
		return FilterOperation{Operator: "<=", Value: value}
	},
	"lt": func(value string) FilterOperation {
		return FilterOperation{Operator: "<", Value: value}
	},
	"ne": func(value string) FilterOperation {
		return FilterOperation{Operator: "!=", Value: value}
	},
	"": func(value string) FilterOperation {
		return FilterOperation{Operator: "=", Value: value}
	},
}

// parseFilters handles modern filtering with nested parameters.
// ?filter[field]=value
// ?filter[created_at][gte]=2024-01-01
// ?filter[id][in]=1,2,3
func parseFilters(c *gin.Context) map[string]FilterOperation {
	filters := make(map[string]FilterOperation)

	if c == nil || c.Request == nil || c.Request.URL == nil {
		return filters
	}

	for key, values := range c.Request.URL.Query() {
		if !strings.HasPrefix(key, "filter[") || len(values) == 0 {
			continue
		}

		field, operator := parseFilterKey(key)
		if field == "" {
			continue
		}

		handler, exists := filterOperatorHandlers[operator]
		if !exists {
			handler = filterOperatorHandlers[""] // Default to equality
		}

		filter := handler(values[0])
		if filter.Operator != "" { // Only add if valid
			filters[field] = filter
		}
	}

	return filters
}

// parseFilterKey extracts field name and operator from filter key.
// Examples:
// filter[name] -> field: "name", operator: ""
// filter[created_at][gte] -> field: "created_at", operator: "gte"
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

// FilterStructFields uses reflection to filter struct fields.
// Exported for use by handlers that need field filtering.
func FilterStructFields(data any, fields []string) any {
	if len(fields) == 0 {
		return data
	}

	value := reflect.ValueOf(data)
	if !value.IsValid() {
		return data
	}

	if value.Kind() == reflect.Ptr {
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

	if value.Kind() == reflect.Ptr {
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

	valueType := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := valueType.Field(i)
		jsonTag := field.Tag.Get("json")

		// Parse JSON tag
		fieldName := field.Name
		if jsonTag != "" && jsonTag != "-" {
			fieldName, _, _ = strings.Cut(jsonTag, ",")
		}

		// Include field if it's in the requested fields
		if fieldSet[fieldName] {
			result[fieldName] = value.Field(i).Interface()
		}
	}

	return result
}

// ParseListQuery parses HTTP query parameters into a repository.ListQuery.
// Converts utils.QueryParams format to repository.ListQuery format for use with repository List methods.
func ParseListQuery(c *gin.Context) *repository.ListQuery {
	params := ParseQueryParams(c)
	if params == nil {
		return repository.NewListQuery()
	}

	query := &repository.ListQuery{
		Limit:  params.Limit,
		Offset: params.Offset,
		Search: params.Search,
		Status: params.Status,
	}

	// Convert sort fields
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

	// Convert filters
	for field, filter := range params.Filters {
		condition := repository.FilterCondition{
			Field: field,
			Value: filter.Value,
		}

		// Map operator strings to repository.FilterOperator
		switch filter.Operator {
		case "=":
			condition.Operator = repository.FilterEquals
		case "!=":
			condition.Operator = repository.FilterNotEquals
		case ">":
			condition.Operator = repository.FilterGreaterThan
		case ">=":
			condition.Operator = repository.FilterGreaterOrEq
		case "<":
			condition.Operator = repository.FilterLessThan
		case "<=":
			condition.Operator = repository.FilterLessOrEq
		case "LIKE":
			condition.Operator = repository.FilterLike
		case "IN":
			condition.Operator = repository.FilterIn
			condition.Value = filter.Values
		default:
			condition.Operator = repository.FilterEquals
		}

		query.Filters = append(query.Filters, condition)
	}

	return query
}
