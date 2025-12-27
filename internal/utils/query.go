// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// QueryParams represents parsed query parameters for modern filtering, sorting, pagination, and field selection
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

// SortField represents a single sort criteria
type SortField struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // "asc" or "desc"
}

// FilterOperation represents a filter operation on a field
type FilterOperation struct {
	Operator string      `json:"operator"` // "eq", "ne", "gt", "gte", "lt", "lte", "in", "like", "between"
	Value    interface{} `json:"value"`
	Values   []string    `json:"values"` // For "in" and "between" operations
}

// ListParams represents simplified parameters for list endpoints
type ListParams struct {
	Limit  int
	Offset int
	Sort   string
	Search string
}

// ParseQueryParams extracts and validates modern query parameters from the request
func ParseQueryParams(c *gin.Context) *QueryParams {
	if c == nil {
		return nil
	}

	params := &QueryParams{
		Filters: make(map[string]FilterOperation),
	}

	// Parse pagination
	params.Limit, params.Offset = GetPagination(c)

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

// parseSorting handles both modern sorting formats:
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

// parseFields handles field selection for sparse fieldsets
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

// filterOperatorHandler defines a function that creates a FilterOperation from a value
type filterOperatorHandler func(value string) FilterOperation

// filterOperatorHandlers maps operator names to their handler functions
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

// parseFilters handles modern filtering with nested parameters
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

// parseFilterKey extracts field name and operator from filter key
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

// applyTablePrefix adds table alias to column if needed
func applyTablePrefix(column, tableAlias string) string {
	// Add table prefix if specified and column doesn't contain parentheses or existing table prefix
	if tableAlias != "" && !strings.Contains(column, "(") && !strings.Contains(column, ".") {
		return tableAlias + "." + column
	}
	return column
}

// processHardcodedFilters processes config.Filters and adds conditions
func processHardcodedFilters(config EnhancedQueryConfig, conditions *[]string, args *[]interface{}) {
	if config.Filters == nil {
		return
	}

	for _, filter := range config.Filters {
		column := filter.Column
		// Add table prefix if specified and column doesn't contain parentheses or existing table prefix
		if filter.Table != "" && !strings.Contains(filter.Column, "(") && !strings.Contains(filter.Column, ".") {
			column = filter.Table + "." + filter.Column
		}

		operator := filter.Operator
		if operator == "" {
			operator = "="
		}

		*conditions = append(*conditions, column+" "+operator+" ?")
		*args = append(*args, filter.Value)
	}
}

// processStatusFiltering handles status and soft delete filtering
func processStatusFiltering(params *QueryParams, config EnhancedQueryConfig, conditions *[]string, args *[]interface{}) {
	// Handle status filtering (skip if soft delete is disabled)
	if !config.DisableSoftDelete {
		statusCondition := buildStatusCondition(params.Status, args)
		if statusCondition != "" {
			*conditions = append(*conditions, statusCondition)
		}
		return
	}

	// If soft delete is disabled but status is explicitly provided, handle it
	if params.Status != "" && params.Status != "all" {
		switch params.Status {
		case "active":
			*args = append(*args, models.StoryStatusActive)
			*conditions = append(*conditions, "status = ?")
		case "suspended":
			*conditions = append(*conditions, "suspended_at IS NOT NULL")
		default:
			*args = append(*args, params.Status)
			*conditions = append(*conditions, "status = ?")
		}
	}
}

// buildFilterCondition builds a single filter condition with arguments.
// SECURITY: Requires FieldMapping to prevent SQL injection. Rejects unmapped fields.
func buildFilterCondition(field string, filter FilterOperation, config EnhancedQueryConfig) (string, []interface{}) {
	// SECURITY: Require FieldMapping for all filter operations
	if config.FieldMapping == nil {
		return "", nil // No mapping = no filtering allowed
	}

	// SECURITY: Only allow fields explicitly in the allowlist
	dbField, exists := config.FieldMapping[field]
	if !exists {
		return "", nil // Unknown field = reject silently
	}

	// Add table prefix
	dbField = applyTablePrefix(dbField, config.TableAlias)

	var condition string
	var args []interface{}

	switch filter.Operator {
	case "IN":
		if len(filter.Values) > 0 {
			placeholders := make([]string, len(filter.Values))
			for i, value := range filter.Values {
				placeholders[i] = "?"
				args = append(args, value)
			}
			condition = dbField + " IN (" + strings.Join(placeholders, ", ") + ")"
		}
	case "BETWEEN":
		if len(filter.Values) == 2 {
			condition = dbField + " BETWEEN ? AND ?"
			args = append(args, filter.Values[0], filter.Values[1])
		}
	case "LIKE":
		condition = dbField + " LIKE ?"
		args = append(args, filter.Value)
	default:
		condition = dbField + " " + filter.Operator + " ?"
		args = append(args, filter.Value)
	}

	return condition, args
}

// processAdvancedFilters processes query param filters
func processAdvancedFilters(params *QueryParams, config EnhancedQueryConfig, conditions *[]string, args *[]interface{}) {
	for field, filter := range params.Filters {
		condition, filterArgs := buildFilterCondition(field, filter, config)
		if condition != "" {
			*conditions = append(*conditions, condition)
			*args = append(*args, filterArgs...)
		}
	}
}

// BuildModernQuery constructs SQL query with WHERE clause from modern query parameters
func BuildModernQuery(params *QueryParams, config EnhancedQueryConfig) (string, []interface{}, error) {
	if params == nil {
		return "", nil, fmt.Errorf("params cannot be nil")
	}

	var conditions []string
	var args []interface{}

	// Add base arguments
	if config.AllowedArgs != nil {
		args = append(args, config.AllowedArgs...)
	}

	// Process hardcoded filters from config first
	processHardcodedFilters(config, &conditions, &args)

	// Handle status filtering
	processStatusFiltering(params, config, &conditions, &args)

	// Handle search functionality
	searchCondition := buildSearchCondition(params.Search, config.SearchFields, &args)
	if searchCondition != "" {
		conditions = append(conditions, searchCondition)
	}

	// Handle advanced filters
	processAdvancedFilters(params, config, &conditions, &args)

	// Build WHERE clause
	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Build main query
	query := config.BaseQuery
	if whereClause != "" {
		query += " " + whereClause
	}

	// Add sorting
	if len(params.Sort) > 0 {
		orderBy := buildOrderByClause(params.Sort, config)
		if orderBy != "" {
			query += " ORDER BY " + orderBy
		}
	} else if config.DefaultOrder != "" {
		query += " ORDER BY " + config.DefaultOrder
	}

	return query, args, nil
}

// buildOrderByClause constructs ORDER BY clause from sort fields.
// SECURITY: Requires FieldMapping to prevent SQL injection. Skips unmapped fields.
func buildOrderByClause(sortFields []SortField, config EnhancedQueryConfig) string {
	if len(sortFields) == 0 {
		return ""
	}

	// SECURITY: Require FieldMapping for sort operations
	if config.FieldMapping == nil {
		return ""
	}

	orderParts := make([]string, 0, len(sortFields))
	for _, sortField := range sortFields {
		// SECURITY: Only allow fields explicitly in the allowlist
		dbField, exists := config.FieldMapping[sortField.Field]
		if !exists {
			continue // Skip unknown fields
		}

		// Add table prefix if specified and field doesn't contain parentheses or existing table prefix
		if config.TableAlias != "" && !strings.Contains(dbField, "(") && !strings.Contains(dbField, ".") {
			dbField = config.TableAlias + "." + dbField
		}

		// Validate sort direction
		direction := "ASC"
		if strings.ToUpper(sortField.Direction) == "DESC" {
			direction = "DESC"
		}

		orderParts = append(orderParts, dbField+" "+direction)
	}

	return strings.Join(orderParts, ", ")
}

// SelectFields builds field selection for sparse fieldsets.
// SECURITY: Requires FieldMapping to prevent SQL injection. Skips unmapped fields.
func SelectFields(params *QueryParams, config EnhancedQueryConfig) string {
	if len(params.Fields) == 0 {
		return config.DefaultFields
	}

	// SECURITY: Require FieldMapping for field selection
	if config.FieldMapping == nil {
		return config.DefaultFields
	}

	// Map requested fields to database columns
	dbFields := make([]string, 0, len(params.Fields))
	for _, field := range params.Fields {
		// SECURITY: Only allow fields explicitly in the allowlist
		dbField, exists := config.FieldMapping[field]
		if !exists {
			continue // Skip unknown fields
		}

		needsAlias := false
		// Check if this is an expression that needs an alias
		if strings.Contains(dbField, "(") && !strings.Contains(dbField, " as ") {
			needsAlias = true
		}

		// Add table prefix if specified and field doesn't contain parentheses or existing table prefix
		if config.TableAlias != "" && !strings.Contains(dbField, "(") && !strings.Contains(dbField, ".") {
			dbField = config.TableAlias + "." + dbField
		}

		// Add alias for expressions that need it
		if needsAlias {
			dbField = dbField + " as " + field
		}

		dbFields = append(dbFields, dbField)
	}

	if len(dbFields) == 0 {
		return config.DefaultFields
	}
	return strings.Join(dbFields, ", ")
}

// FilterResponseFields filters the response to only include requested fields
func FilterResponseFields(data interface{}, fields []string) interface{} {
	if len(fields) == 0 {
		return data
	}

	// Use reflection to create a filtered response
	return filterStructFields(data, fields)
}

// filterStructFields uses reflection to filter struct fields
func filterStructFields(data interface{}, fields []string) interface{} {
	if len(fields) == 0 {
		return data
	}

	value := reflect.ValueOf(data)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	// Handle slices
	if value.Kind() == reflect.Slice {
		result := make([]map[string]interface{}, value.Len())
		for i := 0; i < value.Len(); i++ {
			result[i] = structToFilteredMap(value.Index(i).Interface(), fields)
		}
		return result
	}

	// Handle single struct
	return structToFilteredMap(data, fields)
}

// structToFilteredMap converts struct to map with only requested fields
func structToFilteredMap(data interface{}, fields []string) map[string]interface{} {
	result := make(map[string]interface{})

	value := reflect.ValueOf(data)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
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

// EnhancedQueryConfig extends QueryConfig with modern features
type EnhancedQueryConfig struct {
	QueryConfig
	SearchFields      []string          // Fields to search in for full-text search
	FieldMapping      map[string]string // Map API field names to database columns
	TableAlias        string            // Table alias for prefixing columns
	DefaultFields     string            // Default SELECT fields
	DisableSoftDelete bool              // If true, don't apply soft delete filtering
}

// extractWhereClause extracts the WHERE clause from a query string
func extractWhereClause(query string) string {
	whereStart := strings.Index(query, "WHERE")
	if whereStart < 0 {
		return ""
	}

	// Find the end of the WHERE clause
	remaining := query[whereStart:]
	orderByPos := strings.Index(remaining, "ORDER BY")
	limitPos := strings.Index(remaining, "LIMIT")

	var endPos int
	switch {
	case orderByPos >= 0:
		endPos = orderByPos
	case limitPos >= 0:
		endPos = limitPos
	default:
		endPos = len(remaining)
	}

	return strings.TrimSpace(remaining[:endPos])
}

// buildEnhancedConfig creates an EnhancedQueryConfig from the provided config
func buildEnhancedConfig(config EnhancedQueryConfig) EnhancedQueryConfig {
	return EnhancedQueryConfig{
		QueryConfig: QueryConfig{
			BaseQuery:     config.BaseQuery,
			CountQuery:    config.CountQuery,
			DefaultOrder:  config.DefaultOrder,
			AllowedArgs:   config.AllowedArgs,
			PostProcessor: config.PostProcessor,
			Filters:       config.Filters,
		},
		SearchFields:      config.SearchFields,
		FieldMapping:      config.FieldMapping,
		TableAlias:        config.TableAlias,
		DefaultFields:     config.DefaultFields,
		DisableSoftDelete: config.DisableSoftDelete,
	}
}

// sendPaginatedListResponse handles sending the final paginated response
func sendPaginatedListResponse(c *gin.Context, result interface{}, total int64, params *QueryParams, config EnhancedQueryConfig) {
	if config.PostProcessor != nil {
		c.Set("pagination_data", map[string]interface{}{
			"total":  total,
			"limit":  params.Limit,
			"offset": params.Offset,
		})
		config.PostProcessor(result)

		if c.Writer.Written() {
			return
		}

		responseData := result
		if processedData, exists := c.Get("processed_bulletin_stories"); exists {
			responseData = processedData
		} else if len(params.Fields) > 0 {
			responseData = FilterResponseFields(result, params.Fields)
		}

		PaginatedResponse(c, responseData, total, params.Limit, params.Offset)
		return
	}

	responseData := result
	if len(params.Fields) > 0 {
		responseData = FilterResponseFields(result, params.Fields)
	}
	PaginatedResponse(c, responseData, total, params.Limit, params.Offset)
}

// ModernListWithQuery handles paginated list requests with modern query parameters
func ModernListWithQuery(c *gin.Context, db *sqlx.DB, config EnhancedQueryConfig, result interface{}) {
	if c == nil || db == nil || result == nil {
		ProblemInternalServer(c, "Invalid parameters for query")
		return
	}

	params := ParseQueryParams(c)
	if params == nil {
		ProblemInternalServer(c, "Failed to parse query parameters")
		return
	}

	enhancedConfig := buildEnhancedConfig(config)

	if len(params.Fields) > 0 && config.DefaultFields != "" {
		selectFields := SelectFields(params, config)
		enhancedConfig.BaseQuery = strings.Replace(enhancedConfig.BaseQuery, config.DefaultFields, selectFields, 1)
	}

	query, args, err := BuildModernQuery(params, enhancedConfig)
	if err != nil {
		ProblemInternalServer(c, "Failed to build query: "+err.Error())
		return
	}

	if config.CountQuery == "" {
		ProblemInternalServer(c, "Count query not provided")
		return
	}

	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	countQuery := config.CountQuery
	if whereClause := extractWhereClause(query); whereClause != "" {
		countQuery += " " + whereClause
	}

	total, err := CountWithJoins(db, countQuery, countArgs...)
	if err != nil {
		ProblemInternalServer(c, "Failed to count records: "+err.Error())
		return
	}

	query += " LIMIT ? OFFSET ?"
	args = append(args, params.Limit, params.Offset)

	if err := db.Select(result, query, args...); err != nil {
		ProblemInternalServer(c, "Failed to fetch records: "+err.Error())
		return
	}

	sendPaginatedListResponse(c, result, total, params, config)
}

// buildStatusCondition builds the SQL condition for status filtering
func buildStatusCondition(status string, args *[]interface{}) string {
	switch status {
	case "all":
		return "" // Include all records, no filter
	case "active":
		*args = append(*args, models.StoryStatusActive)
		return "deleted_at IS NULL AND status = ?"
	case "deleted":
		return "deleted_at IS NOT NULL"
	case "suspended":
		return "suspended_at IS NOT NULL"
	case "":
		return "deleted_at IS NULL" // Default: exclude deleted records
	default:
		// Treat as status filter
		*args = append(*args, status)
		return "status = ?"
	}
}

// buildSearchCondition builds the SQL condition for search functionality
func buildSearchCondition(search string, searchFields []string, args *[]interface{}) string {
	if search == "" || searchFields == nil {
		return ""
	}

	searchConditions := make([]string, 0, len(searchFields))
	for _, field := range searchFields {
		searchConditions = append(searchConditions, field+" LIKE ?")
		*args = append(*args, "%"+search+"%")
	}

	if len(searchConditions) > 0 {
		return "(" + strings.Join(searchConditions, " OR ") + ")"
	}
	return ""
}
