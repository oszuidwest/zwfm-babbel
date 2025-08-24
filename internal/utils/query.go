// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
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

// ParseListParams extracts simple list parameters for basic endpoints
func ParseListParams(c *gin.Context) ListParams {
	params := ListParams{}

	// Parse pagination
	params.Limit, params.Offset = GetPagination(c)

	// Parse sort (simple string format: -field or field)
	params.Sort = c.Query("sort")

	// Parse search
	params.Search = c.Query("search")

	return params
}

// ParseQueryParams extracts and validates modern query parameters from the request
func ParseQueryParams(c *gin.Context) *QueryParams {
	if c == nil {
		return nil
	}

	params := &QueryParams{
		Filters:        make(map[string]FilterOperation),
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

	var sortFields []SortField
	parts := strings.Split(sortParam, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		var field, direction string

		// Check for prefix notation (-field or +field) or colon notation
		switch {
		case strings.HasPrefix(part, "-"):
			field = strings.TrimPrefix(part, "-")
			direction = "desc"
		case strings.HasPrefix(part, "+"):
			field = strings.TrimPrefix(part, "+")
			direction = "asc"
		case strings.Contains(part, ":"):
			// Check for colon notation (field:direction)
			colonParts := strings.Split(part, ":")
			if len(colonParts) == 2 {
				field = strings.TrimSpace(colonParts[0])
				direction = strings.ToLower(strings.TrimSpace(colonParts[1]))
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

	var fields []string
	parts := strings.Split(fieldsParam, ",")

	for _, part := range parts {
		field := strings.TrimSpace(part)
		if field != "" {
			fields = append(fields, field)
		}
	}

	return fields
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

	// Parse all query parameters to find filter patterns
	for key, values := range c.Request.URL.Query() {
		if !strings.HasPrefix(key, "filter[") {
			continue
		}

		// Extract field name and operator
		field, operator := parseFilterKey(key)
		if field == "" || len(values) == 0 {
			continue
		}

		value := values[0] // Take first value

		switch operator {
		case "in":
			// Handle comma-separated values for IN operation
			filterValues := strings.Split(value, ",")
			for i, v := range filterValues {
				filterValues[i] = strings.TrimSpace(v)
			}
			filters[field] = FilterOperation{
				Operator: "IN",
				Values:   filterValues,
			}
		case "between":
			// Handle comma-separated values for BETWEEN operation
			betweenValues := strings.Split(value, ",")
			if len(betweenValues) == 2 {
				filters[field] = FilterOperation{
					Operator: "BETWEEN",
					Values:   []string{strings.TrimSpace(betweenValues[0]), strings.TrimSpace(betweenValues[1])},
				}
			}
		case "like":
			filters[field] = FilterOperation{
				Operator: "LIKE",
				Value:    "%" + value + "%",
			}
		case "gte":
			filters[field] = FilterOperation{
				Operator: ">=",
				Value:    value,
			}
		case "gt":
			filters[field] = FilterOperation{
				Operator: ">",
				Value:    value,
			}
		case "lte":
			filters[field] = FilterOperation{
				Operator: "<=",
				Value:    value,
			}
		case "lt":
			filters[field] = FilterOperation{
				Operator: "<",
				Value:    value,
			}
		case "ne":
			filters[field] = FilterOperation{
				Operator: "!=",
				Value:    value,
			}
		default:
			// Default to equality
			filters[field] = FilterOperation{
				Operator: "=",
				Value:    value,
			}
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
	if !strings.HasPrefix(key, "filter[") {
		return "", ""
	}

	content := strings.TrimPrefix(key, "filter[")
	if !strings.HasSuffix(content, "]") {
		return "", ""
	}

	content = strings.TrimSuffix(content, "]")

	// Check for nested structure: field][operator
	parts := strings.Split(content, "][")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	// Simple field filter
	return content, ""
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

	// Handle status filtering (skip if soft delete is disabled)
	if !config.DisableSoftDelete {
		statusCondition := buildStatusCondition(params.Status, &args)
		if statusCondition != "" {
			conditions = append(conditions, statusCondition)
		}
	} else if params.Status != "" && params.Status != "all" {
		// If soft delete is disabled but status is explicitly provided, handle it
		switch params.Status {
		case "active":
			conditions = append(conditions, "status = 'active'")
		case "suspended":
			conditions = append(conditions, "suspended_at IS NOT NULL")
		default:
			args = append(args, params.Status)
			conditions = append(conditions, "status = ?")
		}
	}

	// Handle search functionality
	searchCondition := buildSearchCondition(params.Search, config.SearchFields, &args)
	if searchCondition != "" {
		conditions = append(conditions, searchCondition)
	}


	// Handle advanced filters
	for field, filter := range params.Filters {
		// Map field names to database columns if needed
		dbField := field
		if config.FieldMapping != nil {
			if mapped, exists := config.FieldMapping[field]; exists {
				dbField = mapped
			}
		}

		// Add table prefix if specified and field doesn't contain parentheses or existing table prefix
		if config.TableAlias != "" && !strings.Contains(dbField, "(") && !strings.Contains(dbField, ".") {
			dbField = config.TableAlias + "." + dbField
		}

		switch filter.Operator {
		case "IN":
			if len(filter.Values) > 0 {
				placeholders := make([]string, len(filter.Values))
				for i, value := range filter.Values {
					placeholders[i] = "?"
					args = append(args, value)
				}
				conditions = append(conditions, dbField+" IN ("+strings.Join(placeholders, ", ")+")")
			}
		case "BETWEEN":
			if len(filter.Values) == 2 {
				conditions = append(conditions, dbField+" BETWEEN ? AND ?")
				args = append(args, filter.Values[0], filter.Values[1])
			}
		case "LIKE":
			conditions = append(conditions, dbField+" LIKE ?")
			args = append(args, filter.Value)
		default:
			conditions = append(conditions, dbField+" "+filter.Operator+" ?")
			args = append(args, filter.Value)
		}
	}

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

// buildOrderByClause constructs ORDER BY clause from sort fields
func buildOrderByClause(sortFields []SortField, config EnhancedQueryConfig) string {
	if len(sortFields) == 0 {
		return ""
	}

	var orderParts []string
	for _, sortField := range sortFields {
		// Map field names to database columns if needed
		dbField := sortField.Field
		if config.FieldMapping != nil {
			if mapped, exists := config.FieldMapping[sortField.Field]; exists {
				dbField = mapped
			}
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

// SelectFields builds field selection for sparse fieldsets
func SelectFields(params *QueryParams, config EnhancedQueryConfig) string {
	if len(params.Fields) == 0 {
		return config.DefaultFields
	}

	// Map requested fields to database columns
	var dbFields []string
	for _, field := range params.Fields {
		dbField := field
		needsAlias := false

		if config.FieldMapping != nil {
			if mapped, exists := config.FieldMapping[field]; exists {
				dbField = mapped
				// Check if this is an expression that needs an alias
				if strings.Contains(dbField, "(") && !strings.Contains(dbField, " as ") {
					needsAlias = true
				}
			}
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
			if commaIdx := strings.Index(jsonTag, ","); commaIdx != -1 {
				fieldName = jsonTag[:commaIdx]
			} else {
				fieldName = jsonTag
			}
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

// ModernListWithQuery handles paginated list requests with modern query parameters
func ModernListWithQuery(c *gin.Context, db *sqlx.DB, config EnhancedQueryConfig, result interface{}) {
	// Validate inputs
	if c == nil || db == nil || result == nil {
		ProblemInternalServer(c, "Invalid parameters for query")
		return
	}

	params := ParseQueryParams(c)
	if params == nil {
		ProblemInternalServer(c, "Failed to parse query parameters")
		return
	}

	// Build enhanced query config
	enhancedConfig := EnhancedQueryConfig{
		QueryConfig: QueryConfig{
			BaseQuery:     config.BaseQuery,
			CountQuery:    config.CountQuery,
			DefaultOrder:  config.DefaultOrder,
			AllowedArgs:   config.AllowedArgs,
			PostProcessor: config.PostProcessor,
		},
		SearchFields:      config.SearchFields,
		FieldMapping:      config.FieldMapping,
		TableAlias:        config.TableAlias,
		DefaultFields:     config.DefaultFields,
		DisableSoftDelete: config.DisableSoftDelete,
	}

	// Use custom field selection if requested
	if len(params.Fields) > 0 && config.DefaultFields != "" {
		selectFields := SelectFields(params, config)
		enhancedConfig.BaseQuery = strings.Replace(enhancedConfig.BaseQuery, config.DefaultFields, selectFields, 1)
	}

	// Build query with modern parameters
	query, args, err := BuildModernQuery(params, enhancedConfig)
	if err != nil {
		ProblemInternalServer(c, "Failed to build query: "+err.Error())
		return
	}

	// Get total count with same filters
	countQuery := config.CountQuery
	if countQuery == "" {
		ProblemInternalServer(c, "Count query not provided")
		return
	}

	// Safely extract count arguments
	var countArgs []interface{}
	if len(config.AllowedArgs) > 0 && len(args) >= len(config.AllowedArgs) {
		countArgs = args[:len(config.AllowedArgs)]
	} else {
		countArgs = config.AllowedArgs
	}

	// Add filter conditions to count query - safer string manipulation
	if strings.Contains(query, "WHERE") {
		whereStart := strings.Index(query, "WHERE")
		if whereStart >= 0 {
			var whereClause string

			// Find the end of the WHERE clause
			orderByPos := strings.Index(query[whereStart:], "ORDER BY")
			limitPos := strings.Index(query[whereStart:], "LIMIT")

			switch {
			case orderByPos >= 0:
				whereClause = query[whereStart : whereStart+orderByPos]
			case limitPos >= 0:
				whereClause = query[whereStart : whereStart+limitPos]
			default:
				whereClause = query[whereStart:]
			}

			whereClause = strings.TrimSpace(whereClause)
			if whereClause != "" {
				countQuery += " " + whereClause
				// Add filter arguments to count query - need to calculate this before LIMIT/OFFSET are added
				baseArgsLen := len(config.AllowedArgs)
				if baseArgsLen < 0 {
					baseArgsLen = 0
				}

				// At this point, args doesn't include LIMIT/OFFSET yet, so we can use all args after base args
				if len(args) > baseArgsLen {
					filterArgs := args[baseArgsLen:]
					countArgs = append(countArgs, filterArgs...)
				}
			}
		}
	}

	total, err := CountWithJoins(db, countQuery, countArgs...)
	if err != nil {
		ProblemInternalServer(c, "Failed to count records: "+err.Error())
		return
	}

	// Add pagination
	query += " LIMIT ? OFFSET ?"
	args = append(args, params.Limit, params.Offset)

	// Execute query
	if err := db.Select(result, query, args...); err != nil {
		ProblemInternalServer(c, "Failed to fetch records: "+err.Error())
		return
	}

	// Apply post-processing if provided
	if config.PostProcessor != nil {
		config.PostProcessor(result)
	}

	// Filter response fields if requested - note: this creates a new object
	responseData := result
	if len(params.Fields) > 0 {
		responseData = FilterResponseFields(result, params.Fields)
	}

	PaginatedResponse(c, responseData, total, params.Limit, params.Offset)
}

// buildStatusCondition builds the SQL condition for status filtering
func buildStatusCondition(status string, args *[]interface{}) string {
	switch status {
	case "all":
		return "" // Include all records, no filter
	case "active":
		return "deleted_at IS NULL AND status = 'active'"
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


