package utils

import (
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// QueryParams holds parsed list options plus the sparse fieldset.
type QueryParams struct {
	repository.ListQuery
	// Fields lists the JSON field names requested with ?fields=.
	Fields []string
}

// parseQueryParams parses list options and validates query syntax, operator
// names, duplicate keys, and pagination. The repository validates field
// names, operator applicability, and values. Callers decide on trashed:
// [ParseListQueryWithTrashed] validates its value, the other parsers reject it.
func parseQueryParams(c *gin.Context) (*QueryParams, *apperrors.FieldError) {
	query := c.Request.URL.Query()

	if err := rejectDuplicateSingleValueParams(query); err != nil {
		return nil, err
	}

	limit, offset, err := parsePagination(query)
	if err != nil {
		return nil, err
	}

	sortFields, err := parseSorting(query.Get("sort"))
	if err != nil {
		return nil, err
	}

	filters, err := parseFilters(query)
	if err != nil {
		return nil, err
	}

	return &QueryParams{
		ListQuery: repository.ListQuery{
			Limit:   limit,
			Offset:  offset,
			Sort:    sortFields,
			Filters: filters,
			Trashed: query.Get("trashed"),
			Search:  query.Get("search"),
		},
		Fields: parseFields(query.Get("fields")),
	}, nil
}

const (
	defaultPaginationLimit = 20
	maxPaginationLimit     = 100
)

// parsePagination reads limit and offset, defaulting to 20 and 0. Malformed or
// out-of-range values are errors rather than silently replaced by defaults.
func parsePagination(query url.Values) (limit, offset int, err *apperrors.FieldError) {
	limit = defaultPaginationLimit
	if raw := query.Get("limit"); raw != "" {
		l, atoiErr := strconv.Atoi(raw)
		switch {
		case atoiErr != nil:
			return 0, 0, queryError("limit", apperrors.CodeInvalidFormat, fmt.Sprintf("expected integer, got %q", raw))
		case l < 1:
			return 0, 0, queryError("limit", apperrors.CodeOutOfRange, "must be >= 1")
		case l > maxPaginationLimit:
			return 0, 0, queryError("limit", apperrors.CodeOutOfRange, fmt.Sprintf("must be <= %d", maxPaginationLimit))
		default:
			limit = l
		}
	}
	if raw := query.Get("offset"); raw != "" {
		o, atoiErr := strconv.Atoi(raw)
		switch {
		case atoiErr != nil:
			return 0, 0, queryError("offset", apperrors.CodeInvalidFormat, fmt.Sprintf("expected integer, got %q", raw))
		case o < 0:
			return 0, 0, queryError("offset", apperrors.CodeOutOfRange, "must be >= 0")
		default:
			offset = o
		}
	}
	return limit, offset, nil
}

func parseSorting(sortParam string) ([]repository.SortField, *apperrors.FieldError) {
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
				return nil, queryError("sort", apperrors.CodeInvalidChoice,
					fmt.Sprintf("invalid direction %q for field %q; use asc or desc", after, field))
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

func parseFields(fieldsParam string) []string {
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
// query.Get can discard extra values. parseFilters checks duplicate filter keys.
func rejectDuplicateSingleValueParams(query url.Values) *apperrors.FieldError {
	for key, values := range query {
		if strings.HasPrefix(key, "filter[") {
			continue
		}
		if len(values) > 1 {
			return queryError(key, apperrors.CodeDuplicate, "received multiple values; only one is allowed")
		}
	}
	return nil
}

func parseFilters(queryValues url.Values) ([]repository.FilterCondition, *apperrors.FieldError) {
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
			return nil, queryError(key, apperrors.CodeDuplicate, "received multiple values; only one is allowed per filter key")
		}

		field, operator := parseFilterKey(key)
		if field == "" {
			return nil, queryError(key, apperrors.CodeInvalidFormat, "expected filter[field] or filter[field][operator]")
		}

		op, ok := filterOperators[operator]
		if !ok {
			return nil, queryError(key, apperrors.CodeInvalidChoice, fmt.Sprintf("unknown operator %q", operator))
		}

		raw := []string{values[0]}
		if op == repository.FilterIn || op == repository.FilterBetween {
			raw = strings.Split(values[0], ",")
			for i, v := range raw {
				raw[i] = strings.TrimSpace(v)
			}
		}
		filters = append(filters, repository.FilterCondition{Key: key, Field: field, Operator: op, Values: raw})
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

// filterStructFields projects a struct or slice of structs to requested JSON
// field names.
func filterStructFields(data any, fields []string) any {
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

// ParseListQuery parses list options for resources without soft deletion and
// rejects any non-empty trashed. On errors it writes an RFC 9457 response and
// returns false. The embedded ListQuery is ready for the repository.
func ParseListQuery(c *gin.Context) (*QueryParams, bool) {
	params, err := parseQueryParams(c)
	if err == nil && params.Trashed != "" {
		err = queryError("trashed", apperrors.CodeUnsupported, unsupportedOnEndpoint)
	}
	if err != nil {
		emitQueryError(c, err)
		return nil, false
	}
	return params, true
}

// ParseListQueryWithTrashed is like [ParseListQuery] but accepts trashed=only
// or trashed=with, for resources with soft deletion. An empty or omitted
// trashed lists active records only.
func ParseListQueryWithTrashed(c *gin.Context) (*QueryParams, bool) {
	params, err := parseQueryParams(c)
	if err == nil && params.Trashed != "" && params.Trashed != repository.TrashedOnly && params.Trashed != repository.TrashedWith {
		err = queryError("trashed", apperrors.CodeInvalidChoice, "expected only or with")
	}
	if err != nil {
		emitQueryError(c, err)
		return nil, false
	}
	return params, true
}

const unsupportedOnEndpoint = "not supported on this endpoint"

// ParsePaginationOnly parses limit and offset, rejecting search, sort, filter,
// fields, and trashed options with a 422 response.
func ParsePaginationOnly(c *gin.Context) (limit, offset int, ok bool) {
	params, err := parseQueryParams(c)
	if err != nil {
		emitQueryError(c, err)
		return 0, 0, false
	}
	var unsupported []string
	if params.Search != "" {
		unsupported = append(unsupported, "search")
	}
	if len(params.Sort) > 0 {
		unsupported = append(unsupported, "sort")
	}
	for _, filter := range params.Filters {
		unsupported = append(unsupported, filter.Key)
	}
	if len(params.Fields) > 0 {
		unsupported = append(unsupported, "fields")
	}
	if params.Trashed != "" {
		unsupported = append(unsupported, "trashed")
	}
	if len(unsupported) > 0 {
		errs := make([]apperrors.FieldError, len(unsupported))
		for i, key := range unsupported {
			errs[i] = *queryError(key, apperrors.CodeUnsupported, unsupportedOnEndpoint)
		}
		ProblemQueryValidation(c, "Endpoint only supports limit and offset", errs)
		return 0, 0, false
	}
	return params.Limit, params.Offset, true
}

func emitQueryError(c *gin.Context, err *apperrors.FieldError) {
	ProblemQueryValidation(c, "Invalid query parameter", []apperrors.FieldError{*err})
}

func queryError(key, code, message string) *apperrors.FieldError {
	return &apperrors.FieldError{Field: key, Code: code, Message: message}
}

// RouteKey returns a stable method-and-route key without request parameters.
func RouteKey(c *gin.Context) string {
	if route := c.FullPath(); route != "" {
		return c.Request.Method + " " + route
	}
	return c.Request.Method + " unmatched"
}

// ProblemQueryValidation writes a 422 for invalid list query parameters and
// logs the field errors at Debug. These are expected client errors: the
// response names each field and the access log records the status, so they
// never log at Error or alert.
func ProblemQueryValidation(c *gin.Context, detail string, errs []apperrors.FieldError) {
	logger.Debug("Invalid query parameters",
		"error_type", "query_validation",
		"route", RouteKey(c),
		"errors", errs)
	ProblemValidationError(c, detail, errs)
}

// PaginatedListResponse writes a page with optional sparse fieldsets.
// For struct types, unknown field names produce a 422 response.
func PaginatedListResponse[T any](c *gin.Context, params *QueryParams, result *repository.ListResult[T]) {
	var data any = result.Data
	if len(params.Fields) > 0 {
		if valid := jsonFieldNames[T](); valid != nil {
			var unknown []apperrors.FieldError
			for _, f := range params.Fields {
				if _, ok := valid[f]; !ok {
					unknown = append(unknown, *queryError("fields", apperrors.CodeUnknownField, fmt.Sprintf("unknown field %q", f)))
				}
			}
			if len(unknown) > 0 {
				ProblemQueryValidation(c, "Invalid query parameter", unknown)
				return
			}
		}
		data = filterStructFields(result.Data, params.Fields)
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
