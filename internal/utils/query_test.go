package utils

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func TestFilterOperatorHandlers(t *testing.T) {
	t.Parallel()

	nullCases := []struct {
		name     string
		value    string
		operator repository.FilterOperator
	}{
		{name: "null/true -> is null", value: "true", operator: repository.FilterIsNull},
		{name: "null/false -> is not null", value: "false", operator: repository.FilterIsNotNull},
		{name: "null/1 -> is null", value: "1", operator: repository.FilterIsNull},
		{name: "null/0 -> is not null", value: "0", operator: repository.FilterIsNotNull},
	}
	for _, tt := range nullCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := filterOperatorHandlers["null"](tt.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Operator != tt.operator {
				t.Fatalf("Operator = %q, want %q", got.Operator, tt.operator)
			}
		})
	}

	t.Run("null rejects non-boolean", func(t *testing.T) {
		t.Parallel()
		if _, err := filterOperatorHandlers["null"]("not-bool"); err == nil {
			t.Fatal("expected error")
		}
	})

	// LIKE handler stores the raw substring; the repository layer is the only
	// place that wraps with % wildcards. See list_query_test for that contract.
	t.Run("like leaves value unwrapped", func(t *testing.T) {
		t.Parallel()
		got, err := filterOperatorHandlers["like"]("news")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Operator != repository.FilterLike || got.Value != "news" {
			t.Fatalf("got %+v, want like/news", got)
		}
	})
}

func TestQueryParamsToListQuery_NullFilters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		operator repository.FilterOperator
	}{
		{
			name:     "is null",
			operator: repository.FilterIsNull,
		},
		{
			name:     "is not null",
			operator: repository.FilterIsNotNull,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			query, err := QueryParamsToListQuery(&QueryParams{
				Filters: []ParsedFilter{
					{Field: "audio_url", Operator: tt.operator},
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(query.Filters) != 1 {
				t.Fatalf("len(Filters) = %d, want 1", len(query.Filters))
			}
			if query.Filters[0].Operator != tt.operator {
				t.Fatalf("Operator = %q, want %q", query.Filters[0].Operator, tt.operator)
			}
		})
	}
}

func TestParseQueryParams_InvalidFilterReturnsError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
	}{
		{
			name:   "unknown operator",
			target: "/stories?filter[deleted_at][unknown]=value",
		},
		{
			name:   "invalid null value",
			target: "/stories?filter[deleted_at][null]=not-bool",
		},
		{
			name:   "invalid between value",
			target: "/stories?filter[id][between]=1",
		},
		{
			name:   "invalid sort direction",
			target: "/stories?sort=id:sideways",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseQueryParams(testQueryContext(t, tt.target)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseQueryParams_BetweenAndNotFilters(t *testing.T) {
	t.Parallel()
	params, err := ParseQueryParams(testQueryContext(t, "/stories?filter[id][between]=1,10&filter[status][not]=draft"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	between := findParsedFilter(t, params.Filters, "id", repository.FilterBetween)
	if between.Operator != repository.FilterBetween {
		t.Fatalf("between Operator = %q, want %q", between.Operator, repository.FilterBetween)
	}
	if len(between.Values) != 2 || between.Values[0] != "1" || between.Values[1] != "10" {
		t.Fatalf("between Values = %#v, want [1 10]", between.Values)
	}

	not := findParsedFilter(t, params.Filters, "status", repository.FilterNotEquals)
	if not.Operator != repository.FilterNotEquals || not.Value != "draft" {
		t.Fatalf("not filter = %#v, want %s draft", not, repository.FilterNotEquals)
	}
}

func TestQueryParamsToListQuery_BetweenAndUnknownOperators(t *testing.T) {
	t.Parallel()
	query, err := QueryParamsToListQuery(&QueryParams{
		Filters: []ParsedFilter{
			{
				Field:    "id",
				Operator: repository.FilterBetween,
				Values:   []string{"1", "10"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(query.Filters) != 1 {
		t.Fatalf("len(Filters) = %d, want 1", len(query.Filters))
	}
	if query.Filters[0].Operator != repository.FilterBetween {
		t.Fatalf("Operator = %q, want %q", query.Filters[0].Operator, repository.FilterBetween)
	}

	if _, err := QueryParamsToListQuery(&QueryParams{
		Filters: []ParsedFilter{
			{Field: "id", Operator: "UNKNOWN"},
		},
	}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseQueryParams_SameFieldMultiOperatorFilters(t *testing.T) {
	t.Parallel()
	type wantFilter struct {
		field    string
		operator repository.FilterOperator
		value    any
		values   []string
	}

	tests := []struct {
		name   string
		target string
		want   []wantFilter
	}{
		{
			name:   "gte and lte date bounds",
			target: "/stories?filter[created_at][gte]=2024-01-01&filter[created_at][lte]=2024-12-31",
			want: []wantFilter{
				{field: "created_at", operator: repository.FilterGreaterOrEq, value: "2024-01-01"},
				{field: "created_at", operator: repository.FilterLessOrEq, value: "2024-12-31"},
			},
		},
		{
			name:   "gt and lt numeric bounds",
			target: "/stories?filter[id][gt]=1&filter[id][lt]=10",
			want: []wantFilter{
				{field: "id", operator: repository.FilterGreaterThan, value: "1"},
				{field: "id", operator: repository.FilterLessThan, value: "10"},
			},
		},
		{
			name:   "in and ne on same field",
			target: "/stories?filter[status][in]=active,draft&filter[status][ne]=archived",
			want: []wantFilter{
				{field: "status", operator: repository.FilterIn, values: []string{"active", "draft"}},
				{field: "status", operator: repository.FilterNotEquals, value: "archived"},
			},
		},
		{
			name:   "simple equality and explicit equality on same field",
			target: "/stories?filter[id]=1&filter[id][eq]=2",
			want: []wantFilter{
				{field: "id", operator: repository.FilterEquals, value: "1"},
				{field: "id", operator: repository.FilterEquals, value: "2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			params, err := ParseQueryParams(testQueryContext(t, tt.target))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(params.Filters) != len(tt.want) {
				t.Fatalf("len(Filters) = %d, want %d", len(params.Filters), len(tt.want))
			}

			query, err := QueryParamsToListQuery(params)
			if err != nil {
				t.Fatalf("unexpected conversion error: %v", err)
			}
			if len(query.Filters) != len(tt.want) {
				t.Fatalf("len(ListQuery.Filters) = %d, want %d", len(query.Filters), len(tt.want))
			}

			for _, want := range tt.want {
				if !hasParsedFilter(params.Filters, want.field, want.operator, want.value, want.values) {
					t.Fatalf("missing parsed filter %s/%s value=%v values=%#v in %#v", want.field, want.operator, want.value, want.values, params.Filters)
				}
				if !hasFilterCondition(query.Filters, want.field, want.operator, want.value, want.values) {
					t.Fatalf("missing list filter %s/%s value=%v values=%#v in %#v", want.field, want.operator, want.value, want.values, query.Filters)
				}
			}
		})
	}
}

func TestPagination(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		target     string
		wantLimit  int
		wantOffset int
		wantErr    bool
		wantField  string
	}{
		{name: "defaults when absent", target: "/x", wantLimit: 20, wantOffset: 0},
		{name: "valid limit and offset", target: "/x?limit=5&offset=10", wantLimit: 5, wantOffset: 10},
		{name: "limit at upper bound", target: "/x?limit=100", wantLimit: 100, wantOffset: 0},
		{name: "non-integer limit rejected", target: "/x?limit=abc", wantErr: true, wantField: "limit"},
		{name: "negative limit rejected", target: "/x?limit=-5", wantErr: true, wantField: "limit"},
		{name: "zero limit rejected", target: "/x?limit=0", wantErr: true, wantField: "limit"},
		{name: "limit over cap rejected", target: "/x?limit=101", wantErr: true, wantField: "limit"},
		{name: "non-integer offset rejected", target: "/x?offset=foo", wantErr: true, wantField: "offset"},
		{name: "negative offset rejected", target: "/x?offset=-1", wantErr: true, wantField: "offset"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			limit, offset, err := Pagination(testQueryContext(t, tt.target))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got limit=%d offset=%d", limit, offset)
				}
				var qpe *QueryParamError
				if !errors.As(err, &qpe) {
					t.Fatalf("expected *QueryParamError, got %T", err)
				}
				if qpe.Field != tt.wantField {
					t.Fatalf("Field = %q, want %q", qpe.Field, tt.wantField)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if limit != tt.wantLimit || offset != tt.wantOffset {
				t.Fatalf("limit, offset = %d, %d, want %d, %d", limit, offset, tt.wantLimit, tt.wantOffset)
			}
		})
	}
}

func TestParseQueryParams_RejectsDuplicateSingleValueParams(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		target    string
		wantField string
	}{
		{name: "duplicate limit", target: "/x?limit=1&limit=2", wantField: "limit"},
		{name: "duplicate offset", target: "/x?offset=0&offset=10", wantField: "offset"},
		{name: "duplicate sort", target: "/x?sort=name&sort=-id", wantField: "sort"},
		{name: "duplicate fields", target: "/x?fields=id&fields=name", wantField: "fields"},
		{name: "duplicate search", target: "/x?search=a&search=b", wantField: "search"},
		{name: "duplicate trashed", target: "/x?trashed=only&trashed=with", wantField: "trashed"},
		{name: "duplicate ad-hoc key", target: "/x?latest=true&latest=false", wantField: "latest"},
		{name: "identical duplicates also rejected", target: "/x?limit=1&limit=1", wantField: "limit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseQueryParams(testQueryContext(t, tt.target))
			if err == nil {
				t.Fatal("expected error")
			}
			var qpe *QueryParamError
			if !errors.As(err, &qpe) {
				t.Fatalf("expected *QueryParamError, got %T (%v)", err, err)
			}
			if qpe.Field != tt.wantField {
				t.Fatalf("Field = %q, want %q", qpe.Field, tt.wantField)
			}
			if !strings.Contains(qpe.Message, "multiple values") {
				t.Fatalf("Message = %q, want substring 'multiple values'", qpe.Message)
			}
		})
	}
}

func TestParseQueryParams_AcceptsSingleValueParams(t *testing.T) {
	t.Parallel()
	// Regression: the duplicate-key guard must not reject the single-value happy path.
	params, err := ParseQueryParams(testQueryContext(t, "/x?limit=5&offset=10&sort=name&fields=id&search=x&trashed=with"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if params.Limit != 5 || params.Offset != 10 {
		t.Fatalf("pagination = %d/%d, want 5/10", params.Limit, params.Offset)
	}
	if params.Search != "x" || params.Trashed != "with" {
		t.Fatalf("search/trashed = %q/%q, want x/with", params.Search, params.Trashed)
	}
}

func TestParseFilters_RejectsDuplicateValues(t *testing.T) {
	t.Parallel()
	c := testQueryContext(t, "/x?filter[name]=a&filter[name]=b")
	_, err := ParseQueryParams(c)
	if err == nil {
		t.Fatal("expected error for duplicate filter values")
	}
	var qpe *QueryParamError
	if !errors.As(err, &qpe) {
		t.Fatalf("expected *QueryParamError, got %T", err)
	}
	if !strings.Contains(qpe.Message, "multiple values") {
		t.Fatalf("Message = %q, want substring 'multiple values'", qpe.Message)
	}
}

func TestParseFilters_Rejections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
	}{
		{name: "between/trailing empty", target: "/x?filter[id][between]=1,"},
		{name: "between/leading empty", target: "/x?filter[id][between]=,10"},
		{name: "between/both empty", target: "/x?filter[id][between]=,"},
		{name: "band/not a number", target: "/x?filter[weekdays][band]=notnum"},
		{name: "band/above uint8 range", target: "/x?filter[weekdays][band]=300"},
		{name: "band/negative", target: "/x?filter[weekdays][band]=-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseQueryParams(testQueryContext(t, tt.target)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseFilters_BandAcceptsValidValue(t *testing.T) {
	t.Parallel()
	params, err := ParseQueryParams(testQueryContext(t, "/x?filter[weekdays][band]=42"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := findParsedFilter(t, params.Filters, "weekdays", repository.FilterBitwiseAnd)
	if got.Operator != repository.FilterBitwiseAnd {
		t.Fatalf("Operator = %q, want %q", got.Operator, repository.FilterBitwiseAnd)
	}
	if got.Value != uint8(42) {
		t.Fatalf("Value = %v (%T), want uint8(42)", got.Value, got.Value)
	}
}

type sparseTestRow struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Hidden string `json:"-"`
}

func TestPaginatedListResponse_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x?fields=id,bogus", nil)

	result := &repository.ListResult[sparseTestRow]{
		Data:   []sparseTestRow{{ID: 1, Name: "alpha"}},
		Total:  1,
		Limit:  20,
		Offset: 0,
	}
	PaginatedListResponse(c, &QueryParams{Fields: []string{"id", "bogus"}}, result)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "bogus") {
		t.Fatalf("response should name the unknown field; got %s", w.Body.String())
	}
}

func TestPaginatedListResponse_AppliesKnownFields(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x?fields=id", nil)

	result := &repository.ListResult[sparseTestRow]{
		Data:   []sparseTestRow{{ID: 1, Name: "alpha"}},
		Total:  1,
		Limit:  20,
		Offset: 0,
	}
	PaginatedListResponse(c, &QueryParams{Fields: []string{"id"}}, result)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, w.Body.String())
	}
	if len(body.Data) != 1 {
		t.Fatalf("len(data) = %d, want 1", len(body.Data))
	}
	if _, hasName := body.Data[0]["name"]; hasName {
		t.Fatalf("name should be filtered out; got %v", body.Data[0])
	}
	if _, hasID := body.Data[0]["id"]; !hasID {
		t.Fatalf("id should be present; got %v", body.Data[0])
	}
}

func TestJSONFieldNames_SkipsExcludedTags(t *testing.T) {
	t.Parallel()
	names := jsonFieldNames[sparseTestRow]()
	if _, ok := names["id"]; !ok {
		t.Fatal("expected id in name set")
	}
	if _, ok := names["name"]; !ok {
		t.Fatal("expected name in name set")
	}
	if _, ok := names["Hidden"]; ok {
		t.Fatal("json:\"-\" field should not be exposed")
	}
}

func testQueryContext(t *testing.T, target string) *gin.Context {
	t.Helper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	return c
}

func findParsedFilter(t *testing.T, filters []ParsedFilter, field string, operator repository.FilterOperator) ParsedFilter {
	t.Helper()
	for _, filter := range filters {
		if filter.Field == field && filter.Operator == operator {
			return filter
		}
	}
	t.Fatalf("missing parsed filter %s/%s in %#v", field, operator, filters)
	return ParsedFilter{}
}

func hasParsedFilter(filters []ParsedFilter, field string, operator repository.FilterOperator, value any, values []string) bool {
	for _, filter := range filters {
		if filter.Field != field || filter.Operator != operator {
			continue
		}
		if len(values) > 0 {
			if slices.Equal(filter.Values, values) {
				return true
			}
			continue
		}
		if filter.Value == value {
			return true
		}
	}
	return false
}

func hasFilterCondition(filters []repository.FilterCondition, field string, operator repository.FilterOperator, value any, values []string) bool {
	for _, filter := range filters {
		if filter.Field != field || filter.Operator != operator {
			continue
		}
		if len(values) > 0 {
			got, ok := filter.Value.([]string)
			if ok && slices.Equal(got, values) {
				return true
			}
			continue
		}
		if filter.Value == value {
			return true
		}
	}
	return false
}
