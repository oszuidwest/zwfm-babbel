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

// The parser maps operator names and splits lists; values reach the
// repository unchanged so it can validate them against the field type.
func TestParseQueryParams_PassesRawValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		target   string
		field    string
		operator repository.FilterOperator
		values   []string
	}{
		{"/x?filter[id]=1", "id", repository.FilterEquals, []string{"1"}},
		{"/x?filter[status][not]=draft", "status", repository.FilterNotEquals, []string{"draft"}},
		{"/x?filter[title][like]=news", "title", repository.FilterLike, []string{"news"}},
		{"/x?filter[voice_id][null]=not-bool", "voice_id", repository.FilterIsNull, []string{"not-bool"}},
		{"/x?filter[weekdays][band]=300", "weekdays", repository.FilterBitwiseAnd, []string{"300"}},
		{"/x?filter[id][between]=1,%2010", "id", repository.FilterBetween, []string{"1", "10"}},
		{"/x?filter[id][in]=1,,2", "id", repository.FilterIn, []string{"1", "", "2"}},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			t.Parallel()
			params, err := ParseQueryParams(testQueryContext(t, tt.target))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := findFilter(t, params.Filters, tt.field, tt.operator); !slices.Equal(got.Values, tt.values) {
				t.Fatalf("Values = %#v, want %#v", got.Values, tt.values)
			}
		})
	}
}

func TestParseQueryParams_RejectsMalformedOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		target    string
		wantField string
	}{
		{name: "unknown operator", target: "/stories?filter[deleted_at][unknown]=value", wantField: "filter[deleted_at][unknown]"},
		{name: "malformed filter key", target: "/stories?filter[]=1", wantField: "filter[]"},
		{name: "invalid sort direction", target: "/stories?sort=id:sideways", wantField: "sort"},
		{name: "unknown trashed value", target: "/stories?trashed=bogus", wantField: "trashed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseQueryParams(testQueryContext(t, tt.target))
			var qpe *QueryParamError
			if !errors.As(err, &qpe) || qpe.Field != tt.wantField {
				t.Fatalf("got %v, want QueryParamError for %q", err, tt.wantField)
			}
		})
	}
}

func TestParseQueryParams_SameFieldMultiOperatorFilters(t *testing.T) {
	t.Parallel()
	type wantFilter struct {
		field    string
		operator repository.FilterOperator
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
				{field: "created_at", operator: repository.FilterGreaterOrEq, values: []string{"2024-01-01"}},
				{field: "created_at", operator: repository.FilterLessOrEq, values: []string{"2024-12-31"}},
			},
		},
		{
			name:   "gt and lt numeric bounds",
			target: "/stories?filter[id][gt]=1&filter[id][lt]=10",
			want: []wantFilter{
				{field: "id", operator: repository.FilterGreaterThan, values: []string{"1"}},
				{field: "id", operator: repository.FilterLessThan, values: []string{"10"}},
			},
		},
		{
			name:   "in and ne on same field",
			target: "/stories?filter[status][in]=active,draft&filter[status][ne]=archived",
			want: []wantFilter{
				{field: "status", operator: repository.FilterIn, values: []string{"active", "draft"}},
				{field: "status", operator: repository.FilterNotEquals, values: []string{"archived"}},
			},
		},
		{
			name:   "simple equality and explicit equality on same field",
			target: "/stories?filter[id]=1&filter[id][eq]=2",
			want: []wantFilter{
				{field: "id", operator: repository.FilterEquals, values: []string{"1"}},
				{field: "id", operator: repository.FilterEquals, values: []string{"2"}},
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
			for _, want := range tt.want {
				if !slices.ContainsFunc(params.Filters, func(f repository.FilterCondition) bool {
					return f.Field == want.field && f.Operator == want.operator && slices.Equal(f.Values, want.values)
				}) {
					t.Fatalf("missing filter %s/%s values=%#v in %#v", want.field, want.operator, want.values, params.Filters)
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

func findFilter(t *testing.T, filters []repository.FilterCondition, field string, operator repository.FilterOperator) repository.FilterCondition {
	t.Helper()
	for _, filter := range filters {
		if filter.Field == field && filter.Operator == operator {
			return filter
		}
	}
	t.Fatalf("missing filter %s/%s in %#v", field, operator, filters)
	return repository.FilterCondition{}
}
