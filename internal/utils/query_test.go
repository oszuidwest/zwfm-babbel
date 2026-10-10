package utils

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// The parser maps operator names and splits lists; values reach the
// repository unchanged so it can validate them against the field type.
// Filters come back sorted by query key.
func TestParseQueryParams_PassesRawValues(t *testing.T) {
	t.Parallel()
	type cond = repository.FilterCondition
	tests := []struct {
		target string
		want   []cond
	}{
		{"/x?filter[id]=1", []cond{{Field: "id", Operator: repository.FilterEquals, Values: []string{"1"}}}},
		{"/x?filter[status][not]=draft", []cond{{Field: "status", Operator: repository.FilterNotEquals, Values: []string{"draft"}}}},
		{"/x?filter[title][like]=news", []cond{{Field: "title", Operator: repository.FilterLike, Values: []string{"news"}}}},
		{"/x?filter[voice_id][null]=not-bool", []cond{{Field: "voice_id", Operator: repository.FilterIsNull, Values: []string{"not-bool"}}}},
		{"/x?filter[weekdays][band]=300", []cond{{Field: "weekdays", Operator: repository.FilterBitwiseAnd, Values: []string{"300"}}}},
		{"/x?filter[id][between]=1,%2010", []cond{{Field: "id", Operator: repository.FilterBetween, Values: []string{"1", "10"}}}},
		{"/x?filter[id][in]=1,,2", []cond{{Field: "id", Operator: repository.FilterIn, Values: []string{"1", "", "2"}}}},
		{"/x?filter[created_at][gte]=2024-01-01&filter[created_at][lte]=2024-12-31", []cond{
			{Field: "created_at", Operator: repository.FilterGreaterOrEq, Values: []string{"2024-01-01"}},
			{Field: "created_at", Operator: repository.FilterLessOrEq, Values: []string{"2024-12-31"}},
		}},
		{"/x?filter[status][in]=active,draft&filter[status][ne]=archived", []cond{
			{Field: "status", Operator: repository.FilterIn, Values: []string{"active", "draft"}},
			{Field: "status", Operator: repository.FilterNotEquals, Values: []string{"archived"}},
		}},
		{"/x?filter[id]=1&filter[id][eq]=2", []cond{
			{Field: "id", Operator: repository.FilterEquals, Values: []string{"1"}},
			{Field: "id", Operator: repository.FilterEquals, Values: []string{"2"}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			t.Parallel()
			params, err := ParseQueryParams(testQueryContext(t, tt.target))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(params.Filters, tt.want) {
				t.Fatalf("Filters = %#v, want %#v", params.Filters, tt.want)
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

// Projection dereferences the input or each slice element at most once;
// anything else projects to an empty map.
func TestFilterStructFields_ProjectionShapes(t *testing.T) {
	t.Parallel()

	type row struct {
		ID     int    `json:"id"`
		Name   string `json:"name,omitempty"`
		Secret string `json:"-"`
		Plain  int
		Extra  int `json:"extra"`
	}
	r := row{ID: 1, Secret: "s", Plain: 2, Extra: 3}
	rp := &r
	var nilRow *row
	fields := []string{"id", "name", "Plain", "Secret", "-", "missing"}
	want := map[string]any{"id": 1, "name": "", "Plain": 2}
	empty := map[string]any{}
	rows := []row{r}

	tests := []struct {
		name string
		data any
		want any
	}{
		{name: "nil", data: nil, want: nil},
		{name: "typed nil pointer", data: nilRow, want: nilRow},
		{name: "struct", data: r, want: want},
		{name: "pointer", data: rp, want: want},
		{name: "double pointer", data: &rp, want: empty},
		{name: "scalar", data: 5, want: empty},
		{name: "slice", data: rows, want: []map[string]any{want}},
		{name: "slice pointer", data: &rows, want: []map[string]any{want}},
		{name: "pointer elements", data: []*row{rp, nil}, want: []map[string]any{want, empty}},
		{
			name: "interface elements",
			data: []any{r, rp, &rp, nil, nilRow, 5},
			want: []map[string]any{want, want, empty, empty, empty, empty},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := FilterStructFields(tt.data, fields); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("FilterStructFields() = %#v, want %#v", got, tt.want)
			}
		})
	}

	if got := FilterStructFields(rows, nil); !reflect.DeepEqual(got, rows) {
		t.Fatalf("no fields: got %#v, want input unchanged", got)
	}
}
