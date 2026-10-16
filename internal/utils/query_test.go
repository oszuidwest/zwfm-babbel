package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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
		{"/x?filter[id]=1", []cond{{Key: "filter[id]", Field: "id", Operator: repository.FilterEquals, Values: []string{"1"}}}},
		{"/x?filter[status][not]=draft", []cond{{Key: "filter[status][not]", Field: "status", Operator: repository.FilterNotEquals, Values: []string{"draft"}}}},
		{"/x?filter[title][like]=news", []cond{{Key: "filter[title][like]", Field: "title", Operator: repository.FilterLike, Values: []string{"news"}}}},
		{"/x?filter[voice_id][null]=not-bool", []cond{{Key: "filter[voice_id][null]", Field: "voice_id", Operator: repository.FilterIsNull, Values: []string{"not-bool"}}}},
		{"/x?filter[weekdays][band]=300", []cond{{Key: "filter[weekdays][band]", Field: "weekdays", Operator: repository.FilterBitwiseAnd, Values: []string{"300"}}}},
		{"/x?filter[id][between]=1,%2010", []cond{{Key: "filter[id][between]", Field: "id", Operator: repository.FilterBetween, Values: []string{"1", "10"}}}},
		{"/x?filter[id][in]=1,,2", []cond{{Key: "filter[id][in]", Field: "id", Operator: repository.FilterIn, Values: []string{"1", "", "2"}}}},
		{"/x?filter[created_at][gte]=2024-01-01&filter[created_at][lte]=2024-12-31", []cond{
			{Key: "filter[created_at][gte]", Field: "created_at", Operator: repository.FilterGreaterOrEq, Values: []string{"2024-01-01"}},
			{Key: "filter[created_at][lte]", Field: "created_at", Operator: repository.FilterLessOrEq, Values: []string{"2024-12-31"}},
		}},
		{"/x?filter[status][in]=active,draft&filter[status][ne]=archived", []cond{
			{Key: "filter[status][in]", Field: "status", Operator: repository.FilterIn, Values: []string{"active", "draft"}},
			{Key: "filter[status][ne]", Field: "status", Operator: repository.FilterNotEquals, Values: []string{"archived"}},
		}},
		{"/x?filter[id]=1&filter[id][eq]=2", []cond{
			{Key: "filter[id]", Field: "id", Operator: repository.FilterEquals, Values: []string{"1"}},
			{Key: "filter[id][eq]", Field: "id", Operator: repository.FilterEquals, Values: []string{"2"}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			t.Parallel()
			params, err := parseQueryParams(testQueryContext(t, tt.target))
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
		wantCode  string
	}{
		{name: "unknown operator", target: "/stories?filter[deleted_at][unknown]=value", wantField: "filter[deleted_at][unknown]", wantCode: "invalid_choice"},
		{name: "malformed filter key", target: "/stories?filter[]=1", wantField: "filter[]", wantCode: "invalid_format"},
		{name: "invalid sort direction", target: "/stories?sort=id:sideways", wantField: "sort", wantCode: "invalid_choice"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseQueryParams(testQueryContext(t, tt.target))
			if err == nil || err.Field != tt.wantField || err.Code != tt.wantCode {
				t.Fatalf("got %+v, want %s/%s", err, tt.wantField, tt.wantCode)
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
		wantCode   string
	}{
		{name: "defaults when absent", target: "/x", wantLimit: 20, wantOffset: 0},
		{name: "valid limit and offset", target: "/x?limit=5&offset=10", wantLimit: 5, wantOffset: 10},
		{name: "limit at upper bound", target: "/x?limit=100", wantLimit: 100, wantOffset: 0},
		{name: "non-integer limit rejected", target: "/x?limit=abc", wantErr: true, wantField: "limit", wantCode: "invalid_format"},
		{name: "negative limit rejected", target: "/x?limit=-5", wantErr: true, wantField: "limit", wantCode: "out_of_range"},
		{name: "zero limit rejected", target: "/x?limit=0", wantErr: true, wantField: "limit", wantCode: "out_of_range"},
		{name: "limit over cap rejected", target: "/x?limit=101", wantErr: true, wantField: "limit", wantCode: "out_of_range"},
		{name: "non-integer offset rejected", target: "/x?offset=foo", wantErr: true, wantField: "offset", wantCode: "invalid_format"},
		{name: "negative offset rejected", target: "/x?offset=-1", wantErr: true, wantField: "offset", wantCode: "out_of_range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			limit, offset, err := parsePagination(testQueryContext(t, tt.target).Request.URL.Query())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got limit=%d offset=%d", limit, offset)
				}
				if err.Field != tt.wantField || err.Code != tt.wantCode {
					t.Fatalf("error = %s/%s, want %s/%s", err.Field, err.Code, tt.wantField, tt.wantCode)
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
			_, err := parseQueryParams(testQueryContext(t, tt.target))
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Field != tt.wantField || err.Code != "duplicate" || err.Message == "" {
				t.Fatalf("error = %+v, want %s/duplicate with a message", err, tt.wantField)
			}
		})
	}
}

func TestParseQueryParams_AcceptsSingleValueParams(t *testing.T) {
	t.Parallel()
	params, err := parseQueryParams(testQueryContext(t, "/x?limit=5&offset=10&sort=name&fields=id&search=x&trashed=with"))
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

// Only soft-delete resources accept trashed, and only its two values. Any
// other non-empty value fails with one trashed error. An empty trashed counts
// as omitted everywhere.
func TestParseListQuery_TrashedSupport(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		parse       func(*gin.Context) (*QueryParams, bool)
		target      string
		wantTrashed string
		wantCode    string
	}{
		{name: "unsupported only", parse: ParseListQuery, target: "/x?trashed=only", wantCode: "unsupported"},
		{name: "unsupported with", parse: ParseListQuery, target: "/x?trashed=with", wantCode: "unsupported"},
		{name: "unsupported invalid", parse: ParseListQuery, target: "/x?trashed=bogus", wantCode: "unsupported"},
		{name: "unsupported empty", parse: ParseListQuery, target: "/x?trashed="},
		{name: "supported only", parse: ParseListQueryWithTrashed, target: "/x?trashed=only", wantTrashed: "only"},
		{name: "supported with", parse: ParseListQueryWithTrashed, target: "/x?trashed=with", wantTrashed: "with"},
		{name: "supported empty", parse: ParseListQueryWithTrashed, target: "/x?trashed="},
		{name: "supported invalid", parse: ParseListQueryWithTrashed, target: "/x?trashed=bogus", wantCode: "invalid_choice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.target, nil)

			params, ok := tt.parse(c)
			if tt.wantCode == "" {
				if !ok || params.Trashed != tt.wantTrashed || w.Body.Len() != 0 {
					t.Fatalf("ok = %v, params = %+v, body = %s; want trashed %q and no response", ok, params, w.Body.String(), tt.wantTrashed)
				}
				return
			}
			if ok || w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("ok = %v, status = %d, want 422", ok, w.Code)
			}
			var body problemResponse
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal: %v; body: %s", err, w.Body.String())
			}
			if len(body.Errors) != 1 || body.Errors[0].Field != "trashed" || body.Errors[0].Code != tt.wantCode || body.Errors[0].Message == "" {
				t.Fatalf("errors = %+v, want one trashed/%s error with a message", body.Errors, tt.wantCode)
			}
		})
	}
}

func TestParseFilters_RejectsDuplicateValues(t *testing.T) {
	t.Parallel()
	c := testQueryContext(t, "/x?filter[name]=a&filter[name]=b")
	_, err := parseQueryParams(c)
	if err == nil {
		t.Fatal("expected error for duplicate filter values")
	}
	if err.Field != "filter[name]" || err.Code != "duplicate" || err.Message == "" {
		t.Fatalf("error = %+v, want filter[name]/duplicate with a message", err)
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
	var body problemResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, w.Body.String())
	}
	if len(body.Errors) != 1 || body.Errors[0].Field != "fields" || body.Errors[0].Code != "unknown_field" || body.Errors[0].Message == "" {
		t.Fatalf("errors = %+v, want one fields/unknown_field error with a message", body.Errors)
	}
}

func TestParsePaginationOnly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		target     string
		wantLimit  int
		wantOffset int
		wantFields []string
		wantCodes  []string
	}{
		{name: "pagination accepted", target: "/x?limit=5&offset=10", wantLimit: 5, wantOffset: 10},
		{
			name:       "other list options rejected together",
			target:     "/x?search=news&sort=id&filter[id]=1&fields=id&trashed=only",
			wantFields: []string{"search", "sort", "filter[id]", "fields", "trashed"},
			wantCodes:  []string{"unsupported", "unsupported", "unsupported", "unsupported", "unsupported"},
		},
		{name: "malformed filter keeps parser error", target: "/x?filter[]=1", wantFields: []string{"filter[]"}, wantCodes: []string{"invalid_format"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.target, nil)

			limit, offset, ok := ParsePaginationOnly(c)
			if len(tt.wantFields) == 0 {
				if !ok || limit != tt.wantLimit || offset != tt.wantOffset || w.Body.Len() != 0 {
					t.Fatalf("got limit=%d offset=%d ok=%v body=%s", limit, offset, ok, w.Body.String())
				}
				return
			}
			if ok || w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("ok=%v status=%d, want false/422", ok, w.Code)
			}
			var body problemResponse
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal: %v; body: %s", err, w.Body.String())
			}
			if len(body.Errors) != len(tt.wantFields) {
				t.Fatalf("errors = %+v, want fields %v", body.Errors, tt.wantFields)
			}
			for i, field := range tt.wantFields {
				if body.Errors[i].Field != field || body.Errors[i].Code != tt.wantCodes[i] || body.Errors[i].Message == "" {
					t.Fatalf("errors[%d] = %+v, want %s/%s with a message", i, body.Errors[i], field, tt.wantCodes[i])
				}
			}
		})
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
			if got := filterStructFields(tt.data, fields); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("filterStructFields() = %#v, want %#v", got, tt.want)
			}
		})
	}

	if got := filterStructFields(rows, nil); !reflect.DeepEqual(got, rows) {
		t.Fatalf("no fields: got %#v, want input unchanged", got)
	}
}
