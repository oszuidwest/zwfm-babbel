package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func TestFilterOperatorHandlers_Null(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		operator string
	}{
		{
			name:     "true maps to is null",
			value:    "true",
			operator: "IS NULL",
		},
		{
			name:     "false maps to is not null",
			value:    "false",
			operator: "IS NOT NULL",
		},
		{
			name:     "one maps to is null",
			value:    "1",
			operator: "IS NULL",
		},
		{
			name:     "zero maps to is not null",
			value:    "0",
			operator: "IS NOT NULL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterOperatorHandlers["null"](tt.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Operator != tt.operator {
				t.Fatalf("Operator = %q, want %q", got.Operator, tt.operator)
			}
		})
	}
}

func TestFilterOperatorHandlers_NullRejectsInvalidValues(t *testing.T) {
	if _, err := filterOperatorHandlers["null"]("not-bool"); err == nil {
		t.Fatal("expected error")
	}
}

func TestQueryParamsToListQuery_NullFilters(t *testing.T) {
	tests := []struct {
		name     string
		operator string
		want     repository.FilterOperator
	}{
		{
			name:     "is null",
			operator: "IS NULL",
			want:     repository.FilterIsNull,
		},
		{
			name:     "is not null",
			operator: "IS NOT NULL",
			want:     repository.FilterIsNotNull,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := QueryParamsToListQuery(&QueryParams{
				Filters: map[string]FilterOperation{
					"audio_url": {
						Operator: tt.operator,
					},
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(query.Filters) != 1 {
				t.Fatalf("len(Filters) = %d, want 1", len(query.Filters))
			}
			if query.Filters[0].Operator != tt.want {
				t.Fatalf("Operator = %q, want %q", query.Filters[0].Operator, tt.want)
			}
		})
	}
}

func TestParseQueryParams_InvalidFilterReturnsError(t *testing.T) {
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
			if _, err := ParseQueryParams(testQueryContext(t, tt.target)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseQueryParams_BetweenAndNotFilters(t *testing.T) {
	params, err := ParseQueryParams(testQueryContext(t, "/stories?filter[id][between]=1,10&filter[status][not]=draft"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	between := params.Filters["id"]
	if between.Operator != "BETWEEN" {
		t.Fatalf("between Operator = %q, want BETWEEN", between.Operator)
	}
	if len(between.Values) != 2 || between.Values[0] != "1" || between.Values[1] != "10" {
		t.Fatalf("between Values = %#v, want [1 10]", between.Values)
	}

	not := params.Filters["status"]
	if not.Operator != "!=" || not.Value != "draft" {
		t.Fatalf("not filter = %#v, want != draft", not)
	}
}

func TestQueryParamsToListQuery_BetweenAndUnknownOperators(t *testing.T) {
	query, err := QueryParamsToListQuery(&QueryParams{
		Filters: map[string]FilterOperation{
			"id": {
				Operator: "BETWEEN",
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
		Filters: map[string]FilterOperation{
			"id": {Operator: "UNKNOWN"},
		},
	}); err == nil {
		t.Fatal("expected error")
	}
}

func testQueryContext(t *testing.T, target string) *gin.Context {
	t.Helper()

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	return c
}
