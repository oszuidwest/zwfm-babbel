package utils

import (
	"testing"

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
			got := filterOperatorHandlers["null"](tt.value)
			if got.Operator != tt.operator {
				t.Fatalf("Operator = %q, want %q", got.Operator, tt.operator)
			}
		})
	}
}

func TestFilterOperatorHandlers_NullRejectsInvalidValues(t *testing.T) {
	got := filterOperatorHandlers["null"]("not-bool")
	if got.Operator != "" {
		t.Fatalf("Operator = %q, want empty operator", got.Operator)
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
			query := QueryParamsToListQuery(&QueryParams{
				Filters: map[string]FilterOperation{
					"audio_url": {
						Operator: tt.operator,
					},
				},
			})

			if len(query.Filters) != 1 {
				t.Fatalf("len(Filters) = %d, want 1", len(query.Filters))
			}
			if query.Filters[0].Operator != tt.want {
				t.Fatalf("Operator = %q, want %q", query.Filters[0].Operator, tt.want)
			}
		})
	}
}
