package repository

import (
	"errors"
	"testing"
)

// These tests exercise the error branches of applyFilterCondition. The error
// branches return before touching the *gorm.DB, so a nil DB is safe input.
// Happy-path SQL generation is verified by the Jest integration suite under
// tests/ against a real MySQL.

func TestApplyFilterCondition_UnknownField(t *testing.T) {
	mapping := FieldMapping{"name": "name"}
	_, err := applyFilterCondition(nil, FilterCondition{
		Field:    "bogus",
		Operator: FilterEquals,
		Value:    "x",
	}, mapping)

	var unknown *UnknownFieldError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected *UnknownFieldError, got %T (%v)", err, err)
	}
	if unknown.Kind != "filter" || unknown.Field != "bogus" {
		t.Fatalf("got %+v, want filter/bogus", unknown)
	}
}

func TestApplyFilterCondition_BitwiseRestrictedField(t *testing.T) {
	mapping := FieldMapping{"name": "name"}
	_, err := applyFilterCondition(nil, FilterCondition{
		Field:    "name",
		Operator: FilterBitwiseAnd,
		Value:    uint8(1),
	}, mapping)

	var invalid *InvalidFilterError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *InvalidFilterError, got %T (%v)", err, err)
	}
	if invalid.Field != "name" || invalid.Operator != FilterBitwiseAnd {
		t.Fatalf("got %+v, want name/band", invalid)
	}
}

func TestApplyFilterCondition_LikeRequiresString(t *testing.T) {
	mapping := FieldMapping{"name": "name"}
	_, err := applyFilterCondition(nil, FilterCondition{
		Field:    "name",
		Operator: FilterLike,
		Value:    42,
	}, mapping)

	var invalid *InvalidFilterError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *InvalidFilterError, got %T (%v)", err, err)
	}
	if invalid.Field != "name" || invalid.Operator != FilterLike {
		t.Fatalf("got %+v, want name/like", invalid)
	}
}

func TestApplyFilterCondition_BetweenRequiresTwoValues(t *testing.T) {
	mapping := FieldMapping{"id": "id"}
	tests := []struct {
		name  string
		value any
	}{
		{name: "nil value", value: nil},
		{name: "wrong type", value: "1,2"},
		{name: "one element slice", value: []string{"1"}},
		{name: "three element slice", value: []string{"1", "2", "3"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := applyFilterCondition(nil, FilterCondition{
				Field:    "id",
				Operator: FilterBetween,
				Value:    tt.value,
			}, mapping)

			var invalid *InvalidFilterError
			if !errors.As(err, &invalid) {
				t.Fatalf("expected *InvalidFilterError, got %T (%v)", err, err)
			}
		})
	}
}

func TestApplyFilterCondition_UnsupportedOperator(t *testing.T) {
	mapping := FieldMapping{"id": "id"}
	_, err := applyFilterCondition(nil, FilterCondition{
		Field:    "id",
		Operator: FilterOperator("unknown_op"),
		Value:    "x",
	}, mapping)

	var invalid *InvalidFilterError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *InvalidFilterError, got %T (%v)", err, err)
	}
}

func TestSortDirectionSQL(t *testing.T) {
	if got := sortDirectionSQL(SortAsc); got != "ASC" {
		t.Fatalf("SortAsc -> %q, want ASC", got)
	}
	if got := sortDirectionSQL(SortDesc); got != "DESC" {
		t.Fatalf("SortDesc -> %q, want DESC", got)
	}
	if got := sortDirectionSQL(SortDirection("garbage")); got != "ASC" {
		t.Fatalf("unknown direction -> %q, want ASC fallback", got)
	}
}
