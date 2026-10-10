package repository

import (
	"errors"
	"testing"
)

func TestUserRepository_List_ReturnsQueryErrorsUnwrapped(t *testing.T) {
	t.Parallel()
	repo := NewUserRepository(dryRunDB(t))

	// These field names mimic MySQL error text, which ParseDBError matches by substring.
	for _, query := range []*ListQuery{
		{Filters: []FilterCondition{{Field: "no such table: x", Operator: FilterEquals, Values: []string{"1"}}}},
		{Sort: []SortField{{Field: "Duplicate entry", Direction: SortAsc}}},
	} {
		_, err := repo.List(t.Context(), query)
		var unknown *UnknownFieldError
		if !errors.As(err, &unknown) {
			t.Errorf("%+v: got %v, want UnknownFieldError", query, err)
		}
	}
}
