//go:build integration

package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

func TestStoryRepositoryIntegration_TypedFilters(t *testing.T) {
	db := openIntegrationDB(t).Begin()
	if db.Error != nil {
		t.Fatal(db.Error)
	}
	t.Cleanup(func() {
		if err := db.Rollback().Error; err != nil {
			t.Errorf("rollback: %v", err)
		}
	})

	story := models.Story{
		Title: "Typed filter regression", Text: "Test story", Status: models.StoryStatusDraft,
		StartDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		EndDate:   time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC),
	}
	if err := db.Create(&story).Error; err != nil {
		t.Fatal(err)
	}
	// GORM's default tag inserts 127 for a zero value; set zero explicitly.
	if err := db.Model(&story).Update("weekdays", 0).Error; err != nil {
		t.Fatal(err)
	}
	repo := NewStoryRepository(db)
	for _, value := range []string{"abc", "false", "0"} {
		t.Run(value, func(t *testing.T) {
			query := NewListQuery()
			query.Filters = []FilterCondition{
				{Field: "title", Operator: FilterEquals, Value: story.Title},
				{Field: "weekdays", Operator: FilterEquals, Value: value},
			}
			result, err := repo.List(t.Context(), query)
			if value != "0" {
				var invalid *InvalidFilterError
				if !errors.As(err, &invalid) || result != nil {
					t.Fatalf("List = %+v, %v; want InvalidFilterError", result, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Total != 1 || len(result.Data) != 1 || result.Data[0].ID != story.ID {
				t.Fatalf("List = %+v, want only story %d", result, story.ID)
			}
		})
	}
}
