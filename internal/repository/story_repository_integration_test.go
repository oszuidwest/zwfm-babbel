//go:build integration

package repository

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

func TestStoryRepositoryIntegration_AudioWriteAfterDeletion(t *testing.T) {
	db := openIntegrationDB(t).Begin()
	if db.Error != nil {
		t.Fatal(db.Error)
	}
	defer db.Rollback()
	repo := NewStoryRepository(db)
	date := time.Date(2026, 9, 26, 0, 0, 0, 0, time.Local)
	story, err := repo.Create(t.Context(), &StoryCreateData{
		Title: "Audio write", Text: "News", Status: "active", StartDate: date, EndDate: date, Weekdays: models.WeekdaysAll,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateAudio(t.Context(), story.ID, "original.wav", 12); err != nil {
		t.Fatal(err)
	}
	if err := repo.SoftDelete(t.Context(), story.ID); err != nil {
		t.Fatal(err)
	}
	err = repo.UpdateAudio(t.Context(), story.ID, "replacement.wav", 20)
	deleted, ok := errors.AsType[*StoryDeletedError](err)
	if !ok || deleted.ID != story.ID || deleted.DeletedAt.IsZero() {
		t.Fatalf("UpdateAudio after deletion = %v, want deletion timestamp", err)
	}
	var saved models.Story
	if err := db.Unscoped().First(&saved, story.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.AudioFile != "original.wav" || saved.DurationSeconds == nil || *saved.DurationSeconds != 12 {
		t.Fatalf("deleted story audio changed: %+v", saved)
	}
	if err := repo.UpdateAudio(t.Context(), math.MaxInt64, "replacement.wav", 20); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateAudio missing = %v, want ErrNotFound", err)
	}
}

func TestStoryRepositoryIntegration_CalendarDatesAndBulletinSelection(t *testing.T) {
	db := openIntegrationDB(t).Begin()
	if db.Error != nil {
		t.Fatal(db.Error)
	}
	defer db.Rollback()
	station := models.Station{Name: fmt.Sprintf("date-station-%d", time.Now().UnixNano())}
	voice := models.Voice{Name: fmt.Sprintf("date-voice-%d", time.Now().UnixNano())}
	if err := db.Create(&station).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&voice).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.StationVoice{StationID: station.ID, VoiceID: voice.ID, MixPoint: 1.5}).Error; err != nil {
		t.Fatal(err)
	}
	repo := NewStoryRepository(db)
	date := time.Date(2026, 9, 26, 0, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	story, err := repo.Create(t.Context(), &StoryCreateData{
		Title: "Calendar day", Text: "News", VoiceID: &voice.ID, Status: "active",
		StartDate: date, EndDate: date, Weekdays: models.WeekdaySaturday,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateAudio(t.Context(), story.ID, "calendar.wav", 10); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		date time.Time
		want int
	}{
		{name: "before range", date: date.AddDate(0, 0, -7), want: 0},
		{name: "inclusive range at midnight", date: date, want: 1},
		{name: "inclusive range late in day", date: date.Add(23 * time.Hour), want: 1},
		{name: "after range", date: date.AddDate(0, 0, 7), want: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stories, err := repo.GetStoriesForBulletin(t.Context(), station.ID, tt.date, 5)
			if err != nil {
				t.Fatal(err)
			}
			if len(stories) != tt.want {
				t.Fatalf("selected %d stories, want %d", len(stories), tt.want)
			}
			if tt.want == 1 {
				assertStoryDateJSON(t, stories[0], "2026-09-26")
				if stories[0].MixPoint != 1.5 || stories[0].ID != story.ID {
					t.Fatalf("unexpected embedded story: %+v", stories[0])
				}
			}
		})
	}
}

func assertStoryDateJSON(t *testing.T, story any, want string) {
	t.Helper()
	data, err := json.Marshal(story)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["start_date"] != want || fields["end_date"] != want {
		t.Fatalf("story dates = %v/%v, want %s", fields["start_date"], fields["end_date"], want)
	}
}
