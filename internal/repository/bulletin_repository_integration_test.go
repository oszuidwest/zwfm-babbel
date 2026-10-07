//go:build integration

package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

func TestBulletinRepositoryIntegration_GetLatestLocalDay(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)
	repo := NewBulletinRepository(db)
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	bulletin := models.Bulletin{
		StationID: station.ID,
		Filename:  "latest-day.wav",
		CreatedAt: today.Add(-time.Second),
	}
	if err := db.Create(&bulletin).Error; err != nil {
		t.Fatalf("create bulletin: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&bulletin).Error; err != nil {
			t.Errorf("delete bulletin: %v", err)
		}
	})

	maxAge := 48 * time.Hour
	if got, err := repo.GetLatest(t.Context(), station.ID, &maxAge); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetLatest() yesterday = %#v, %v; want ErrNotFound", got, err)
	}
	if got, err := repo.GetLatest(t.Context(), station.ID, nil); err != nil || got.ID != bulletin.ID {
		t.Fatalf("GetLatest() without maxAge = %#v, %v; want bulletin %d", got, err, bulletin.ID)
	}

	for _, test := range []struct {
		name      string
		createdAt time.Time
		maxAge    time.Duration
		wantFound bool
	}{
		{name: "local midnight included", createdAt: today, maxAge: maxAge, wantFound: true},
		{name: "current day within max age", createdAt: now, maxAge: maxAge, wantFound: true},
		{name: "age still enforced", createdAt: today, maxAge: 0},
		{name: "next day excluded", createdAt: today.AddDate(0, 0, 1), maxAge: maxAge},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := db.Model(&bulletin).Update("created_at", test.createdAt).Error; err != nil {
				t.Fatalf("set bulletin time: %v", err)
			}
			got, err := repo.GetLatest(t.Context(), station.ID, &test.maxAge)
			if test.wantFound {
				if err != nil || got.ID != bulletin.ID {
					t.Fatalf("GetLatest() = %#v, %v; want bulletin %d", got, err, bulletin.ID)
				}
			} else if !errors.Is(err, ErrNotFound) {
				t.Fatalf("GetLatest() = %#v, %v; want ErrNotFound", got, err)
			}
		})
	}
}

func TestStoryRepositoryIntegration_RotationResetsAtLocalMidnight(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)
	voice := models.Voice{Name: station.Name}
	if err := db.Create(&voice).Error; err != nil {
		t.Fatalf("create voice: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&voice).Error; err != nil {
			t.Errorf("delete voice: %v", err)
		}
	})
	stationVoice := models.StationVoice{StationID: station.ID, VoiceID: voice.ID}
	if err := db.Create(&stationVoice).Error; err != nil {
		t.Fatalf("create station voice: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&stationVoice).Error; err != nil {
			t.Errorf("delete station voice: %v", err)
		}
	})

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	story := models.Story{
		Title: "Daily rotation", Text: "News", VoiceID: &voice.ID, AudioFile: "story.wav",
		Status: models.StoryStatusActive, StartDate: today, EndDate: today, Weekdays: 127,
	}
	if err := db.Create(&story).Error; err != nil {
		t.Fatalf("create story: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Unscoped().Delete(&story).Error; err != nil {
			t.Errorf("delete story: %v", err)
		}
	})
	olderStory := models.Story{
		Title: "Older story", Text: "News", VoiceID: &voice.ID, AudioFile: "older.wav",
		Status: models.StoryStatusActive, StartDate: today.AddDate(0, 0, -1), EndDate: today, Weekdays: 127,
	}
	if err := db.Create(&olderStory).Error; err != nil {
		t.Fatalf("create older story: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Unscoped().Delete(&olderStory).Error; err != nil {
			t.Errorf("delete older story: %v", err)
		}
	})
	bulletin := models.Bulletin{StationID: station.ID, Filename: "rotation.wav", CreatedAt: today.Add(-time.Second)}
	if err := db.Create(&bulletin).Error; err != nil {
		t.Fatalf("create bulletin: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&bulletin).Error; err != nil {
			t.Errorf("delete bulletin: %v", err)
		}
	})
	link := models.BulletinStory{BulletinID: bulletin.ID, StoryID: story.ID}
	if err := db.Create(&link).Error; err != nil {
		t.Fatalf("link story: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&link).Error; err != nil {
			t.Errorf("delete story link: %v", err)
		}
	})

	repo := NewStoryRepository(db)
	stories, err := repo.GetStoriesForBulletin(t.Context(), station.ID, now, 1)
	if err != nil || len(stories) != 1 || stories[0].ID != story.ID {
		t.Fatalf("stories after yesterday's usage = %+v, %v; want today's story unused", stories, err)
	}
	if err := db.Model(&bulletin).Update("created_at", today).Error; err != nil {
		t.Fatalf("set bulletin time: %v", err)
	}
	stories, err = repo.GetStoriesForBulletin(t.Context(), station.ID, now, 1)
	if err != nil || len(stories) != 1 || stories[0].ID != olderStory.ID {
		t.Fatalf("stories after today's usage = %+v, %v; want unused older story", stories, err)
	}
}
