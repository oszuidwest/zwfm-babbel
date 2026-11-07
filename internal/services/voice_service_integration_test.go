//go:build integration

package services

import (
	"errors"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/gorm"
)

// A dependent row committed after the service's dependency check must make the
// delete fail, instead of losing its reference or disappearing with the parent.
func TestDeleteRefusesDependentAddedAfterCheck(t *testing.T) {
	addStationVoice := func(db *gorm.DB, stationID, voiceID int64) error {
		return db.Create(&models.StationVoice{StationID: stationID, VoiceID: voiceID, MixPoint: 1}).Error
	}
	tests := []struct {
		name  string
		table string
		// arrange returns the write that races with the delete, and the delete.
		arrange func(t *testing.T, db *gorm.DB) (write, remove func() error)
	}{
		{
			name:  "story assigned to voice",
			table: "voices",
			arrange: func(t *testing.T, db *gorm.DB) (write, remove func() error) {
				voice, other := createNamedVoice(t, db, t.Name()), createNamedVoice(t, db, t.Name()+"/other")
				story := createAudioIntegrationStory(t, db, &other.ID)
				return func() error {
						return db.Model(&models.Story{}).Where("id = ?", story.ID).Update("voice_id", voice.ID).Error
					}, func() error {
						return NewVoiceService(repository.NewVoiceRepository(db)).Delete(t.Context(), voice.ID)
					}
			},
		},
		{
			name:  "voice added to station",
			table: "voices",
			arrange: func(t *testing.T, db *gorm.DB) (write, remove func() error) {
				station, voice := createTestStation(t, db), createNamedVoice(t, db, t.Name())
				return func() error { return addStationVoice(db, station.ID, voice.ID) }, func() error {
					return NewVoiceService(repository.NewVoiceRepository(db)).Delete(t.Context(), voice.ID)
				}
			},
		},
		{
			name:  "station given a voice",
			table: "stations",
			arrange: func(t *testing.T, db *gorm.DB) (write, remove func() error) {
				station, voice := createTestStation(t, db), createNamedVoice(t, db, t.Name())
				return func() error { return addStationVoice(db, station.ID, voice.ID) }, func() error {
					return NewStationService(repository.NewStationRepository(db)).Delete(t.Context(), station.ID)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := testutil.OpenIntegrationDB(t)
			write, remove := tt.arrange(t, db)
			done := false
			if err := db.Callback().Delete().Before("gorm:delete").Register("test:after_check", func(tx *gorm.DB) {
				if tx.Statement.Table != tt.table || done {
					return
				}
				done = true
				if err := write(); err != nil {
					t.Errorf("write during delete: %v", err)
				}
			}); err != nil {
				t.Fatal(err)
			}

			err := remove()
			if !done {
				t.Fatal("write did not run during the delete")
			}
			if _, ok := errors.AsType[*apperrors.DependencyError](err); !ok {
				t.Fatalf("Delete() = %v, want a dependency error", err)
			}
		})
	}
}
