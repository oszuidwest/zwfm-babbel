package services

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// deleteRepository holds one station-voice row, which only queries inside the
// transaction can lock and delete.
type deleteRepository struct {
	stationVoiceRepository
	row     *models.StationVoice
	deleted bool
}

func (r *deleteRepository) GetForUpdate(ctx context.Context, id int64) (*models.StationVoice, error) {
	if ctx.Value(jingleTxKey{}) == nil {
		return nil, errors.New("GetForUpdate ran outside the transaction")
	}
	if r.row == nil || r.row.ID != id {
		return nil, repository.ErrNotFound
	}
	row := *r.row
	return &row, nil
}

func (r *deleteRepository) Delete(ctx context.Context, id int64) error {
	if ctx.Value(jingleTxKey{}) == nil {
		return errors.New("Delete ran outside the transaction")
	}
	r.deleted = true
	return nil
}

func newDeleteTestService(t *testing.T, row *models.StationVoice) (*StationVoiceService, *deleteRepository, *jingleTxManager) {
	t.Helper()
	repo := &deleteRepository{row: row}
	txManager := &jingleTxManager{}
	return &StationVoiceService{
		txManager:        txManager,
		stationVoiceRepo: repo,
		config:           &config.Config{Audio: config.AudioConfig{ProcessedPath: t.TempDir()}},
	}, repo, txManager
}

// writeJingles creates the jingle files of the given pairs.
func writeJingles(t *testing.T, service *StationVoiceService, pairs ...[2]int64) {
	t.Helper()
	for _, pair := range pairs {
		// #nosec G703 - storage root and numeric IDs are controlled by the test.
		if err := os.WriteFile(utils.JinglePath(service.config, pair[0], pair[1]), []byte("jingle"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertJingleExists(t *testing.T, service *StationVoiceService, stationID, voiceID int64, want bool) {
	t.Helper()
	_, err := os.Stat(utils.JinglePath(service.config, stationID, voiceID))
	if want && err != nil {
		t.Fatalf("jingle %d/%d: %v, want kept", stationID, voiceID, err)
	}
	if !want && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("jingle %d/%d: %v, want removed", stationID, voiceID, err)
	}
}

// An upload whose commit failed leaves its jingle published while the row
// records none.
func TestStationVoiceService_DeleteRemovesUnrecordedJingle(t *testing.T) {
	t.Parallel()
	service, repo, _ := newDeleteTestService(t, &models.StationVoice{ID: 3, StationID: 1, VoiceID: 2})
	writeJingles(t, service, [2]int64{1, 2}, [2]int64{4, 2})

	if err := service.Delete(t.Context(), 3); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
	if !repo.deleted {
		t.Fatal("row was not deleted")
	}
	assertJingleExists(t, service, 1, 2, false)
	assertJingleExists(t, service, 4, 2, true)
}

func TestStationVoiceService_DeleteMissingRowIsNotFound(t *testing.T) {
	t.Parallel()
	service, repo, _ := newDeleteTestService(t, nil)

	err := service.Delete(t.Context(), 3)
	if _, ok := errors.AsType[*apperrors.NotFoundError](err); !ok || repo.deleted {
		t.Fatalf("Delete() = %v, deleted = %v; want not found and nothing deleted", err, repo.deleted)
	}
}

func TestStationVoiceService_DeleteCommitFailureIsDatabaseError(t *testing.T) {
	t.Parallel()
	service, _, txManager := newDeleteTestService(t, &models.StationVoice{ID: 3, StationID: 1, VoiceID: 2})
	cause := errors.New("connection refused")
	txManager.err = cause

	err := service.Delete(t.Context(), 3)
	dbErr, ok := errors.AsType[*apperrors.DatabaseError](err)
	if !ok || dbErr.Resource != "StationVoice" || dbErr.Operation != apperrors.OpDelete.String() || !errors.Is(err, cause) {
		t.Fatalf("Delete() = %v, want a StationVoice delete database error caused by %v", err, cause)
	}
}
