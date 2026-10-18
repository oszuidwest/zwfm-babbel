package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
	inUse   bool
	deleted bool
	checked string
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

func (r *deleteRepository) IsJingleInUse(ctx context.Context, filename string, _, _ int64) (bool, error) {
	if ctx.Value(jingleTxKey{}) == nil {
		return false, errors.New("IsJingleInUse ran outside the transaction")
	}
	r.checked = filename
	return r.inUse, nil
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

func TestStationVoiceService_DeleteRemovesStoredJingleOfAnotherPair(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		inUse    bool
		wantKept bool
	}{
		{name: "unused", inUse: false, wantKept: false},
		{name: "in use", inUse: true, wantKept: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stored := utils.JingleFilename(4, 2)
			service, repo, _ := newDeleteTestService(t, &models.StationVoice{ID: 3, StationID: 1, VoiceID: 2, AudioFile: stored})
			repo.inUse = tt.inUse
			writeJingles(t, service, [2]int64{1, 2}, [2]int64{4, 2})

			if err := service.Delete(t.Context(), 3); err != nil {
				t.Fatalf("Delete() = %v", err)
			}
			if !repo.deleted || repo.checked != stored {
				t.Fatalf("deleted = %v, checked %q; want the row deleted and %q checked", repo.deleted, repo.checked, stored)
			}
			assertJingleExists(t, service, 1, 2, false)
			assertJingleExists(t, service, 4, 2, tt.wantKept)
		})
	}
}

func TestStationVoiceService_DeleteKeepsStoredFileThatIsNotAJingle(t *testing.T) {
	t.Parallel()
	for _, stored := range []string{
		"../" + utils.JingleFilename(4, 2),
		"sub/" + utils.JingleFilename(4, 2),
		"station_04_voice_2_jingle.wav",
		"story_4.wav",
	} {
		t.Run(stored, func(t *testing.T) {
			t.Parallel()
			service, repo, _ := newDeleteTestService(t, &models.StationVoice{ID: 3, StationID: 1, VoiceID: 2, AudioFile: stored})
			// Put the jingle of pair 4/2 both inside and beside the jingle
			// directory, and the stored name itself under the jingle directory.
			outside := filepath.Join(filepath.Dir(service.config.Audio.ProcessedPath), utils.JingleFilename(4, 2))
			paths := []string{outside, utils.JinglePath(service.config, 4, 2)}
			if filepath.Dir(stored) == "." {
				paths = append(paths, filepath.Join(service.config.Audio.ProcessedPath, stored))
			}
			for _, path := range paths {
				// #nosec G703 - paths inside the test's temp directories.
				if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if err := service.Delete(t.Context(), 3); err != nil {
				t.Fatalf("Delete() = %v", err)
			}
			if !repo.deleted || repo.checked != "" {
				t.Fatalf("deleted = %v, checked %q; want the row deleted and nothing checked", repo.deleted, repo.checked)
			}
			for _, path := range paths {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("%s after delete: %v, want kept", path, err)
				}
			}
		})
	}
}

func TestStationVoiceService_DeleteRollsBackWhenStoredJingleRemovalFails(t *testing.T) {
	t.Parallel()
	service, _, txManager := newDeleteTestService(t, &models.StationVoice{ID: 3, StationID: 1, VoiceID: 2, AudioFile: utils.JingleFilename(4, 2)})
	// A non-empty directory makes os.Remove fail with an error other than
	// not-exist.
	path := utils.JinglePath(service.config, 4, 2)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := service.Delete(t.Context(), 3); err == nil {
		t.Fatal("Delete() = nil, want the removal error")
	}
	if !txManager.rolledBack {
		t.Fatal("delete was not rolled back")
	}
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
