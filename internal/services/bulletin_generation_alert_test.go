package services

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

// resolveJobOutcome's own test covers the classification; this pins which
// outcomes alert and that the alert is immediate and names the cause.
func TestBulletinGenerationAlertsOnlyRealFailures(t *testing.T) {
	t.Parallel()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, cancelExpired := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancelExpired()
	for _, tt := range []struct {
		name      string
		ctx       context.Context
		err       error
		wantAlert bool
	}{
		{"timeout", t.Context(), apperrors.Audio("Bulletin", "generate", context.DeadlineExceeded), true},
		{"audio failure during shutdown", canceled, apperrors.Audio("Bulletin", "generate", errors.New("read-only file system")), true},
		{"commit failure after the budget expired", expired, apperrors.Database("Bulletin", "create", errors.New("invalid connection")), true},
		{"shutdown", canceled, apperrors.Database("Bulletin", "create", errors.New("connection closed during shutdown")), false},
		{"job state conflict", t.Context(), apperrors.Database("Bulletin", "create", repository.ErrBulletinJobStateConflict), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			alerts := &capturingAlerter{}
			(&BulletinService{alerts: alerts}).reportGeneration(tt.ctx, 7, tt.err)
			if !tt.wantAlert {
				if len(alerts.events) != 0 {
					t.Fatalf("events = %+v; want none", alerts.events)
				}
				return
			}
			if len(alerts.events) != 1 || alerts.events[0].RequiresThreshold || alerts.events[0].Key != "bulletin:generation:station:7" ||
				!strings.Contains(alerts.events[0].Details, errors.Unwrap(tt.err).Error()) {
				t.Fatalf("events = %+v; want one immediate alert naming the cause", alerts.events)
			}
		})
	}
}

func TestBulletinJobSaveFailureLogsCauseAlertsAndRecovers(t *testing.T) {
	alerts := &capturingAlerter{}
	db := insertFailingDB(t, nil)
	if err := db.Callback().Update().After("gorm:update").Register("test:changed", func(tx *gorm.DB) { tx.RowsAffected = 1 }); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("driver connection lost during COMMIT")
	bulletins := NewBulletinService(BulletinServiceDeps{BulletinRepo: repository.NewBulletinRepository(db), TxManager: failingTxManager{err: cause}, Alerts: alerts})
	jobs := NewBulletinJobService(repository.NewBulletinJobRepository(db), bulletins, config.BulletinJobConfig{GenerationTimeout: time.Minute}, alerts)
	path := filepath.Join(t.TempDir(), "kept-bulletin.wav")
	if err := os.WriteFile(path, []byte("RIFF"), 0o600); err != nil {
		t.Fatal(err)
	}
	jobs.generateBulletin = func(ctx context.Context, stationID int64, finalize func(context.Context, int64) error) (int64, error) {
		return bulletins.saveBulletinToDatabase(ctx, saveBulletinParams{StationID: stationID, BulletinPath: path}, finalize)
	}
	logs := testutil.CaptureLogs(t, slog.LevelInfo)
	job := &models.BulletinJob{ID: 42, StationID: 7, Attempt: 1}
	if err := jobs.processJob(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(logs.Bytes(), &record); err != nil || record["level"] != "ERROR" ||
		!strings.Contains(record["cause"].(string), cause.Error()) || !strings.Contains(record["cause"].(string), path) {
		t.Fatalf("logs = %s; want driver cause and kept WAV path", logs)
	}
	if len(alerts.events) != 1 || alerts.events[0].RequiresThreshold || !strings.Contains(alerts.events[0].Details, cause.Error()) ||
		!strings.Contains(alerts.events[0].Details, path) || slices.Contains(alerts.resolved, "bulletin:generation:station:7") {
		t.Fatalf("events = %+v, resolved = %v", alerts.events, alerts.resolved)
	}
	bulletins.txManager = failingTxManager{}
	if err := jobs.processJob(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(alerts.resolved, "bulletin:generation:station:7") {
		t.Fatalf("successful save did not resolve generation alert: %v", alerts.resolved)
	}
}
