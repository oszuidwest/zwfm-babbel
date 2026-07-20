package scheduler

import (
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestCleanOrphanedFilesDoesNotPropagateAlreadyAlertedReadError(t *testing.T) {
	alerts := &schedulerAlertRecorder{}
	service := &BulletinCleanupService{
		config: &config.Config{Audio: config.AudioConfig{OutputPath: t.TempDir() + "/missing"}},
		alerts: alerts,
	}

	_, _, err := service.cleanOrphanedFiles(t.Context())
	if err != nil {
		t.Fatalf("cleanOrphanedFiles error = %v, want handled storage alert", err)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "storage:bulletin-output" {
		t.Fatalf("events = %+v, want one storage alert", alerts.events)
	}
}
