package scheduler

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

func TestPurgeExpiredBulletinsStopsAtDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	db := offlineDB(t)
	updates := 0
	if err := db.Callback().Update().Before("gorm:update").Register("count", func(*gorm.DB) { updates++ }); err != nil {
		t.Fatal(err)
	}
	s := NewBulletinCleanupService(db, &config.Config{}, nil)
	stats, err := s.purgeExpiredBulletins(ctx, make([]models.Bulletin, 1000))
	if updates != 0 || stats.count != 0 || !errors.Is(err, context.DeadlineExceeded) ||
		strings.Count(err.Error(), "context deadline exceeded") != 1 || !strings.Contains(err.Error(), "1000 bulletin records remaining") {
		t.Fatalf("stats = %+v, updates = %d, err = %v", stats, updates, err)
	}
}

func TestPurgeExpiredBulletinsStopsDuringUpdateWithoutErrorSpam(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	db := offlineDB(t)
	updates := 0
	if err := db.Callback().Update().Before("gorm:update").Register("cancel", func(tx *gorm.DB) {
		updates++
		if updates == 2 {
			cancel()
			_ = tx.AddError(ctx.Err())
		}
	}); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })
	s := NewBulletinCleanupService(db, &config.Config{}, nil)
	_, err := s.purgeExpiredBulletins(ctx, make([]models.Bulletin, 10))
	if updates != 2 || !errors.Is(err, context.Canceled) || strings.Count(err.Error(), "context canceled") != 1 ||
		!strings.Contains(err.Error(), "9 bulletin records remaining") || logs.Len() != 0 {
		t.Fatalf("updates = %d, err = %v, logs = %s", updates, err, &logs)
	}
}
