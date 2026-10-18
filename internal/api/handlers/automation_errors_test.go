package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

func TestServeAudioFileClassifiesStatFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "audio-*.wav")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	c, rec := newProblemContext(t)
	err = serveAudioFile(c, file, "bulletin.wav", 42, true)
	if !errors.Is(err, errAudioFileAccess) || !errors.Is(err, os.ErrClosed) || rec.Body.Len() != 0 {
		t.Fatalf("serveAudioFile = %v, body = %s; want access failure before response", err, rec.Body)
	}
}

func TestAutomationWrappedMissingStatRemainsNotFound(t *testing.T) {
	alerts := &automationAlertRecorder{}
	h := NewAutomationHandler(nil, nil, nil, alerts)
	c, rec := newProblemContext(t)
	err := fmt.Errorf("%w: %w", errAudioFileAccess, &os.PathError{Op: "stat", Path: "bulletin.wav", Err: os.ErrNotExist})
	h.audioAccessFailure(c, "bulletin:served-audio:station:7", "bulletin.wav", 42, 7, err)
	if rec.Code != http.StatusNotFound || len(alerts.events) != 1 {
		t.Fatalf("status = %d, events = %+v; want missing-file response", rec.Code, alerts.events)
	}
	decodeProblem(t, rec)
}

func TestAutomationQueryFailuresUseSharedErrorHandling(t *testing.T) {
	for _, path := range []string{"station", "cache"} {
		for _, cause := range []error{context.Canceled, errors.New("driver connection lost"), fmt.Errorf("query exceeded deadline: %w", context.DeadlineExceeded)} {
			t.Run(path+"/"+cause.Error(), func(t *testing.T) {
				logs := testutil.CaptureLogs(t, slog.LevelDebug)
				alerts := &automationAlertRecorder{}
				db := failingAutomationQueryDB(t, cause)
				h := NewAutomationHandler(services.NewBulletinService(services.BulletinServiceDeps{BulletinRepo: repository.NewBulletinRepository(db)}),
					services.NewStationService(repository.NewStationRepository(db)), &config.Config{Automation: config.AutomationConfig{Key: "expected"}}, alerts)
				c, rec := newProblemContext(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				wantStatus, wantLevel, wantAlerts := http.StatusInternalServerError, "ERROR", 1
				if errors.Is(cause, context.Canceled) {
					cancel()
					wantStatus, wantLevel, wantAlerts = statusClientClosedRequest, "DEBUG", 0
				} else if errors.Is(cause, context.DeadlineExceeded) {
					wantStatus = http.StatusGatewayTimeout
				}
				c.Request = httptest.NewRequestWithContext(ctx, http.MethodGet, "/public/stations/7/bulletin.wav?key=expected&max_age=60", nil)
				c.Params = gin.Params{{Key: "id", Value: "7"}}
				c.Set(alertContextKey, alerts)
				if path == "station" {
					h.GetPublicBulletin(c)
				} else {
					h.lookupFreshBulletin(c, ctx, 7, time.Minute)
				}
				if rec.Code != wantStatus || len(alerts.events) != wantAlerts {
					t.Fatalf("status = %d, alerts = %+v", rec.Code, alerts.events)
				}
				var record map[string]any
				if err := json.Unmarshal(logs.Bytes(), &record); err != nil || record["level"] != wantLevel {
					t.Fatalf("logs = %s; want one %s record", logs, wantLevel)
				}
				if wantAlerts > 0 && (record["cause"] != cause.Error() || !strings.Contains(alerts.events[0].Details, cause.Error()) || !alerts.events[0].RequiresThreshold) {
					t.Fatalf("record = %v, alerts = %+v; want original cause and thresholded database alert", record, alerts.events)
				}
			})
		}
	}
}

func failingAutomationQueryDB(t *testing.T, cause error) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(mysql.New(mysql.Config{DSN: "babbel@unix(" + filepath.Join(t.TempDir(), "none.sock") + ")/babbel", SkipInitializeWithVersion: true}),
		&gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.Callback().Query().Before("gorm:query").Register("test:fail-query", func(tx *gorm.DB) { _ = tx.AddError(cause) }); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestAutomationCanceledLockWaitIsNotServerFailure(t *testing.T) {
	logs := testutil.CaptureLogs(t, slog.LevelDebug)
	svc := services.NewBulletinService(services.BulletinServiceDeps{})
	release, err := svc.LockStation(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h := NewAutomationHandler(svc, nil, &config.Config{Automation: config.AutomationConfig{GenerationTimeout: time.Minute}}, nil)
	c, rec := newProblemContext(t)
	c.Request = httptest.NewRequestWithContext(ctx, http.MethodGet, "/public/stations/7/bulletin.wav", nil)
	alerts := &automationAlertRecorder{}
	c.Set(alertContextKey, alerts)
	h.getOrGenerateBulletin(c, &bulletinRequest{stationID: 7}, 0)
	var record map[string]any
	if rec.Code != statusClientClosedRequest || len(alerts.events) != 0 || json.Unmarshal(logs.Bytes(), &record) != nil || record["level"] != "DEBUG" {
		t.Fatalf("status = %d, alerts = %+v, logs = %s", rec.Code, alerts.events, logs)
	}
}

func TestHandleServiceError_TimeoutLogsCauseAndRoute(t *testing.T) {
	for _, database := range []bool{false, true} {
		t.Run(fmt.Sprint(database), func(t *testing.T) {
			logs := testutil.CaptureLogs(t, slog.LevelDebug)
			alerts := &automationAlertRecorder{}
			cause := fmt.Errorf("driver read stalled: %w", context.DeadlineExceeded)
			err := cause
			resource := "Operation"
			if database {
				err = apperrors.Database("Bulletin", "query", cause)
				resource = "Bulletin"
			}
			router := gin.New()
			router.Use(NotificationMiddleware(alerts))
			router.GET("/bulletins/:id", func(c *gin.Context) { handleServiceError(c, err, resource) })
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/bulletins/7?key=secret", nil))
			var record map[string]any
			if rec.Code != http.StatusGatewayTimeout || json.Unmarshal(logs.Bytes(), &record) != nil || record["level"] != "ERROR" ||
				record["resource"] != resource || record["error_type"] != "timeout" || record["route"] != "GET /bulletins/:id" ||
				!strings.Contains(fmt.Sprint(record["cause"]), "deadline exceeded") {
				t.Fatalf("status = %d, logs = %s", rec.Code, logs)
			}
			if database && (len(alerts.events) != 1 || !strings.Contains(alerts.events[0].Details, cause.Error())) {
				t.Fatalf("alerts = %+v; want database cause", alerts.events)
			} else if !database && len(alerts.events) != 0 {
				t.Fatalf("non-database timeout alerts = %+v", alerts.events)
			}
		})
	}
}
