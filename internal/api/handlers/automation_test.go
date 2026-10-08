package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
)

type automationAlertRecorder struct {
	events   []notify.Event
	resolved []string
}

func (a *automationAlertRecorder) Alert(_ context.Context, event notify.Event) {
	a.events = append(a.events, event)
}

func (a *automationAlertRecorder) Resolve(_ context.Context, key, _, _ string) {
	a.resolved = append(a.resolved, key)
}

func TestAutomationHandlerInvalidKeyRaisesThresholdedSecurityAlert(t *testing.T) {
	gin.SetMode(gin.TestMode)
	alerts := &automationAlertRecorder{}
	handler := NewAutomationHandler(nil, nil, &config.Config{
		Automation: config.AutomationConfig{Key: "expected"},
	}, alerts)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/public/stations/1/bulletin.wav?key=wrong&max_age=0", nil)

	if request := handler.validateBulletinRequest(c); request != nil {
		t.Fatalf("request = %+v, want nil", request)
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if len(alerts.events) != 1 {
		t.Fatalf("event count = %d, want 1", len(alerts.events))
	}
	event := alerts.events[0]
	if event.Key != "security:automation-key" || !event.RequiresThreshold {
		t.Fatalf("event = %+v", event)
	}
}

func TestAutomationHandlerValidKeyResolvesSecurityAlert(t *testing.T) {
	gin.SetMode(gin.TestMode)
	alerts := &automationAlertRecorder{}
	handler := NewAutomationHandler(nil, nil, &config.Config{
		Automation: config.AutomationConfig{Key: "expected"},
	}, alerts)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/public/stations/1/bulletin.wav?key=expected&max_age=0", nil)

	if request := handler.validateBulletinRequest(c); request == nil {
		t.Fatal("request = nil, want validated request")
	}
	if len(alerts.resolved) != 1 || alerts.resolved[0] != "security:automation-key" {
		t.Fatalf("resolved = %v, want [security:automation-key]", alerts.resolved)
	}
}

// failingAudioWriter simulates either a failed body write or final flush.
type failingAudioWriter struct {
	*httptest.ResponseRecorder
	failWrite bool
}

func (w *failingAudioWriter) Write(p []byte) (int, error) {
	if w.failWrite {
		return 0, errors.New("client disconnected")
	}
	return w.ResponseRecorder.Write(p)
}

func (w *failingAudioWriter) FlushError() error { return errors.New("flush failed") }

func TestAutomationBulletinDeliveryFailureAlerts(t *testing.T) {
	for _, failWrite := range []bool{true, false} {
		t.Run(fmt.Sprintf("write_failure_%t", failWrite), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "bulletin.wav"), []byte("audio"), 0600); err != nil {
				t.Fatal(err)
			}
			alerts := &automationAlertRecorder{}
			handler := NewAutomationHandler(nil, nil, &config.Config{Audio: config.AudioConfig{OutputPath: dir}}, alerts)
			c, _ := gin.CreateTestContext(&failingAudioWriter{ResponseRecorder: httptest.NewRecorder(), failWrite: failWrite})
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			handler.serveBulletinAudio(c, "bulletin.wav", 42, 7, false)
			if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:delivery:station:7" {
				t.Fatalf("alerts = %+v, want delivery failure", alerts.events)
			}
			for _, key := range alerts.resolved {
				if key == "bulletin:delivery:station:7" {
					t.Fatal("failed delivery resolved alert")
				}
			}
		})
	}
}

func TestAutomationLockWaitTimeout(t *testing.T) {
	svc := services.NewBulletinService(services.BulletinServiceDeps{})
	release, err := svc.LockStation(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	handler := NewAutomationHandler(svc, nil, &config.Config{
		Automation: config.AutomationConfig{GenerationTimeout: 20 * time.Millisecond},
	}, nil)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	if _, _, ok := handler.getOrGenerateBulletin(c, &bulletinRequest{stationID: 7}, 0); ok {
		t.Fatal("generation succeeded while lock was held")
	}
	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", recorder.Code)
	}
}

func TestAutomationBulletinConditionalResponse(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bulletin.wav"), []byte("audio"), 0600); err != nil {
		t.Fatal(err)
	}
	handler := NewAutomationHandler(nil, nil, &config.Config{Audio: config.AudioConfig{OutputPath: dir}}, nil)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	c.Request.Header.Set("If-Modified-Since", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
	handler.serveBulletinAudio(c, "bulletin.wav", 42, 7, true)
	if recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 {
		t.Fatalf("response = %d, %q; want empty 304", recorder.Code, recorder.Body.String())
	}
}
