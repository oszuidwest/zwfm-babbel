package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
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

// failingFlushWriter simulates a client that is gone by the final flush.
type failingFlushWriter struct{ *httptest.ResponseRecorder }

func (w failingFlushWriter) FlushError() error { return errors.New("broken pipe") }

// newBulletinFileHandler returns a handler whose output dir holds bulletin.wav.
func newBulletinFileHandler(t *testing.T, alerts notify.Alerter) *AutomationHandler {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bulletin.wav"), []byte("audio"), 0600); err != nil {
		t.Fatal(err)
	}
	return NewAutomationHandler(nil, nil, &config.Config{Audio: config.AudioConfig{OutputPath: dir}}, alerts)
}

func TestAutomationBulletinDeliveryFailureAlerts(t *testing.T) {
	alerts := &automationAlertRecorder{}
	handler := newBulletinFileHandler(t, alerts)
	c, _ := gin.CreateTestContext(failingFlushWriter{httptest.NewRecorder()})
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	handler.serveBulletinAudio(c, "bulletin.wav", 42, 7, false)
	if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:delivery:station:7" {
		t.Fatalf("alerts = %+v, want delivery failure", alerts.events)
	}
	if slices.Contains(alerts.resolved, "bulletin:delivery:station:7") {
		t.Fatal("failed delivery resolved alert")
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
	c, rec := newProblemContext(t)
	if _, _, ok := handler.getOrGenerateBulletin(c, &bulletinRequest{stationID: 7}, 0); ok {
		t.Fatal("generation succeeded while lock was held")
	}
	if problem := decodeProblem(t, rec); rec.Code != http.StatusGatewayTimeout || problem.Code != apperrors.CodeTimeout {
		t.Fatalf("response = %d %q, want 504 %q", rec.Code, problem.Code, apperrors.CodeTimeout)
	}
}

func TestAutomationBulletinConditionalResponse(t *testing.T) {
	handler := newBulletinFileHandler(t, nil)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	c.Request.Header.Set("If-Modified-Since", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
	handler.serveBulletinAudio(c, "bulletin.wav", 42, 7, true)
	if recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 {
		t.Fatalf("response = %d, %q; want empty 304", recorder.Code, recorder.Body.String())
	}
}

// ServeFile swallows write errors; serveAudioFile must still report a client
// that the server write deadline cut off, for both buffered and streamed bodies.
func TestServeAudioFileReportsWriteDeadline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, size := range []int{1 << 10, 8 << 20} {
		path := filepath.Join(t.TempDir(), "bulletin.wav")
		if err := os.WriteFile(path, make([]byte, size), 0600); err != nil {
			t.Fatal(err)
		}
		served := make(chan error, 1)
		router := gin.New()
		router.GET("/", func(c *gin.Context) {
			time.Sleep(100 * time.Millisecond)
			served <- serveAudioFile(c, path, "bulletin.wav", 1, false)
		})
		server := httptest.NewUnstartedServer(router)
		server.Config.WriteTimeout = 50 * time.Millisecond
		server.Start()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := server.Client().Do(request); err == nil {
			_ = response.Body.Close()
		}
		if err := <-served; err == nil {
			t.Errorf("size %d: serveAudioFile = nil, want write deadline error", size)
		}
		server.Close()
	}
}
