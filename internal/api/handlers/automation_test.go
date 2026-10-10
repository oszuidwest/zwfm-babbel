package handlers

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

// failingFlushWriter simulates a client disconnecting at the final flush.
type failingFlushWriter struct{ *httptest.ResponseRecorder }

func (w failingFlushWriter) FlushError() error { return errors.New("broken pipe") }

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

func TestServeAudioFileReportsWriteDeadline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name      string
		size      int
		timeout   time.Duration
		wantError bool
	}{
		{name: "buffered expired", size: 1 << 10, timeout: 50 * time.Millisecond, wantError: true},
		{name: "streamed expired", size: 8 << 20, timeout: 50 * time.Millisecond, wantError: true},
		{name: "buffered extended", size: 1 << 10, timeout: 5 * time.Second},
		{name: "streamed extended", size: 8 << 20, timeout: 5 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "bulletin-*.wav")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			data := bytes.Repeat([]byte("a"), tt.size)
			if _, err := file.Write(data); err != nil {
				t.Fatal(err)
			}
			served := make(chan error, 1)
			router := gin.New()
			router.GET("/", func(c *gin.Context) {
				time.Sleep(100 * time.Millisecond) // Simulate generation before delivery.
				served <- serveAudioFile(c, file, "bulletin.wav", 1, false)
			})
			server := httptest.NewUnstartedServer(router)
			server.Config.WriteTimeout = tt.timeout
			server.Start()
			defer server.Close()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if response, err := server.Client().Do(request); err == nil {
				body, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if !tt.wantError && (readErr != nil || !bytes.Equal(body, data)) {
					t.Errorf("body = %d bytes, error = %v; want complete %d-byte file", len(body), readErr, tt.size)
				}
			} else if !tt.wantError {
				t.Errorf("request failed: %v", err)
			}
			if err := <-served; (err != nil) != tt.wantError {
				t.Errorf("serveAudioFile = %v, wantError = %v", err, tt.wantError)
			}
		})
	}
}

// audioFileChangingWriter changes the file after Content-Length is set, before copying.
type audioFileChangingWriter struct {
	gin.ResponseWriter
	change func()
}

func (w audioFileChangingWriter) WriteHeader(code int) {
	w.change()
	w.ResponseWriter.WriteHeader(code)
}

func TestAutomationBulletinBodylessResponse(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			alerts := &automationAlertRecorder{}
			handler := newBulletinFileHandler(t, alerts)
			c, recorder := newProblemContext(t)
			c.Request.Method = method
			want := http.StatusOK
			if method == http.MethodGet {
				c.Request.Header.Set("If-Modified-Since", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
				want = http.StatusNotModified
			}
			handler.serveBulletinAudio(c, "bulletin.wav", 42, 7, true)
			if len(alerts.events) != 0 {
				t.Fatalf("unexpected alerts: %+v", alerts.events)
			}
			if recorder.Code != want || recorder.Body.Len() != 0 {
				t.Fatalf("response = %d, %q; want empty %d", recorder.Code, recorder.Body.String(), want)
			}
		})
	}
}

func TestAutomationBulletinDelivery(t *testing.T) {
	for _, tt := range []struct {
		name, byteRange, change string
		status                  int
	}{
		{name: "complete", status: http.StatusOK},
		{name: "range", byteRange: "bytes=1-3", status: http.StatusPartialContent},
		{name: "multipart", byteRange: "bytes=0-0,3-4", status: http.StatusPartialContent},
		{name: "truncated", change: "truncate", status: http.StatusOK},
		{name: "truncated range", change: "truncate", byteRange: "bytes=1-3", status: http.StatusPartialContent},
		{name: "truncated multipart", change: "truncate", byteRange: "bytes=0-0,3-4", status: http.StatusPartialContent},
		{name: "unlinked", change: "remove", status: http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			alerts := &automationAlertRecorder{}
			handler := newBulletinFileHandler(t, alerts)
			c, recorder := newProblemContext(t)
			c.Request.Method = http.MethodGet
			c.Writer = audioFileChangingWriter{c.Writer, func() {
				path := filepath.Join(handler.config.Audio.OutputPath, "bulletin.wav")
				var err error
				switch tt.change {
				case "truncate":
					err = os.Truncate(path, 0)
				case "remove":
					err = os.Remove(path)
				}
				if err != nil {
					t.Fatal(err)
				}
			}}
			c.Request.Header.Set("Range", tt.byteRange)
			handler.serveBulletinAudio(c, "bulletin.wav", 42, 7, true)
			if recorder.Code != tt.status {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.status)
			}
			failed := tt.change == "truncate"
			if failed {
				if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:delivery:station:7" {
					t.Errorf("alerts = %+v, want delivery failure", alerts.events)
				}
			} else if len(alerts.events) != 0 {
				t.Errorf("unexpected alerts: %+v", alerts.events)
			}
			if got := slices.Contains(alerts.resolved, "bulletin:delivery:station:7"); got == failed {
				t.Errorf("resolved = %v", alerts.resolved)
			}
			if !failed && strconv.Itoa(recorder.Body.Len()) != recorder.Header().Get("Content-Length") {
				t.Errorf("body length = %d, declared = %s", recorder.Body.Len(), recorder.Header().Get("Content-Length"))
			}
		})
	}
}

func TestAutomationBulletinUnavailableFile(t *testing.T) {
	for _, tt := range []struct {
		name   string
		make   func(path string) error
		status int
	}{
		{name: "missing", make: os.Remove, status: http.StatusNotFound},
		{name: "unreadable", make: func(path string) error { return os.Chmod(path, 0) }, status: http.StatusInternalServerError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "unreadable" && os.Geteuid() == 0 {
				t.Skip("root can read files without read permissions")
			}
			alerts := &automationAlertRecorder{}
			handler := newBulletinFileHandler(t, alerts)
			if err := tt.make(filepath.Join(handler.config.Audio.OutputPath, "bulletin.wav")); err != nil {
				t.Fatal(err)
			}
			c, rec := newProblemContext(t)
			c.Request.Method = http.MethodGet
			handler.serveBulletinAudio(c, "bulletin.wav", 42, 7, false)
			if rec.Code != tt.status || len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:served-audio:station:7" {
				t.Fatalf("response = %d, alerts = %+v; want %d and an unavailable-file alert", rec.Code, alerts.events, tt.status)
			}
		})
	}
}
