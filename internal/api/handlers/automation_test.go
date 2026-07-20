package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
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

func TestAutomationHandlerInvalidKeyRaisesContinuousSecurityAlert(t *testing.T) {
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
	if event.Key != "security:automation-key" || event.Kind != notify.KindContinuous {
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
