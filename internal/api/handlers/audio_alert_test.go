package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

func TestAudioServerFailuresAlertAndResolveByRoute(t *testing.T) {
	alerts := &automationAlertRecorder{}
	fail := true
	router := gin.New()
	router.Use(NotificationMiddleware(alerts))
	router.POST("/audio/:id", func(c *gin.Context) {
		if fail {
			handleServiceError(c, apperrors.Audio("Story", "finalize", errors.New("rename: read-only file system")), "Story")
			return
		}
		c.Status(http.StatusCreated)
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/audio/7", nil))
	if rec.Code != http.StatusInternalServerError || len(alerts.events) != 1 {
		t.Fatalf("status = %d, events = %+v", rec.Code, alerts.events)
	}
	event := alerts.events[0]
	if event.Key != "audio:request:POST /audio/:id" || !event.RequiresThreshold || !strings.Contains(event.Details, "read-only file system") {
		t.Fatalf("event = %+v", event)
	}
	if slices.Contains(alerts.resolved, event.Key) {
		t.Fatal("failed request resolved its incident")
	}
	fail = false
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/audio/7", nil))
	if !slices.Contains(alerts.resolved, event.Key) {
		t.Fatalf("success did not resolve %q: %v", event.Key, alerts.resolved)
	}
}
