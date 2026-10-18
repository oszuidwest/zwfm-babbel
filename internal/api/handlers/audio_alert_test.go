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
	for _, resource := range []string{"Story", "StationVoice"} {
		t.Run(resource, func(t *testing.T) {
			alerts := &automationAlertRecorder{}
			fail := true
			router := gin.New()
			router.Use(NotificationMiddleware(alerts))
			router.POST("/audio/:id", func(c *gin.Context) {
				if fail {
					handleServiceError(c, apperrors.Audio(resource, "finalize", errors.New("rename: read-only file system")), resource)
					return
				}
				c.Status(http.StatusCreated)
			})
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/audio/7?key=secret", nil))
			problem := decodeProblem(t, rec)
			if rec.Code != http.StatusInternalServerError || problem.Hint != "Please try again later or contact support" || len(alerts.events) != 1 {
				t.Fatalf("status = %d, problem = %+v, events = %+v", rec.Code, problem, alerts.events)
			}
			event := alerts.events[0]
			if event.Key != "audio:request:POST /audio/:id" || !event.RequiresThreshold || !strings.Contains(event.Details, "read-only file system") || strings.Contains(event.Details, "secret") {
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
		})
	}
}

func TestAlreadyOwnedAudioFailuresAndValidationDoNotDuplicateAlerts(t *testing.T) {
	for _, err := range []error{
		apperrors.Audio("Bulletin", "generate", errors.New("ffmpeg failed")),
		apperrors.Audio("Story", "tts_generate", errors.New("provider failed")),
		&apperrors.ValidationError{Errors: []apperrors.FieldError{{Field: "audio", Code: apperrors.CodeUndecodable, Message: "no decoded samples"}}},
	} {
		t.Run(err.Error(), func(t *testing.T) {
			alerts := &automationAlertRecorder{}
			c, _ := newProblemContext(t)
			c.Set(alertContextKey, alerts)
			handleServiceError(c, err, "Audio")
			if len(alerts.events) != 0 {
				t.Fatalf("duplicate events = %+v", alerts.events)
			}
		})
	}
}
