package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestUpdateStoryStatusRejectsInvalidRequestsBeforeCallingService(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		body  string
		field string
		code  string
	}{
		{name: "empty", body: `{}`, field: "request", code: "empty_update"},
		{name: "null status", body: `{"status":null}`, field: "request", code: "empty_update"},
		{name: "fields without restore", body: `{"status":"active","weekdays":0}`, field: "request", code: "unsupported"},
		{name: "delete with fields", body: `{"deleted_at":"now","is_breaking":false}`, field: "request", code: "unsupported"},
		{name: "invalid status", body: `{"deleted_at":"","status":"invalid"}`, field: "status", code: "invalid_choice"},
		{name: "invalid weekdays", body: `{"deleted_at":"","weekdays":128}`, field: "weekdays", code: "out_of_range"},
		{name: "blank normalized title", body: `{"deleted_at":"","title":"&#32;"}`, field: "title", code: "blank"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/api/v1/stories/1", strings.NewReader(tt.body))
			c.Params = gin.Params{{Key: "id", Value: "1"}}

			(&Handlers{}).UpdateStoryStatus(c)

			if recorder.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body=%s", recorder.Code, recorder.Body.String())
			}
			assertFieldError(t, recorder, tt.field, tt.code)
		})
	}
}

func TestGenerateStoryTTSRejectsInvalidForceBeforeCallingService(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/stories/1/tts?force=yes", nil)
	c.Params = gin.Params{{Key: "id", Value: "1"}}

	(&Handlers{ttsEnabled: true}).GenerateStoryTTS(c)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", recorder.Code, recorder.Body.String())
	}
	assertFieldError(t, recorder, "force", "invalid_format")
}
