package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

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
