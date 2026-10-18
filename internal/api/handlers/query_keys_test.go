package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// GET /{resource}/{id} handlers reject query keys before calling a service.
// The services are nil, so a handler that skips the check panics. An invalid
// id is reported instead of the query key.
func TestSingleResourceGETsRejectQueryKeysBeforeCallingService(t *testing.T) {
	t.Parallel()

	h := &Handlers{}
	handlers := map[string]gin.HandlerFunc{
		"GetStation":               h.GetStation,
		"GetVoice":                 h.GetVoice,
		"GetStory":                 h.GetStory,
		"GetUser":                  h.GetUser,
		"GetStationVoice":          h.GetStationVoice,
		"GetBulletin":              h.GetBulletin,
		"GetBulletinJob":           h.GetBulletinJob,
		"GetLatestStationBulletin": h.GetLatestStationBulletin,
		"GetStationBulletins":      h.GetStationBulletins,
		"GetBulletinStories":       h.GetBulletinStories,
		"GetStoryBulletinHistory":  h.GetStoryBulletinHistory,
	}
	cases := []struct {
		name, id, field, code string
	}{
		{name: "query key", id: "1", field: "bogus", code: "unknown_field"},
		{name: "invalid id wins", id: "abc", field: "id", code: "invalid_format"},
	}
	for name, handler := range handlers {
		for _, tt := range cases {
			t.Run(name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/x/"+tt.id+"?bogus=1", nil)
				c.Params = gin.Params{{Key: "id", Value: tt.id}}

				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("handler called a service: %v", r)
						}
					}()
					handler(c)
				}()

				if recorder.Code != http.StatusUnprocessableEntity {
					t.Fatalf("status = %d, want 422; body=%s", recorder.Code, recorder.Body.String())
				}
				assertFieldError(t, recorder, tt.field, tt.code)
			})
		}
	}
}

func TestSingletonGETsRejectQueryKeysBeforeCallingService(t *testing.T) {
	t.Parallel()
	h := &Handlers{}
	for name, handler := range map[string]gin.HandlerFunc{"settings": h.GetTTSSettings, "pronunciations": h.GetPronunciationRules} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/settings?fields=x", nil)
			handler(c) // Nil services must not be touched.
			assertFieldError(t, recorder, "fields", "unknown_field")
		})
	}
}

func TestRepeatedNonListQueryValuesAreRejected(t *testing.T) {
	t.Parallel()
	h := &Handlers{ttsEnabled: true}
	automation := NewAutomationHandler(nil, nil, &config.Config{Automation: config.AutomationConfig{Key: "expected"}}, nil)
	for _, tt := range []struct {
		query, field string
		handler      gin.HandlerFunc
	}{
		{"force=false&force=true", "force", h.GenerateStoryTTS},
		{"force=true&force=false", "force", h.GenerateStoryTTS},
		{"key=expected&max_age=0&max_age=3600", "max_age", automation.GetPublicBulletin},
		{"key=expected&max_age=3600&max_age=0", "max_age", automation.GetPublicBulletin},
		{"key=expected&key=other&max_age=0", "key", automation.GetPublicBulletin},
		{"key=other&key=expected&max_age=0", "key", automation.GetPublicBulletin},
	} {
		t.Run(tt.query, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x/7?"+tt.query, nil)
			c.Params = gin.Params{{Key: "id", Value: "7"}}
			tt.handler(c)
			assertFieldError(t, recorder, tt.field, "duplicate")
		})
	}
}

type missingAudioRepo struct{}

func (missingAudioRepo) GetFilePath(context.Context, string, int64) (string, error) {
	return "", repository.ErrNotFound
}

// Audio downloads ignore query keys, so a cache-busting key reaches the lookup.
func TestServeAudioIgnoresQueryKeys(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/stories/1/audio?v=1", nil)
	c.Params = gin.Params{{Key: "id", Value: "1"}}

	(&Handlers{audioRepo: missingAudioRepo{}}).ServeAudio(c, AudioConfig{TableName: "stories"})

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 from the lookup; body=%s", recorder.Code, recorder.Body.String())
	}
}
