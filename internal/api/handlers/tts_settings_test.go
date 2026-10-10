package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

func TestToTTSSettingsServiceRequest_SeedStates(t *testing.T) {
	seed := int64(42)

	tests := []struct {
		name          string
		req           utils.TTSSettingsUpdateRequest
		wantSeed      *int64
		wantClearSeed bool
	}{
		{
			name: "absent seed is ignored",
		},
		{
			name: "null seed clears",
			req: utils.TTSSettingsUpdateRequest{
				Seed: utils.Optional[int64]{Set: true},
			},
			wantClearSeed: true,
		},
		{
			name: "present seed updates",
			req: utils.TTSSettingsUpdateRequest{
				Seed: utils.Optional[int64]{Set: true, Value: &seed},
			},
			wantSeed: &seed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toTTSSettingsServiceRequest(tt.req)

			if got.ClearSeed != tt.wantClearSeed {
				t.Fatalf("ClearSeed = %t, want %t", got.ClearSeed, tt.wantClearSeed)
			}
			if tt.wantSeed == nil {
				if got.Seed != nil {
					t.Fatalf("Seed = %v, want nil", *got.Seed)
				}
				return
			}
			if got.Seed == nil || *got.Seed != *tt.wantSeed {
				t.Fatalf("Seed = %v, want %d", got.Seed, *tt.wantSeed)
			}
		})
	}
}

func TestUpdateTTSSettings_StrictBindingUnknownFields(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantField string
	}{
		{
			name:      "model ID read only",
			body:      `{"model_id":"eleven_v4"}`,
			wantField: "model_id",
		},
		{
			name:      "unknown typo",
			body:      `{"stabilty":0.5}`,
			wantField: "stabilty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{}
			recorder := performTTSSettingsHandlerRequest(t, tt.body, h.UpdateTTSSettings)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
			}
			assertFieldError(t, recorder, tt.wantField, "unknown_field")
		})
	}
}

func performTTSSettingsHandlerRequest(
	t *testing.T,
	body string,
	handler gin.HandlerFunc,
) *httptest.ResponseRecorder {
	t.Helper()

	const path = "/settings/tts"
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PATCH(path, handler)

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)
	return recorder
}
