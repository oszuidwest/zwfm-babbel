package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

type problemResponse struct {
	Status int                         `json:"status"`
	Code   string                      `json:"code"`
	Hint   string                      `json:"hint"`
	Detail string                      `json:"detail"`
	Errors []apperrors.ValidationError `json:"errors"`
}

func newProblemContext(t *testing.T) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/stories/1/tts", nil)
	return c, rec
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) problemResponse {
	t.Helper()
	var problem problemResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem body: %v; body=%s", err, rec.Body.String())
	}
	return problem
}

func TestHandleServiceError_RateLimitedSetsRetryAfter(t *testing.T) {
	c, rec := newProblemContext(t)

	handleServiceError(c, apperrors.RateLimited("TTS", "45", errors.New("quota")), "TTS")

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "45" {
		t.Fatalf("Retry-After = %q, want 45", got)
	}
	problem := decodeProblem(t, rec)
	if problem.Code != "tts.rate_limited" {
		t.Fatalf("code = %q, want tts.rate_limited", problem.Code)
	}
	if problem.Status != http.StatusTooManyRequests {
		t.Fatalf("problem.status = %d, want 429", problem.Status)
	}
}

func TestHandleServiceError_RateLimitedOmitsRetryAfterWhenMissing(t *testing.T) {
	c, rec := newProblemContext(t)

	handleServiceError(c, apperrors.RateLimited("TTS", "", nil), "TTS")

	if got := rec.Header().Get("Retry-After"); got != "" {
		t.Fatalf("Retry-After = %q, want empty when upstream omits it", got)
	}
}

func TestHandleServiceError_UpstreamRespectsStatus(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantHint   string
	}{
		{
			name:       "passes through 502 from upstream",
			err:        apperrors.Upstream("TTS", "ElevenLabs", http.StatusBadGateway, "Retry shortly", errors.New("boom")),
			wantStatus: http.StatusBadGateway,
			wantHint:   "Retry shortly",
		},
		{
			name:       "passes through 503 from upstream",
			err:        apperrors.Upstream("TTS", "ElevenLabs", http.StatusServiceUnavailable, "", errors.New("boom")),
			wantStatus: http.StatusServiceUnavailable,
			wantHint:   "Please try again later",
		},
		{
			name:       "defaults to 502 when status is zero",
			err:        apperrors.Upstream("TTS", "ElevenLabs", 0, "", errors.New("boom")),
			wantStatus: http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec := newProblemContext(t)
			handleServiceError(c, tt.err, "TTS")

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			problem := decodeProblem(t, rec)
			if problem.Code != "tts.upstream_failed" {
				t.Fatalf("code = %q, want tts.upstream_failed", problem.Code)
			}
			if tt.wantHint != "" && problem.Hint != tt.wantHint {
				t.Fatalf("hint = %q, want %q", problem.Hint, tt.wantHint)
			}
		})
	}
}

func TestHandleServiceError_NotInitializedUsesCustomCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{
			name:     "defaults code from resource",
			err:      apperrors.NotInitialized("tts_settings", "apply migration", nil),
			wantCode: "tts_settings.not_initialized",
		},
		{
			name: "honors explicit code",
			err: apperrors.NotInitializedWithCode(
				"tts_settings",
				"tts_settings.row_missing",
				"singleton row missing",
				"restore seed row",
				nil,
			),
			wantCode: "tts_settings.row_missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec := newProblemContext(t)
			handleServiceError(c, tt.err, "TTSSettings")

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", rec.Code)
			}
			problem := decodeProblem(t, rec)
			if problem.Code != tt.wantCode {
				t.Fatalf("code = %q, want %q", problem.Code, tt.wantCode)
			}
		})
	}
}

func TestHandleServiceError_ValidationProblemReturns422(t *testing.T) {
	c, rec := newProblemContext(t)
	err := apperrors.NewValidationProblemError("tts_settings", "validation failed", []apperrors.ValidationError{
		{Field: "stability", Message: "must be between 0 and 1"},
		{Field: "speed", Message: "must be between 0.7 and 1.2"},
	})

	handleServiceError(c, err, "tts_settings")

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	problem := decodeProblem(t, rec)
	if len(problem.Errors) != 2 {
		t.Fatalf("errors len = %d, want 2; body=%s", len(problem.Errors), rec.Body.String())
	}
	wantFields := map[string]bool{"stability": false, "speed": false}
	for _, e := range problem.Errors {
		wantFields[e.Field] = true
	}
	for field, seen := range wantFields {
		if !seen {
			t.Fatalf("missing field %q in problem errors", field)
		}
	}
}
