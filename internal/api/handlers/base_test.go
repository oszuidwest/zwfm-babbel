package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

type problemResponse struct {
	Type      string                      `json:"type"`
	Status    int                         `json:"status"`
	Code      string                      `json:"code"`
	Hint      string                      `json:"hint"`
	Detail    string                      `json:"detail"`
	DeletedAt time.Time                   `json:"deleted_at"`
	Errors    []apperrors.ValidationError `json:"errors"`
}

func newProblemContext(t *testing.T) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/stories/1/tts", nil)
	return c, rec
}

// decodeProblem requires a problem+json response and decodes its body.
func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) problemResponse {
	t.Helper()
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", got)
	}
	var problem problemResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem body: %v; body=%s", err, rec.Body.String())
	}
	return problem
}

// assertValidationField requires a problem+json body with exactly one error for field.
func assertValidationField(t *testing.T, rec *httptest.ResponseRecorder, field string) {
	t.Helper()
	if errs := decodeProblem(t, rec).Errors; len(errs) != 1 || errs[0].Field != field {
		t.Fatalf("errors = %+v, want exactly one %q error", errs, field)
	}
}

func TestHandleServiceError_StoryDeletedReturnsGone(t *testing.T) {
	c, rec := newProblemContext(t)
	deletedAt := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	err := apperrors.TranslateRepoErrorWithID("Story", 1, apperrors.OpUpdate,
		&repository.StoryDeletedError{ID: 1, DeletedAt: deletedAt})

	handleServiceError(c, err, "Story")

	problem := decodeProblem(t, rec)
	if rec.Code != http.StatusGone || problem.Code != "story.deleted" ||
		problem.Type != "https://babbel.api/problems/story.deleted" || !problem.DeletedAt.Equal(deletedAt) {
		t.Fatalf("response = %d %s", rec.Code, rec.Body.String())
	}
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

func TestHandleServiceErrorAlertsOnlyOperationalFailures(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantEvents int
		wantKey    string
	}{
		{
			name:       "database error alerts",
			err:        apperrors.Database("Story", "query", errors.New("connection lost")),
			wantEvents: 1,
			wantKey:    "database:request:POST unmatched",
		},
		{
			name: "validation error does not alert",
			err:  apperrors.Validation("Story", "title", "is required"),
		},
		{
			name: "not found does not alert",
			err:  apperrors.NotFoundWithID("Story", 9),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newProblemContext(t)
			alerts := &automationAlertRecorder{}
			c.Set(alertContextKey, alerts)

			handleServiceError(c, tt.err, "Story")
			if len(alerts.events) != tt.wantEvents {
				t.Fatalf("event count = %d, want %d", len(alerts.events), tt.wantEvents)
			}
			if tt.wantKey != "" && alerts.events[0].Key != tt.wantKey {
				t.Fatalf("event key = %q, want %q", alerts.events[0].Key, tt.wantKey)
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

func TestHandleServiceError_QueryShapeErrors(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantField string
	}{
		{name: "unknown filter field", err: &repository.UnknownFieldError{Kind: "filter", Field: "bogus"}, wantField: "filter"},
		{name: "unknown sort field", err: &repository.UnknownFieldError{Kind: "sort", Field: "bogus"}, wantField: "sort"},
		{name: "invalid filter value", err: &repository.InvalidFilterError{Field: "weekdays", Operator: repository.FilterBitwiseAnd, Reason: "expected integer between 0 and 127"}, wantField: "filter[weekdays][band]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec := newProblemContext(t)
			handleServiceError(c, tt.err, "User")
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
			}
			assertValidationField(t, rec, tt.wantField)
		})
	}
}

// captureLogs sends the slog default to a JSON buffer for one test. It swaps
// process-wide loggers, so do not use it in parallel tests.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous, previousWriter, previousFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	// SetDefault also redirects the log package, and restoring the built-in
	// default handler does not undo that.
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
	return &buf
}

// Invalid list queries are expected client input, whichever check rejects
// them: one Debug record and no alert, even when a query error arrives
// wrapped. A database failure logs at Error and alerts.
func TestQueryValidationLogsAtDebugAndDatabaseFailuresAtError(t *testing.T) {
	serviceError := func(err error) func(*gin.Context) {
		return func(c *gin.Context) { handleServiceError(c, err, "Story") }
	}
	tests := []struct {
		name       string
		respond    func(*gin.Context)
		wantStatus int
	}{
		{
			name:       "parser rejects trashed",
			respond:    func(c *gin.Context) { utils.ParseListQuery(c) },
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "pagination-only endpoint rejects trashed",
			respond:    func(c *gin.Context) { utils.ParsePaginationOnly(c) },
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "sparse fieldset names an unknown field",
			respond: func(c *gin.Context) {
				utils.PaginatedListResponse(c, &utils.QueryParams{Fields: []string{"bogus"}}, &repository.ListResult[models.Story]{})
			},
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "repository rejects unknown sort field",
			respond:    serviceError(&repository.UnknownFieldError{Kind: "sort", Field: "bogus"}),
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "repository rejects filter value",
			respond:    serviceError(&repository.InvalidFilterError{Field: "weekdays", Operator: repository.FilterBitwiseAnd, Reason: "expected integer between 0 and 127"}),
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "query error wrapped as a database error",
			respond:    serviceError(apperrors.Database("Story", "query", &repository.UnknownFieldError{Kind: "sort", Field: "bogus"})),
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "database failure",
			respond:    serviceError(apperrors.Database("Story", "query", errors.New("connection lost"))),
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			c, rec := newProblemContext(t)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/stories?trashed=only", nil)
			alerts := &automationAlertRecorder{}
			c.Set(alertContextKey, alerts)
			wantLevel, wantAlerts := "DEBUG", 0
			if tt.wantStatus == http.StatusInternalServerError {
				wantLevel, wantAlerts = "ERROR", 1
			}

			tt.respond(c)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			// Unmarshal rejects an empty buffer and a second record.
			var record map[string]any
			if err := json.Unmarshal(logs.Bytes(), &record); err != nil || record["level"] != wantLevel {
				t.Fatalf("logs = %s, want one %s record", logs, wantLevel)
			}
			if wantLevel == "DEBUG" {
				_, hasRoute := record["route"]
				if errs, _ := record["errors"].([]any); record["error_type"] != "query_validation" || len(errs) != 1 || !hasRoute {
					t.Fatalf("record = %v, want error_type query_validation, a route and one field error", record)
				}
			}
			if len(alerts.events) != wantAlerts {
				t.Fatalf("alerts = %d, want %d", len(alerts.events), wantAlerts)
			}
		})
	}
}

func TestHandleServiceError_ValidationProblemReturns422(t *testing.T) {
	c, rec := newProblemContext(t)
	err := apperrors.NewValidationProblemError("tts_settings", "validation failed", []apperrors.ValidationError{
		{Field: "stability", Message: "must be between 0 and 1"},
		{Field: "tts_style_prefix", Message: "must be at most 500 characters"},
	})

	handleServiceError(c, err, "tts_settings")

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	problem := decodeProblem(t, rec)
	if len(problem.Errors) != 2 {
		t.Fatalf("errors len = %d, want 2; body=%s", len(problem.Errors), rec.Body.String())
	}
	wantFields := map[string]bool{"stability": false, "tts_style_prefix": false}
	for _, e := range problem.Errors {
		wantFields[e.Field] = true
	}
	for field, seen := range wantFields {
		if !seen {
			t.Fatalf("missing field %q in problem errors", field)
		}
	}
}

func TestNotificationMiddlewareAcceptsNilAlerter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NotificationMiddleware(nil))
	router.GET("/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
}

func TestHandleServiceError_DeadlineExceededReturnsGatewayTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"direct", context.DeadlineExceeded},
		{"wrapped", fmt.Errorf("generate bulletin: %w", context.DeadlineExceeded)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec := newProblemContext(t)

			handleServiceError(c, tt.err, "Bulletin")

			if rec.Code != http.StatusGatewayTimeout {
				t.Fatalf("status = %d, want 504", rec.Code)
			}
			problem := decodeProblem(t, rec)
			if problem.Status != http.StatusGatewayTimeout {
				t.Fatalf("problem.status = %d, want 504", problem.Status)
			}
			if problem.Code != "internal.timeout" {
				t.Fatalf("code = %q, want internal.timeout", problem.Code)
			}
			if problem.Detail != "Bulletin operation timed out" {
				t.Fatalf("detail = %q, want Bulletin operation timed out", problem.Detail)
			}
		})
	}
}

func TestHandleServiceError_Audio(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantHint   string
	}{
		{
			name:       "wrapped silent audio",
			err:        apperrors.Audio("Story", "convert", fmt.Errorf("convert: %w", audio.ErrSilent)),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "audio.silent",
			wantHint:   "Check the recording level and input channel, then upload audible audio or regenerate speech",
		},
		{
			name:       "processing failure",
			err:        apperrors.Audio("Story", "convert", errors.New("ffmpeg failed")),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "audio.processing_failed",
			wantHint:   "Check the audio file format and try again",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec := newProblemContext(t)
			handleServiceError(c, tt.err, "Story")
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			problem := decodeProblem(t, rec)
			if problem.Status != tt.wantStatus || problem.Code != tt.wantCode || problem.Hint != tt.wantHint {
				t.Fatalf("problem = %+v, want status %d, code %q, hint %q", problem, tt.wantStatus, tt.wantCode, tt.wantHint)
			}
		})
	}
}
