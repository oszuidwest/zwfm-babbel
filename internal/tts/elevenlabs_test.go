package tts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

type generateSpeechRequestCase struct {
	name                  string
	options               Options
	wantSeedPresent       bool
	wantNormalizationMode string
}

func TestService_GenerateSpeech_RequestBody(t *testing.T) {
	tests := []generateSpeechRequestCase{
		{
			name: "omits optional seed",
			options: Options{
				VoiceSettings: VoiceSettings{
					Stability:       0.8,
					SimilarityBoost: 0.7,
					Style:           0.25,
					Speed:           1.0,
				},
				ApplyTextNormalization: "auto",
			},
			wantNormalizationMode: "auto",
		},
		{
			name: "includes optional seed",
			options: Options{
				VoiceSettings: VoiceSettings{
					Stability:       0,
					SimilarityBoost: 1,
					Style:           0,
					Speed:           0.7,
				},
				ApplyTextNormalization: "off",
				Seed:                   uint32Ptr(123),
			},
			wantSeedPresent:       true,
			wantNormalizationMode: "off",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertGenerateSpeechHTTPRequest(t, r)
				captured = decodeGenerateSpeechRequest(t, r)

				w.Header().Set("Content-Type", "audio/ogg")
				_, _ = w.Write([]byte("opus"))
			}))
			defer server.Close()

			service := &Service{
				apiKey:  "test-key",
				baseURL: server.URL,
				client:  &http.Client{Timeout: time.Second},
			}

			audio, err := service.GenerateSpeech(context.Background(), "final text", "voice-123", tt.options)
			if err != nil {
				t.Fatalf("GenerateSpeech() error = %v", err)
			}
			if string(audio) != "opus" {
				t.Fatalf("audio = %q, want opus", string(audio))
			}

			assertGenerateSpeechRequestBody(t, captured, tt)
		})
	}
}

func assertGenerateSpeechHTTPRequest(t *testing.T, r *http.Request) {
	t.Helper()

	if r.URL.Path != "/v1/text-to-speech/voice-123" {
		t.Errorf("path = %q, want /v1/text-to-speech/voice-123", r.URL.Path)
	}
	if got := r.URL.Query().Get("output_format"); got != outputFormatOpus48k128 {
		t.Errorf("output_format = %q, want %q", got, outputFormatOpus48k128)
	}
	if got := r.Header.Get("xi-api-key"); got != "test-key" {
		t.Errorf("xi-api-key = %q, want test-key", got)
	}
}

func decodeGenerateSpeechRequest(t *testing.T, r *http.Request) map[string]any {
	t.Helper()

	var captured map[string]any
	if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return captured
}

func assertGenerateSpeechRequestBody(t *testing.T, captured map[string]any, tt generateSpeechRequestCase) {
	t.Helper()

	if captured["text"] != "final text" {
		t.Fatalf("text = %q, want final text", captured["text"])
	}
	if captured["model_id"] != ModelV3 {
		t.Fatalf("model_id = %q, want %q", captured["model_id"], ModelV3)
	}
	if captured["apply_text_normalization"] != tt.wantNormalizationMode {
		t.Fatalf("apply_text_normalization = %q, want %q", captured["apply_text_normalization"], tt.wantNormalizationMode)
	}

	_, seedPresent := captured["seed"]
	if seedPresent != tt.wantSeedPresent {
		t.Fatalf("seed present = %t, want %t; body=%#v", seedPresent, tt.wantSeedPresent, captured)
	}

	voiceSettings, ok := captured["voice_settings"].(map[string]any)
	if !ok {
		t.Fatalf("voice_settings = %#v, want object", captured["voice_settings"])
	}
	if _, present := voiceSettings["use_speaker_boost"]; present {
		t.Fatalf("use_speaker_boost present in voice_settings: %#v", voiceSettings)
	}
	if _, present := captured["pronunciation_dictionary_locators"]; present {
		t.Fatalf("pronunciation_dictionary_locators present in request body: %#v", captured)
	}
}

func TestService_GenerateSpeech_APIErrorIncludesRetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "45")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"detail":"slow down"}`))
	}))
	defer server.Close()

	service := &Service{
		apiKey:  "test-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: time.Second},
	}

	_, err := service.GenerateSpeech(context.Background(), "final text", "voice-123", Options{})
	if err == nil {
		t.Fatal("GenerateSpeech() error = nil, want API error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusTooManyRequests)
	}
	if apiErr.RetryAfter != "45" {
		t.Fatalf("RetryAfter = %q, want 45", apiErr.RetryAfter)
	}
	if apiErr.Body == "" {
		t.Fatal("Body is empty, want response body")
	}
}

func TestParseElevenLabsErrorDetail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		body          string
		wantType      string
		wantCode      string
		wantRequestID string
	}{
		{
			name:          "official detail code",
			body:          `{"detail":{"type":"rate_limit_error","code":"rate_limit_exceeded","request_id":"req_123"}}`,
			wantType:      "rate_limit_error",
			wantCode:      "rate_limit_exceeded",
			wantRequestID: "req_123",
		},
		{
			name:     "legacy status fallback",
			body:     `{"detail":{"type":"rate_limit_error","status":"too_many_concurrent_requests"}}`,
			wantType: "rate_limit_error",
			wantCode: "too_many_concurrent_requests",
		},
		{
			name:     "code preferred over status",
			body:     `{"detail":{"code":"rate_limit_exceeded","status":"too_many_concurrent_requests"}}`,
			wantCode: "rate_limit_exceeded",
		},
		{
			name:     "string detail fallback",
			body:     `{"detail":"system_busy"}`,
			wantCode: "system_busy",
		},
		{
			name: "non-token string detail ignored",
			body: `{"detail":"slow down"}`,
		},
		{
			name:     "request id with control character ignored",
			body:     `{"detail":{"type":"rate_limit_error","code":"rate_limit_exceeded","request_id":"req\n123"}}`,
			wantType: "rate_limit_error",
			wantCode: "rate_limit_exceeded",
		},
		{
			name: "overlong token ignored",
			body: `{"detail":{"code":"` + strings.Repeat("a", 129) + `"}}`,
		},
		{
			name: "malformed body",
			body: `not json`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := parseElevenLabsErrorDetail([]byte(tt.body))
			if got.Type != tt.wantType {
				t.Fatalf("Type = %q, want %q", got.Type, tt.wantType)
			}
			if got.Code != tt.wantCode {
				t.Fatalf("Code = %q, want %q", got.Code, tt.wantCode)
			}
			if got.RequestID != tt.wantRequestID {
				t.Fatalf("RequestID = %q, want %q", got.RequestID, tt.wantRequestID)
			}
		})
	}
}

func TestConcurrencyHeaderValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "valid count",
			value: "5",
			want:  "5",
		},
		{
			name:  "valid count normalized",
			value: "005",
			want:  "5",
		},
		{
			name:  "negative count ignored",
			value: "-1",
		},
		{
			name:  "non numeric count ignored",
			value: "abc",
		},
		{
			name: "empty count ignored",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			header := http.Header{}
			if tt.value != "" {
				header.Set(headerCurrentConcurrentRequests, tt.value)
			}

			got := concurrencyHeaderValue(header, headerCurrentConcurrentRequests)
			if got != tt.want {
				t.Fatalf("concurrencyHeaderValue() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestElevenLabsResponseLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		want       slog.Level
	}{
		{
			name:       "unauthorized is error",
			statusCode: http.StatusUnauthorized,
			want:       slog.LevelError,
		},
		{
			name:       "forbidden is error",
			statusCode: http.StatusForbidden,
			want:       slog.LevelError,
		},
		{
			name:       "rate limited is warn",
			statusCode: http.StatusTooManyRequests,
			want:       slog.LevelWarn,
		},
		{
			name:       "request timeout is warn",
			statusCode: http.StatusRequestTimeout,
			want:       slog.LevelWarn,
		},
		{
			name:       "not found is info",
			statusCode: http.StatusNotFound,
			want:       slog.LevelInfo,
		},
		{
			name:       "unprocessable is info",
			statusCode: http.StatusUnprocessableEntity,
			want:       slog.LevelInfo,
		},
		{
			name:       "server error is error",
			statusCode: http.StatusInternalServerError,
			want:       slog.LevelError,
		},
		{
			name:       "unexpected non error status is warn",
			statusCode: http.StatusMovedPermanently,
			want:       slog.LevelWarn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := elevenLabsResponseLogLevel(tt.statusCode)
			if got != tt.want {
				t.Fatalf("elevenLabsResponseLogLevel(%d) = %s, want %s", tt.statusCode, got, tt.want)
			}
		})
	}
}

func TestLogElevenLabsResponseIncludesSafeFields(t *testing.T) {
	header := http.Header{}
	header.Set("Retry-After", "45")
	header.Set(headerCurrentConcurrentRequests, "5")
	header.Set(headerMaximumConcurrentRequests, "8")

	entry := captureLogEntry(t, func() {
		logElevenLabsResponse(
			ContextWithStoryID(context.Background(), 99),
			http.StatusTooManyRequests,
			123*time.Millisecond,
			header,
			elevenLabsErrorDetail{
				Type:      "rate_limit_error",
				Code:      "concurrent_limit_exceeded",
				RequestID: "req_123",
			},
		)
	})

	assertLogField(t, entry, "level", "WARN")
	assertLogField(t, entry, "msg", "elevenlabs tts response")
	assertLogField(t, entry, "status_code", float64(http.StatusTooManyRequests))
	assertLogField(t, entry, "duration_ms", float64(123))
	assertLogField(t, entry, "story_id", float64(99))
	assertLogField(t, entry, "retry_after", "45")
	assertLogField(t, entry, "elevenlabs_error_type", "rate_limit_error")
	assertLogField(t, entry, "elevenlabs_error_code", "concurrent_limit_exceeded")
	assertLogField(t, entry, "elevenlabs_request_id", "req_123")
	assertLogField(t, entry, "current_concurrent_requests", "5")
	assertLogField(t, entry, "maximum_concurrent_requests", "8")
}

func TestContextWithStoryID(t *testing.T) {
	t.Parallel()

	base := context.Background()
	ctx := ContextWithStoryID(base, 99)

	storyID, ok := storyIDFromContext(ctx)
	if !ok {
		t.Fatal("storyIDFromContext() ok = false, want true")
	}
	if storyID != 99 {
		t.Fatalf("storyIDFromContext() storyID = %d, want 99", storyID)
	}

	if got := ContextWithStoryID(base, 0); got != base {
		t.Fatal("ContextWithStoryID() with zero story ID returned child context, want original")
	}
	if got := ContextWithStoryID(base, -1); got != base {
		t.Fatal("ContextWithStoryID() with negative story ID returned child context, want original")
	}
}

func TestService_GenerateSpeech_APIErrorMarksTruncatedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("x", int(maxErrorResponseBytes)+1)))
	}))
	defer server.Close()

	service := &Service{
		apiKey:  "test-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: time.Second},
	}

	_, err := service.GenerateSpeech(context.Background(), "final text", "voice-123", Options{})
	if err == nil {
		t.Fatal("GenerateSpeech() error = nil, want API error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T, want *APIError", err)
	}

	wantBody := strings.Repeat("x", int(maxErrorResponseBytes)) + " (truncated)"
	if apiErr.Body != wantBody {
		t.Fatalf("Body len = %d, want %d with truncated marker", len(apiErr.Body), len(wantBody))
	}
}

func TestService_GenerateSpeech_EscapesVoiceIDPath(t *testing.T) {
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "audio/ogg")
		_, _ = w.Write([]byte("opus"))
	}))
	defer server.Close()

	service := &Service{
		apiKey:  "test-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: time.Second},
	}

	// Even if the service layer let a path-altering value slip, the client must
	// not route it to a different upstream endpoint.
	if _, err := service.GenerateSpeech(context.Background(), "t", "../evil", Options{}); err != nil {
		t.Fatalf("GenerateSpeech() error = %v", err)
	}

	const want = "/v1/text-to-speech/..%2Fevil"
	if capturedPath != want {
		t.Fatalf("escaped path = %q, want %q", capturedPath, want)
	}
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func captureLogEntry(t *testing.T, emit func()) map[string]any {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create log capture pipe: %v", err)
	}
	defer func() {
		os.Stdout = originalStdout
		_ = logger.Initialize("debug", false)
		_ = reader.Close()
		_ = writer.Close()
	}()

	os.Stdout = writer
	if err := logger.Initialize("debug", false); err != nil {
		t.Fatalf("initialize capture logger: %v", err)
	}

	emit()

	if err := writer.Close(); err != nil {
		t.Fatalf("close log capture writer: %v", err)
	}
	os.Stdout = originalStdout
	if err := logger.Initialize("debug", false); err != nil {
		t.Fatalf("restore logger: %v", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		t.Fatalf("read captured log: %v", err)
	}

	line := bytes.TrimSpace(buf.Bytes())
	if len(line) == 0 {
		t.Fatal("captured log is empty")
	}

	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		t.Fatalf("decode captured log %q: %v", line, err)
	}
	return entry
}

func assertLogField(t *testing.T, entry map[string]any, key string, want any) {
	t.Helper()

	got, ok := entry[key]
	if !ok {
		t.Fatalf("log field %q missing in %#v", key, entry)
	}
	if got != want {
		t.Fatalf("log field %q = %#v, want %#v", key, got, want)
	}
}
