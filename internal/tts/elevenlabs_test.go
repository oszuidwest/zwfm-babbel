package tts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
