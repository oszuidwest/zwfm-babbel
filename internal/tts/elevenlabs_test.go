package tts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestService_GenerateSpeech_RequestBody(t *testing.T) {
	tests := []struct {
		name                  string
		options               Options
		wantSeedPresent       bool
		wantBoostPresent      bool
		wantUseSpeakerBoost   bool
		wantNormalizationMode string
	}{
		{
			name: "omits optional seed and speaker boost",
			options: Options{
				Model: "eleven_v3",
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
			name: "includes optional seed and speaker boost",
			options: Options{
				Model: "eleven_multilingual_v2",
				VoiceSettings: VoiceSettings{
					Stability:       0,
					SimilarityBoost: 1,
					Style:           0,
					Speed:           0.7,
					UseSpeakerBoost: boolPtr(false),
				},
				ApplyTextNormalization: "off",
				Seed:                   uint32Ptr(123),
			},
			wantSeedPresent:       true,
			wantBoostPresent:      true,
			wantUseSpeakerBoost:   false,
			wantNormalizationMode: "off",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/text-to-speech/voice-123" {
					t.Errorf("path = %q, want /v1/text-to-speech/voice-123", r.URL.Path)
				}
				if got := r.Header.Get("xi-api-key"); got != "test-key" {
					t.Errorf("xi-api-key = %q, want test-key", got)
				}
				if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
					t.Errorf("decode request body: %v", err)
				}

				w.Header().Set("Content-Type", "audio/mpeg")
				_, _ = w.Write([]byte("mp3"))
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
			if string(audio) != "mp3" {
				t.Fatalf("audio = %q, want mp3", string(audio))
			}

			if captured["text"] != "final text" {
				t.Fatalf("text = %q, want final text", captured["text"])
			}
			if captured["model_id"] != tt.options.Model {
				t.Fatalf("model_id = %q, want %q", captured["model_id"], tt.options.Model)
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
			boost, boostPresent := voiceSettings["use_speaker_boost"]
			if boostPresent != tt.wantBoostPresent {
				t.Fatalf("use_speaker_boost present = %t, want %t; body=%#v", boostPresent, tt.wantBoostPresent, voiceSettings)
			}
			if boostPresent && boost != tt.wantUseSpeakerBoost {
				t.Fatalf("use_speaker_boost = %#v, want %t", boost, tt.wantUseSpeakerBoost)
			}
		})
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

	_, err := service.GenerateSpeech(context.Background(), "final text", "voice-123", Options{Model: "eleven_v3"})
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

func TestService_GenerateSpeech_EscapesVoiceIDPath(t *testing.T) {
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write([]byte("mp3"))
	}))
	defer server.Close()

	service := &Service{
		apiKey:  "test-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: time.Second},
	}

	// Even if the service layer let a path-altering value slip, the client must
	// not route it to a different upstream endpoint.
	if _, err := service.GenerateSpeech(context.Background(), "t", "../evil", Options{Model: "eleven_v3"}); err != nil {
		t.Fatalf("GenerateSpeech() error = %v", err)
	}

	const want = "/v1/text-to-speech/..%2Fevil"
	if capturedPath != want {
		t.Fatalf("escaped path = %q, want %q", capturedPath, want)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}
