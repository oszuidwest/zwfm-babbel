// Package tts provides text-to-speech integration with the ElevenLabs API.
package tts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

const maxAudioResponseBytes int64 = 50 * 1024 * 1024 // 50 MiB safety cap
const defaultAPIBaseURL = "https://api.elevenlabs.io"
const outputFormatOpus48k128 = "opus_48000_128"

// APIError preserves ElevenLabs response details for service-layer translation.
type APIError struct {
	StatusCode int
	Body       string
	RetryAfter string
}

func (e *APIError) Error() string {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return "ElevenLabs API key is invalid or expired"
	case http.StatusForbidden:
		return "ElevenLabs API key does not have access to this resource"
	case http.StatusNotFound:
		return "ElevenLabs voice ID not found - check the voice configuration"
	case http.StatusTooManyRequests:
		return "ElevenLabs API rate limit or quota exceeded - try again later"
	case http.StatusUnprocessableEntity:
		return fmt.Sprintf("ElevenLabs rejected the request: %s", e.Body)
	default:
		return fmt.Sprintf("ElevenLabs API returned status %d: %s", e.StatusCode, e.Body)
	}
}

// Service handles text-to-speech generation via the ElevenLabs API.
type Service struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

// NewService returns nil when TTS is disabled by an empty API key.
func NewService(cfg *config.TTSConfig) *Service {
	if cfg.APIKey == "" {
		return nil
	}

	return &Service{
		apiKey:  cfg.APIKey,
		baseURL: defaultAPIBaseURL,
		client: &http.Client{
			Timeout: cfg.RequestTimeout,
		},
	}
}

// Options selects the ElevenLabs request options supplied by the story service.
type Options struct {
	Model                  string
	VoiceSettings          VoiceSettings
	ApplyTextNormalization string
	Seed                   *uint32
}

// VoiceSettings contains ElevenLabs voice_settings values.
type VoiceSettings struct {
	Stability       float64 `json:"stability"`
	SimilarityBoost float64 `json:"similarity_boost"`
	Style           float64 `json:"style"`
	Speed           float64 `json:"speed"`
	UseSpeakerBoost *bool   `json:"use_speaker_boost,omitempty"`
}

// ttsRequest is the JSON body sent to the ElevenLabs API.
type ttsRequest struct {
	Text                   string        `json:"text"`
	ModelID                string        `json:"model_id"`
	VoiceSettings          VoiceSettings `json:"voice_settings"`
	ApplyTextNormalization string        `json:"apply_text_normalization"`
	Seed                   *uint32       `json:"seed,omitempty"`
}

// GenerateSpeech converts text to speech audio using the ElevenLabs API.
// Returns the raw Opus audio bytes.
func (s *Service) GenerateSpeech(ctx context.Context, text string, voiceID string, opts Options) ([]byte, error) {
	body, err := json.Marshal(ttsRequest{
		Text:                   text,
		ModelID:                opts.Model,
		VoiceSettings:          opts.VoiceSettings,
		ApplyTextNormalization: opts.ApplyTextNormalization,
		Seed:                   opts.Seed,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TTS request: %w", err)
	}

	// Defense-in-depth: escape the voice ID path segment in case upstream validation
	// is bypassed. The service layer also allowlists voice IDs at write time.
	query := url.Values{}
	query.Set("output_format", outputFormatOpus48k128)
	reqURL := fmt.Sprintf("%s/v1/text-to-speech/%s?%s", s.baseURL, url.PathEscape(voiceID), query.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create TTS request: %w", err)
	}

	req.Header.Set("xi-api-key", s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("TTS API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if err != nil {
			return nil, fmt.Errorf("failed to read TTS error response body for status %d: %w", resp.StatusCode, err)
		}
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
			RetryAfter: resp.Header.Get("Retry-After"),
		}
	}

	limitedReader := io.LimitReader(resp.Body, maxAudioResponseBytes+1)
	audio, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TTS response: %w", err)
	}
	if int64(len(audio)) > maxAudioResponseBytes {
		return nil, fmt.Errorf("TTS response exceeded maximum allowed size of %d bytes", maxAudioResponseBytes)
	}

	return audio, nil
}
