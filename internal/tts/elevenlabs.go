// Package tts provides text-to-speech integration with the ElevenLabs API.
package tts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// APIError represents an error response from the ElevenLabs API with the HTTP status code preserved.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return "ElevenLabs API key is invalid or expired"
	case http.StatusForbidden:
		return "ElevenLabs API key does not have access to this resource"
	case http.StatusNotFound:
		return "ElevenLabs voice ID not found — check the voice configuration"
	case http.StatusTooManyRequests:
		return "ElevenLabs API rate limit or quota exceeded — try again later"
	case http.StatusUnprocessableEntity:
		return fmt.Sprintf("ElevenLabs rejected the request: %s", e.Body)
	default:
		return fmt.Sprintf("ElevenLabs API returned status %d: %s", e.StatusCode, e.Body)
	}
}

// Service handles text-to-speech generation via the ElevenLabs API.
type Service struct {
	apiKey string
	model  string
	client *http.Client
}

// NewService creates a new TTS service. Returns nil if no API key is configured.
func NewService(cfg *config.TTSConfig) *Service {
	if cfg.APIKey == "" {
		return nil
	}

	return &Service{
		apiKey: cfg.APIKey,
		model:  cfg.Model,
		client: &http.Client{
			Timeout: cfg.RequestTimeout,
		},
	}
}

// ttsRequest is the JSON body sent to the ElevenLabs API.
type ttsRequest struct {
	Text    string `json:"text"`
	ModelID string `json:"model_id"`
}

// GenerateSpeech converts text to speech audio using the ElevenLabs API.
// Returns the raw MP3 audio bytes.
func (s *Service) GenerateSpeech(ctx context.Context, text string, voiceID string) ([]byte, error) {
	body, err := json.Marshal(ttsRequest{
		Text:    text,
		ModelID: s.model,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TTS request: %w", err)
	}

	url := fmt.Sprintf("https://api.elevenlabs.io/v1/text-to-speech/%s", voiceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create TTS request: %w", err)
	}

	req.Header.Set("xi-api-key", s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "audio/mpeg")

	//nolint:gosec // G704: voiceID is from database (trusted), not user input
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("TTS API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	audio, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read TTS response: %w", err)
	}

	return audio, nil
}
