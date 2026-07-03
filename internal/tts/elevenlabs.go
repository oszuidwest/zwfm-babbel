// Package tts provides text-to-speech integration with the ElevenLabs API.
package tts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const maxAudioResponseBytes int64 = 50 * 1024 * 1024 // 50 MiB safety cap
const maxErrorResponseBytes int64 = 1024
const defaultAPIBaseURL = "https://api.elevenlabs.io"
const outputFormatOpus48k128 = "opus_48000_128"

const (
	headerCurrentConcurrentRequests = "current-concurrent-requests"
	headerMaximumConcurrentRequests = "maximum-concurrent-requests"
)

const (
	// ModelV3 is the only ElevenLabs model Babbel supports for generated TTS.
	ModelV3 = "eleven_v3"

	// MaxV3InputChars is ElevenLabs' per-request character limit for v3.
	MaxV3InputChars = 5000
)

// APIError preserves ElevenLabs response details for service-layer translation.
type APIError struct {
	StatusCode int
	Body       string
	RetryAfter string
}

// Error returns the ElevenLabs failure message for the upstream status code.
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
}

// ttsRequest is the JSON body sent to the ElevenLabs API.
type ttsRequest struct {
	Text                   string        `json:"text"`
	ModelID                string        `json:"model_id"`
	VoiceSettings          VoiceSettings `json:"voice_settings"`
	ApplyTextNormalization string        `json:"apply_text_normalization"`
	Seed                   *uint32       `json:"seed,omitempty"`
}

type elevenLabsErrorDetail struct {
	Type      string
	Code      string
	RequestID string
}

type storyIDContextKey struct{}

// ContextWithStoryID returns a child context that adds story correlation to TTS failure logs.
func ContextWithStoryID(ctx context.Context, storyID int64) context.Context {
	if storyID <= 0 {
		return ctx
	}
	return context.WithValue(ctx, storyIDContextKey{}, storyID)
}

// GenerateSpeech converts text to speech audio using the ElevenLabs API.
// Returns the raw Opus audio bytes.
func (s *Service) GenerateSpeech(ctx context.Context, text string, voiceID string, opts Options) ([]byte, error) {
	body, err := json.Marshal(ttsRequest{
		Text:                   text,
		ModelID:                ModelV3,
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

	started := time.Now()
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("TTS API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorResponseBytes+1))
		var detail elevenLabsErrorDetail
		if readErr == nil {
			detail = parseElevenLabsErrorDetail(respBody)
		}
		logElevenLabsResponse(ctx, resp.StatusCode, time.Since(started), resp.Header, detail)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read TTS error response body for status %d: %w", resp.StatusCode, readErr)
		}
		if int64(len(respBody)) > maxErrorResponseBytes {
			respBody = append(respBody[:maxErrorResponseBytes], []byte(" (truncated)")...)
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

func parseElevenLabsErrorDetail(body []byte) elevenLabsErrorDetail {
	var payload struct {
		Detail json.RawMessage `json:"detail"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return elevenLabsErrorDetail{}
	}

	var detail struct {
		Type      string `json:"type"`
		Code      string `json:"code"`
		Status    string `json:"status"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(payload.Detail, &detail); err == nil {
		code := detail.Code
		if code == "" {
			code = detail.Status
		}
		return elevenLabsErrorDetail{
			Type:      cleanElevenLabsToken(detail.Type),
			Code:      cleanElevenLabsToken(code),
			RequestID: cleanElevenLabsToken(detail.RequestID),
		}
	}

	var detailMessage string
	if err := json.Unmarshal(payload.Detail, &detailMessage); err == nil {
		return elevenLabsErrorDetail{Code: cleanElevenLabsToken(detailMessage)}
	}
	return elevenLabsErrorDetail{}
}

func logElevenLabsResponse(
	ctx context.Context,
	statusCode int,
	duration time.Duration,
	header http.Header,
	detail elevenLabsErrorDetail,
) {
	fields := map[string]any{
		"status_code": statusCode,
		"duration_ms": duration.Milliseconds(),
	}
	if storyID, ok := storyIDFromContext(ctx); ok {
		fields["story_id"] = storyID
	}
	addNonEmptyField(fields, "retry_after", header.Get("Retry-After"))
	addNonEmptyField(fields, "elevenlabs_error_type", detail.Type)
	addNonEmptyField(fields, "elevenlabs_error_code", detail.Code)
	addNonEmptyField(fields, "elevenlabs_request_id", detail.RequestID)
	addNonEmptyField(fields, "current_concurrent_requests", concurrencyHeaderValue(header, headerCurrentConcurrentRequests))
	addNonEmptyField(fields, "maximum_concurrent_requests", concurrencyHeaderValue(header, headerMaximumConcurrentRequests))

	logger.WithFields(fields).Log(ctx, elevenLabsResponseLogLevel(statusCode), "elevenlabs tts response")
}

func storyIDFromContext(ctx context.Context) (int64, bool) {
	storyID, ok := ctx.Value(storyIDContextKey{}).(int64)
	return storyID, ok
}

func elevenLabsResponseLogLevel(statusCode int) slog.Level {
	switch {
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
		return slog.LevelError
	case statusCode >= http.StatusInternalServerError:
		return slog.LevelError
	case statusCode == http.StatusTooManyRequests || statusCode == http.StatusRequestTimeout:
		return slog.LevelWarn
	case statusCode >= http.StatusBadRequest:
		return slog.LevelInfo
	default:
		return slog.LevelWarn
	}
}

func concurrencyHeaderValue(header http.Header, key string) string {
	value := header.Get(key)
	if value == "" {
		return ""
	}
	count, err := strconv.Atoi(value)
	if err != nil || count < 0 {
		return ""
	}
	return strconv.Itoa(count)
}

func cleanElevenLabsToken(value string) string {
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return ""
		}
	}
	return value
}

func addNonEmptyField(fields map[string]any, key, value string) {
	if value != "" {
		fields[key] = value
	}
}
