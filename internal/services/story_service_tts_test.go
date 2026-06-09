package services

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
)

func TestComposeV3TTSText(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		prefix string
		want   string
	}{
		{
			name:   "applies non-empty prefix",
			text:   "Hallo",
			prefix: "[news anchor]",
			want:   "[news anchor]\nHallo",
		},
		{
			name:   "trims blank prefix",
			text:   "Hallo",
			prefix: "  \t\n",
			want:   "Hallo",
		},
		{
			name: "empty prefix",
			text: "Hallo",
			want: "Hallo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := composeV3TTSText(tt.text, tt.prefix); got != tt.want {
				t.Fatalf("composeV3TTSText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateTTSTextLength(t *testing.T) {
	withinLimit := strings.Repeat("é", tts.MaxV3InputChars)
	overLimit := withinLimit + "ë"

	if err := validateTTSTextLength(withinLimit); err != nil {
		t.Fatalf("validateTTSTextLength within limit returned error: %v", err)
	}

	err := validateTTSTextLength(overLimit)
	if err == nil {
		t.Fatal("validateTTSTextLength over limit returned nil")
	}

	var validationErr *apperrors.ValidationProblemError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error type = %T, want *apperrors.ValidationProblemError", err)
	}
	if validationErr.Resource != "story" || len(validationErr.Errors) != 1 || validationErr.Errors[0].Field != "text" {
		t.Fatalf("validation error = %#v, want one story.text error", validationErr)
	}

	wantMessage := "rune count " + strconv.Itoa(tts.MaxV3InputChars+1) +
		" exceeds limit " + strconv.Itoa(tts.MaxV3InputChars)
	if !strings.Contains(validationErr.Errors[0].Message, wantMessage) {
		t.Fatalf("message = %q, want %q", validationErr.Errors[0].Message, wantMessage)
	}
}

func TestTTSOptionsFromSettings(t *testing.T) {
	seed := uint32(42)

	options := ttsOptionsFromSettings(&models.TTSSettings{
		Stability:              0.8,
		SimilarityBoost:        0.7,
		Style:                  0.2,
		Speed:                  1.0,
		ApplyTextNormalization: TTSNormalizationAuto,
		Seed:                   &seed,
	})

	if options.Seed == nil || *options.Seed != seed {
		t.Fatalf("seed = %v, want %d", options.Seed, seed)
	}
	if options.ApplyTextNormalization != TTSNormalizationAuto {
		t.Fatalf("normalization = %q, want %q", options.ApplyTextNormalization, TTSNormalizationAuto)
	}
	if options.VoiceSettings.Stability != 0.8 ||
		options.VoiceSettings.SimilarityBoost != 0.7 ||
		options.VoiceSettings.Style != 0.2 ||
		options.VoiceSettings.Speed != 1.0 {
		t.Fatalf("voice settings = %#v", options.VoiceSettings)
	}
}

func TestTranslateTTSError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		assert func(t *testing.T, got error)
	}{
		{
			name: "unauthorized maps to upstream service unavailable",
			err:  &tts.APIError{StatusCode: http.StatusUnauthorized, Body: "bad key"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				assertUpstreamError(t, got, http.StatusServiceUnavailable)
			},
		},
		{
			name: "forbidden maps to upstream service unavailable",
			err:  &tts.APIError{StatusCode: http.StatusForbidden, Body: "forbidden"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				assertUpstreamError(t, got, http.StatusServiceUnavailable)
			},
		},
		{
			name: "voice not found maps to voice validation",
			err:  &tts.APIError{StatusCode: http.StatusNotFound, Body: "voice missing"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				assertValidationError(t, got, "Voice", "elevenlabs_voice_id")
			},
		},
		{
			name: "rate limited preserves retry after",
			err:  &tts.APIError{StatusCode: http.StatusTooManyRequests, Body: "slow down", RetryAfter: "45"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				var rateLimited *apperrors.RateLimitedError
				if !errors.As(got, &rateLimited) {
					t.Fatalf("error type = %T, want *apperrors.RateLimitedError", got)
				}
				if rateLimited.RetryAfter != "45" {
					t.Fatalf("RetryAfter = %q, want 45", rateLimited.RetryAfter)
				}
			},
		},
		{
			name: "unprocessable maps to request validation",
			err:  &tts.APIError{StatusCode: http.StatusUnprocessableEntity, Body: "invalid request"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				assertValidationError(t, got, "TTS", "request")
			},
		},
		{
			name: "server error maps to upstream bad gateway",
			err:  &tts.APIError{StatusCode: http.StatusInternalServerError, Body: "upstream failed"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				assertUpstreamError(t, got, http.StatusBadGateway)
			},
		},
		{
			name: "plain error maps to audio error",
			err:  errors.New("encoder failed"),
			assert: func(t *testing.T, got error) {
				t.Helper()
				var audioErr *apperrors.AudioError
				if !errors.As(got, &audioErr) {
					t.Fatalf("error type = %T, want *apperrors.AudioError", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translateTTSError(tt.err)
			if got == nil {
				t.Fatal("translateTTSError returned nil")
			}
			var apiErr *tts.APIError
			if errors.As(tt.err, &apiErr) && !errors.Is(got, tt.err) {
				t.Fatalf("translated error does not wrap original API error: %v", got)
			}
			tt.assert(t, got)
		})
	}
}

func assertUpstreamError(t *testing.T, got error, wantStatus int) {
	t.Helper()

	var upstream *apperrors.UpstreamError
	if !errors.As(got, &upstream) {
		t.Fatalf("error type = %T, want *apperrors.UpstreamError", got)
	}
	if upstream.Status != wantStatus {
		t.Fatalf("status = %d, want %d", upstream.Status, wantStatus)
	}
}

func assertValidationError(t *testing.T, got error, wantResource, wantField string) {
	t.Helper()

	var validation *apperrors.ValidationError
	if !errors.As(got, &validation) {
		t.Fatalf("error type = %T, want *apperrors.ValidationError", got)
	}
	if validation.Resource != wantResource || validation.Field != wantField {
		t.Fatalf("validation = %#v, want %s.%s", validation, wantResource, wantField)
	}
}
