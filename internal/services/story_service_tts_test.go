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

func TestComposeTTSText(t *testing.T) {
	tests := []struct {
		name     string
		settings *models.TTSSettings
		text     string
		want     string
	}{
		{
			name: "applies prefix for eleven v3",
			settings: &models.TTSSettings{
				Model:          TTSModelElevenV3,
				TTSStylePrefix: "[news anchor]",
			},
			text: "Hallo",
			want: "[news anchor]\nHallo",
		},
		{
			name: "drops prefix for multilingual v2",
			settings: &models.TTSSettings{
				Model:          TTSModelMultilingualV2,
				TTSStylePrefix: "[news anchor]",
			},
			text: "Hallo",
			want: "Hallo",
		},
		{
			name: "trims blank prefix",
			settings: &models.TTSSettings{
				Model:          TTSModelElevenV3,
				TTSStylePrefix: "  \t\n",
			},
			text: "Hallo",
			want: "Hallo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := composeTTSText(tt.text, tt.settings); got != tt.want {
				t.Fatalf("composeTTSText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateTTSTextLength(t *testing.T) {
	tests := []struct {
		model string
		limit int
	}{
		{model: TTSModelElevenV3, limit: 5000},
		{model: TTSModelMultilingualV2, limit: 10000},
		{model: TTSModelFlashV25, limit: 40000},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			withinLimit := strings.Repeat("é", tt.limit)
			overLimit := withinLimit + "ë"

			if err := validateTTSTextLength(withinLimit, tt.model); err != nil {
				t.Fatalf("validateTTSTextLength within limit returned error: %v", err)
			}

			err := validateTTSTextLength(overLimit, tt.model)
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

			wantMessage := "rune count " + strconv.Itoa(tt.limit+1) + " exceeds limit " + strconv.Itoa(tt.limit)
			if !strings.Contains(validationErr.Errors[0].Message, wantMessage) {
				t.Fatalf("message = %q, want %q", validationErr.Errors[0].Message, wantMessage)
			}
		})
	}
}

func TestValidateTTSTextLength_UnknownModel(t *testing.T) {
	err := validateTTSTextLength("Hallo", "eleven_future_v1")
	if err == nil {
		t.Fatal("validateTTSTextLength unknown model returned nil")
	}

	var dbErr *apperrors.DatabaseError
	if !errors.As(err, &dbErr) {
		t.Fatalf("error type = %T, want *apperrors.DatabaseError", err)
	}
	if dbErr.Resource != "TTSSettings" || dbErr.Operation != "validate" {
		t.Fatalf("database error = %#v, want TTSSettings validate", dbErr)
	}
}

func TestTTSOptionsFromSettings(t *testing.T) {
	seed := uint32(42)

	v3Options := ttsOptionsFromSettings(&models.TTSSettings{
		Model:                  TTSModelElevenV3,
		Stability:              0.8,
		SimilarityBoost:        0.7,
		Style:                  0.2,
		Speed:                  1.0,
		UseSpeakerBoost:        true,
		ApplyTextNormalization: TTSNormalizationAuto,
		Seed:                   &seed,
	})
	if v3Options.VoiceSettings.UseSpeakerBoost != nil {
		t.Fatal("eleven_v3 options included use_speaker_boost")
	}
	if v3Options.Seed == nil || *v3Options.Seed != seed {
		t.Fatalf("seed = %v, want %d", v3Options.Seed, seed)
	}

	v2Options := ttsOptionsFromSettings(&models.TTSSettings{
		Model:           TTSModelMultilingualV2,
		UseSpeakerBoost: false,
	})
	if v2Options.VoiceSettings.UseSpeakerBoost == nil {
		t.Fatal("multilingual v2 options omitted use_speaker_boost")
	}
	if *v2Options.VoiceSettings.UseSpeakerBoost {
		t.Fatal("multilingual v2 use_speaker_boost = true, want false")
	}

	flashOptions := ttsOptionsFromSettings(&models.TTSSettings{
		Model:           TTSModelFlashV25,
		UseSpeakerBoost: true,
	})
	if flashOptions.VoiceSettings.UseSpeakerBoost == nil {
		t.Fatal("flash v2.5 options omitted use_speaker_boost")
	}
	if !*flashOptions.VoiceSettings.UseSpeakerBoost {
		t.Fatal("flash v2.5 use_speaker_boost = false, want true")
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

	var validationErr *apperrors.ValidationError
	if !errors.As(got, &validationErr) {
		t.Fatalf("error type = %T, want *apperrors.ValidationError", got)
	}
	if validationErr.Resource != wantResource || validationErr.Field != wantField {
		t.Fatalf("validation error = %#v, want %s.%s", validationErr, wantResource, wantField)
	}
}
