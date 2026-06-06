package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
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
	const limit = 5000
	withinLimit := strings.Repeat("é", limit)
	overLimit := withinLimit + "ë"

	if err := validateTTSTextLength(withinLimit, TTSModelElevenV3); err != nil {
		t.Fatalf("validateTTSTextLength within limit returned error: %v", err)
	}

	err := validateTTSTextLength(overLimit, TTSModelElevenV3)
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
	if !strings.Contains(validationErr.Errors[0].Message, "rune count 5001 exceeds limit 5000") {
		t.Fatalf("message = %q, want rune-count overflow detail", validationErr.Errors[0].Message)
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
}
