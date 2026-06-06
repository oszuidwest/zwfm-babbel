package services

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func TestValidateTTSSettingsUpdate(t *testing.T) {
	tooHigh := 1.5
	validZero := 0.0
	validSpeed := 0.7
	invalidSpeed := 0.69
	invalidModel := "eleven_turbo_v2_5"
	validModel := TTSModelElevenV3
	invalidNormalization := "sometimes"
	maxSeed := int64(maxElevenLabsSeedUint32)
	tooLargeSeed := maxSeed + 1
	tooLongPrefix := strings.Repeat("é", maxTTSStylePrefixRunes+1)

	tests := []struct {
		name       string
		req        *UpdateTTSSettingsRequest
		wantFields []string
	}{
		{
			name: "valid boundary values",
			req: &UpdateTTSSettingsRequest{
				Model:                  &validModel,
				Stability:              &validZero,
				Speed:                  &validSpeed,
				Seed:                   &maxSeed,
				ApplyTextNormalization: ptr(TTSNormalizationAuto),
				TTSStylePrefix:         ptr(strings.Repeat("é", maxTTSStylePrefixRunes)),
			},
		},
		{
			name: "aggregates invalid fields",
			req: &UpdateTTSSettingsRequest{
				Model:                  &invalidModel,
				Stability:              &tooHigh,
				Speed:                  &invalidSpeed,
				Seed:                   &tooLargeSeed,
				ApplyTextNormalization: &invalidNormalization,
				TTSStylePrefix:         &tooLongPrefix,
			},
			wantFields: []string{
				"model",
				"stability",
				"speed",
				"apply_text_normalization",
				"seed",
				"tts_style_prefix",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateTTSSettingsUpdate(tt.req)
			gotFields := make([]string, 0, len(errs))
			for _, err := range errs {
				gotFields = append(gotFields, err.Field)
			}
			if !slices.Equal(gotFields, tt.wantFields) {
				t.Fatalf("fields = %v, want %v", gotFields, tt.wantFields)
			}
		})
	}
}

func TestModelCharLimit(t *testing.T) {
	tests := []struct {
		model string
		want  int
	}{
		{model: TTSModelElevenV3, want: 5000},
		{model: TTSModelMultilingualV2, want: 10000},
		{model: TTSModelFlashV25, want: 40000},
		{model: "unknown", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			if got := modelCharLimit(tt.model); got != tt.want {
				t.Fatalf("modelCharLimit(%q) = %d, want %d", tt.model, got, tt.want)
			}
		})
	}
}

func TestTranslateTTSSettingsRepoError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantCode   string
		wantDetail string
		wantHint   string
	}{
		{
			name:       "schema unavailable",
			err:        repository.ErrSchemaUnavailable,
			wantDetail: "tts_settings not initialized",
			wantHint:   "apply migration 005_tts_settings.sql",
		},
		{
			name:       "singleton row missing",
			err:        repository.ErrNotFound,
			wantCode:   "tts_settings.row_missing",
			wantDetail: "tts_settings singleton row missing",
			wantHint:   "restore the id=1 row from migrations/005_tts_settings.sql seed data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translateTTSSettingsRepoError(tt.err)

			var notInitialized *apperrors.NotInitializedError
			if !errors.As(got, &notInitialized) {
				t.Fatalf("error type = %T, want *apperrors.NotInitializedError", got)
			}
			if !errors.Is(got, tt.err) {
				t.Fatalf("translated error does not wrap %v: %v", tt.err, got)
			}
			if notInitialized.Code != tt.wantCode {
				t.Fatalf("code = %q, want %q", notInitialized.Code, tt.wantCode)
			}
			if got.Error() != tt.wantDetail {
				t.Fatalf("detail = %q, want %q", got.Error(), tt.wantDetail)
			}
			if notInitialized.Hint != tt.wantHint {
				t.Fatalf("hint = %q, want %q", notInitialized.Hint, tt.wantHint)
			}
		})
	}
}

func ptr[T any](v T) *T {
	return &v
}
