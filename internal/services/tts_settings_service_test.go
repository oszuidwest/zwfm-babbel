package services

import (
	"slices"
	"strings"
	"testing"
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

func ptr[T any](v T) *T {
	return &v
}
