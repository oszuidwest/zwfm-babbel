package services

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func TestValidateTTSSettingsUpdate(t *testing.T) {
	tooHigh := 1.5
	validZero := 0.0
	validSpeed := 0.7
	invalidSpeed := 0.69
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
				Stability:              &tooHigh,
				Speed:                  &invalidSpeed,
				Seed:                   &tooLargeSeed,
				ApplyTextNormalization: &invalidNormalization,
				TTSStylePrefix:         &tooLongPrefix,
			},
			wantFields: []string{
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

func TestSeedUpdateValue(t *testing.T) {
	maxSeed := int64(maxElevenLabsSeedUint32)
	tooLargeSeed := maxSeed + 1

	tests := []struct {
		name string
		seed *int64
		want *uint32
	}{
		{
			name: "nil seed",
			seed: nil,
			want: nil,
		},
		{
			name: "zero",
			seed: ptr(int64(0)),
			want: ptr(uint32(0)),
		},
		{
			name: "max uint32",
			seed: &maxSeed,
			want: ptr(uint32(maxElevenLabsSeedUint32)),
		},
		{
			name: "negative",
			seed: ptr(int64(-1)),
			want: nil,
		},
		{
			name: "too large",
			seed: &tooLargeSeed,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := seedUpdateValue(tt.seed)
			switch {
			case tt.want == nil && got == nil:
				return
			case tt.want == nil || got == nil:
				t.Fatalf("seedUpdateValue() = %v, want %v", got, tt.want)
			case *got != *tt.want:
				t.Fatalf("seedUpdateValue() = %d, want %d", *got, *tt.want)
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
			wantHint:   "apply migrations/001_complete_schema.sql",
		},
		{
			name:       "singleton row missing",
			err:        repository.ErrNotFound,
			wantCode:   "tts_settings.row_missing",
			wantDetail: "tts_settings singleton row missing",
			wantHint:   "restore the id=1 row from migrations/001_complete_schema.sql seed data",
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

func TestBuildTTSSettingsAuditFields_RecordsOldAndNewValues(t *testing.T) {
	actor := int64(7)
	newPrefix := "[news anchor]"
	req := &UpdateTTSSettingsRequest{
		TTSStylePrefix: &newPrefix,
		ActorUserID:    &actor,
	}

	before := &models.TTSSettings{
		TTSStylePrefix: "[professional]",
	}
	after := &models.TTSSettings{
		TTSStylePrefix: newPrefix,
	}

	fields := buildTTSSettingsAuditFields(req, before, after)

	if fields == nil {
		t.Fatal("expected audit fields, got nil")
	}

	want := map[string]any{
		"changed_fields":       []string{"tts_style_prefix"},
		"old_tts_style_prefix": "[professional]",
		"new_tts_style_prefix": newPrefix,
		"user_id":              actor,
	}

	for key, expected := range want {
		got, ok := fields[key]
		if !ok {
			t.Fatalf("missing audit field %q in %#v", key, fields)
		}
		if slice, isSlice := expected.([]string); isSlice {
			gotSlice, ok := got.([]string)
			if !ok || !slices.Equal(gotSlice, slice) {
				t.Fatalf("audit[%q] = %#v, want %#v", key, got, slice)
			}
			continue
		}
		if got != expected {
			t.Fatalf("audit[%q] = %#v, want %#v", key, got, expected)
		}
	}
}

func TestBuildTTSSettingsAuditFields_NoChangeReturnsNil(t *testing.T) {
	noop := &UpdateTTSSettingsRequest{}
	before := &models.TTSSettings{}
	after := &models.TTSSettings{}

	if fields := buildTTSSettingsAuditFields(noop, before, after); fields != nil {
		t.Fatalf("expected nil for no-change update, got %#v", fields)
	}
}

func ptr[T any](v T) *T {
	return &v
}
