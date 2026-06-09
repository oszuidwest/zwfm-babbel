package services

import (
	"context"
	"errors"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func TestApplyPronunciationRules(t *testing.T) {
	tests := []struct {
		name  string
		rules []models.PronunciationRule
		input string
		want  string
	}{
		{
			name:  "single rule",
			rules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", true, true)},
			input: "PSV wint",
			want:  "/piː ɛs veː/ wint",
		},
		{
			name:  "multi-word rule",
			rules: []models.PronunciationRule{rule("Albert Heijn", "ˈɑlbərt ˈɦɛin", true, true)},
			input: "Albert Heijn opent",
			want:  "/ˈɑlbərt ˈɦɛin/ opent",
		},
		{
			name: "longest match wins",
			rules: []models.PronunciationRule{
				rule("PSV", "short", true, true),
				rule("PSV Eindhoven", "long", true, true),
			},
			input: "PSV Eindhoven scoort",
			want:  "/long/ scoort",
		},
		{
			name:  "case-sensitive mismatch",
			rules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", true, true)},
			input: "psv wint",
			want:  "psv wint",
		},
		{
			name:  "case-insensitive match",
			rules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", false, true)},
			input: "psv wint",
			want:  "/piː ɛs veː/ wint",
		},
		{
			name:  "word boundary blocks middle of word",
			rules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", false, true)},
			input: "topsvclub",
			want:  "topsvclub",
		},
		{
			name:  "word boundary disabled matches middle of word",
			rules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", false, false)},
			input: "topsvclub",
			want:  "to/piː ɛs veː/club",
		},
		{
			name:  "apostrophe and hyphen are boundaries",
			rules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", true, true)},
			input: "PSV-fan PSV's",
			want:  "/piː ɛs veː/-fan /piː ɛs veː/'s",
		},
		{
			name:  "diacritics count as word characters",
			rules: []models.PronunciationRule{rule("een", "eːn", true, true)},
			input: "één",
			want:  "één",
		},
		{
			name:  "slash wrapped match is not skipped",
			rules: []models.PronunciationRule{rule("psv", "piː ɛs veː", false, true)},
			input: "nieuws /psv/ uitslag",
			want:  "nieuws //piː ɛs veː// uitslag",
		},
		{
			name:  "date fragment is preserved",
			rules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", true, true)},
			input: "PSV 2025/26",
			want:  "/piː ɛs veː/ 2025/26",
		},
		{
			name:  "case-sensitive URL fragment does not match",
			rules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", true, true)},
			input: "www.psv.nl",
			want:  "www.psv.nl",
		},
		{
			name:  "case-insensitive URL fragment matches",
			rules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", false, true)},
			input: "www.psv.nl",
			want:  "www./piː ɛs veː/.nl",
		},
		{
			name: "non-recursive output",
			rules: []models.PronunciationRule{
				rule("PSV", "AZ", true, true),
				rule("AZ", "aː zɛt", true, true),
			},
			input: "PSV",
			want:  "/AZ/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyPronunciationRules(tt.input, tt.rules)
			if got != tt.want {
				t.Fatalf("applyPronunciationRules() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyPronunciationRulesNoRulesReturnsInput(t *testing.T) {
	got := applyPronunciationRules("PSV wint", nil)
	if got != "PSV wint" {
		t.Fatalf("applyPronunciationRules() = %q, want unchanged input", got)
	}
}

func TestTranslatePronunciationInjectorRepoError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantError any
	}{
		{name: "schema unavailable", err: repository.ErrSchemaUnavailable, wantError: &apperrors.NotInitializedError{}},
		{name: "generic db error", err: errors.New("db failed"), wantError: &apperrors.DatabaseError{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := translatePronunciationInjectorRepoError(tt.err)

			switch target := tt.wantError.(type) {
			case *apperrors.NotInitializedError:
				if !errors.As(err, &target) {
					t.Fatalf("error type = %T, want *apperrors.NotInitializedError", err)
				}
			case *apperrors.DatabaseError:
				if !errors.As(err, &target) {
					t.Fatalf("error type = %T, want *apperrors.DatabaseError", err)
				}
			default:
				t.Fatalf("unhandled target type %T", target)
			}
		})
	}
}

func TestPronunciationInjectorApplyEmptyInputSkipsRepo(t *testing.T) {
	injector := NewPronunciationInjector(nil)
	got, err := injector.Apply(context.Background(), "")
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if got != "" {
		t.Fatalf("Apply() = %q, want empty", got)
	}
}

func rule(term, ipa string, caseSensitive, wordBoundaries bool) models.PronunciationRule {
	return models.PronunciationRule{
		StringToReplace: term,
		IPA:             ipa,
		CaseSensitive:   caseSensitive,
		WordBoundaries:  wordBoundaries,
	}
}
