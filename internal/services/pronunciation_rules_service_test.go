package services

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func TestMaterializePronunciationRulesDefaultsAndTrimming(t *testing.T) {
	rules, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
		Rules: []PronunciationRuleUpdate{{
			StringToReplace: "  PSV  ",
			IPA:             "  piː ɛs veː  ",
		}},
	})
	if err != nil {
		t.Fatalf("materializePronunciationRules() error = %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(rules))
	}
	rule := rules[0]
	if rule.StringToReplace != "PSV" || rule.IPA != "piː ɛs veː" {
		t.Fatalf("rule = %#v, want trimmed term and IPA", rule)
	}
	if !rule.CaseSensitive || !rule.WordBoundaries {
		t.Fatalf("defaults = %t/%t, want true/true", rule.CaseSensitive, rule.WordBoundaries)
	}
}

func TestMaterializePronunciationRulesPreservesFalseFlags(t *testing.T) {
	rules, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
		Rules: []PronunciationRuleUpdate{{
			StringToReplace: "PSV",
			IPA:             "piː ɛs veː",
			CaseSensitive:   ptr(false),
			WordBoundaries:  ptr(false),
		}},
	})
	if err != nil {
		t.Fatalf("materializePronunciationRules() error = %v", err)
	}
	if rules[0].CaseSensitive || rules[0].WordBoundaries {
		t.Fatalf("flags = %t/%t, want false/false", rules[0].CaseSensitive, rules[0].WordBoundaries)
	}
}

func TestMaterializePronunciationRulesAcceptsRealisticIPA(t *testing.T) {
	validIPA := []string{
		"ˈstreːkɔmˌrupə",
		"piː ɛs veː",
		"ˈɑlkmaːr ˈzɑːnstreːk",
		"ˌbaɪoʊˈkemɪstri",
		"ˈæktʃuəli",
	}

	for _, ipa := range validIPA {
		t.Run(ipa, func(t *testing.T) {
			_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
				Rules: []PronunciationRuleUpdate{{StringToReplace: "term", IPA: ipa}},
			})
			if err != nil {
				t.Fatalf("materializePronunciationRules() error = %v", err)
			}
		})
	}
}

func TestMaterializePronunciationRulesValidation(t *testing.T) {
	long := strings.Repeat("é", maxPronunciationFieldRunes+1)
	maxWithDiacritics := strings.Repeat("é", maxPronunciationFieldRunes)

	tests := []struct {
		name      string
		rule      PronunciationRuleUpdate
		wantField string
	}{
		{
			name:      "empty string_to_replace",
			rule:      PronunciationRuleUpdate{StringToReplace: " ", IPA: "piː"},
			wantField: "rules[0].string_to_replace",
		},
		{
			name:      "empty ipa",
			rule:      PronunciationRuleUpdate{StringToReplace: "PSV", IPA: " "},
			wantField: "rules[0].ipa",
		},
		{
			name:      "slash in ipa",
			rule:      PronunciationRuleUpdate{StringToReplace: "PSV", IPA: "piː/ɛs"},
			wantField: "rules[0].ipa",
		},
		{
			name:      "control character in string_to_replace",
			rule:      PronunciationRuleUpdate{StringToReplace: "P\nSV", IPA: "piː"},
			wantField: "rules[0].string_to_replace",
		},
		{
			name:      "control character in ipa",
			rule:      PronunciationRuleUpdate{StringToReplace: "PSV", IPA: "piː\u0085x"},
			wantField: "rules[0].ipa",
		},
		{
			name:      "term too long",
			rule:      PronunciationRuleUpdate{StringToReplace: long, IPA: "piː"},
			wantField: "rules[0].string_to_replace",
		},
		{
			name:      "ipa too long",
			rule:      PronunciationRuleUpdate{StringToReplace: "PSV", IPA: long},
			wantField: "rules[0].ipa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
				Rules: []PronunciationRuleUpdate{tt.rule},
			})
			assertPronunciationValidationField(t, err, tt.wantField)
		})
	}

	t.Run("255 runes with diacritics accepted", func(t *testing.T) {
		_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
			Rules: []PronunciationRuleUpdate{{StringToReplace: maxWithDiacritics, IPA: maxWithDiacritics}},
		})
		if err != nil {
			t.Fatalf("materializePronunciationRules() error = %v", err)
		}
	})
}

func TestMaterializePronunciationRulesConflicts(t *testing.T) {
	tests := []struct {
		name        string
		rules       []PronunciationRuleUpdate
		wantField   string
		wantMessage string
	}{
		{
			name: "byte exact duplicate",
			rules: []PronunciationRuleUpdate{
				{StringToReplace: "PSV", IPA: "one"},
				{StringToReplace: "PSV", IPA: "two"},
			},
			wantField:   "rules[1].string_to_replace",
			wantMessage: "duplicates rules[0]",
		},
		{
			name: "case insensitive shadow",
			rules: []PronunciationRuleUpdate{
				{StringToReplace: "PSV", IPA: "one", CaseSensitive: ptr(false)},
				{StringToReplace: "psv", IPA: "two"},
			},
			wantField:   "rules[0].string_to_replace",
			wantMessage: "conflicts with rules[1] under case-insensitive matching",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{Rules: tt.rules})

			var validationErr *apperrors.ValidationProblemError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error type = %T, want *apperrors.ValidationProblemError", err)
			}
			if !slices.ContainsFunc(validationErr.Errors, func(e apperrors.ValidationError) bool {
				return e.Field == tt.wantField && e.Message == tt.wantMessage
			}) {
				t.Fatalf("errors = %#v, want %s %q", validationErr.Errors, tt.wantField, tt.wantMessage)
			}
		})
	}
}

func TestMaterializePronunciationRulesMaxRules(t *testing.T) {
	rules := make([]PronunciationRuleUpdate, MaxPronunciationRules+1)
	for i := range rules {
		rules[i] = PronunciationRuleUpdate{
			StringToReplace: "term-" + string(rune('a'+(i%26))) + "-" + strings.Repeat("x", i/26),
			IPA:             "ipa",
		}
	}

	_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{Rules: rules})
	assertPronunciationValidationField(t, err, "rules")
}

func TestTranslatePronunciationRulesRepoError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantError any
	}{
		{
			name:      "schema unavailable",
			err:       repository.ErrSchemaUnavailable,
			wantError: &apperrors.NotInitializedError{},
		},
		{
			name:      "generic repo error",
			err:       errors.New("db failed"),
			wantError: &apperrors.DatabaseError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translatePronunciationRulesRepoError(apperrors.OpUpdate, tt.err)
			switch target := tt.wantError.(type) {
			case *apperrors.NotInitializedError:
				if !errors.As(got, &target) {
					t.Fatalf("error type = %T, want *apperrors.NotInitializedError", got)
				}
			case *apperrors.DatabaseError:
				if !errors.As(got, &target) {
					t.Fatalf("error type = %T, want *apperrors.DatabaseError", got)
				}
			default:
				t.Fatalf("unhandled target type %T", target)
			}
		})
	}
}

func assertPronunciationValidationField(t *testing.T, err error, wantField string) {
	t.Helper()

	var validationErr *apperrors.ValidationProblemError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error type = %T, want *apperrors.ValidationProblemError", err)
	}
	if !slices.ContainsFunc(validationErr.Errors, func(e apperrors.ValidationError) bool {
		return e.Field == wantField
	}) {
		t.Fatalf("errors = %#v, want field %q", validationErr.Errors, wantField)
	}
}
