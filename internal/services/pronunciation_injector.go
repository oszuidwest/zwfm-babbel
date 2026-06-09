package services

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// PronunciationRuleLister is the minimal repository dependency for IPA injection.
type PronunciationRuleLister interface {
	List(ctx context.Context) ([]models.PronunciationRule, error)
}

// PronunciationInjector wraps matched story text terms in ElevenLabs v3 inline IPA tags.
type PronunciationInjector struct {
	repo PronunciationRuleLister
}

// NewPronunciationInjector returns an inline-IPA injector backed by repo.
func NewPronunciationInjector(repo PronunciationRuleLister) *PronunciationInjector {
	return &PronunciationInjector{repo: repo}
}

// Apply wraps each match of any rule's string_to_replace in /<ipa>/.
func (p *PronunciationInjector) Apply(ctx context.Context, text string) (string, error) {
	if text == "" {
		return "", nil
	}

	rules, err := p.repo.List(ctx)
	if err != nil {
		return "", translatePronunciationInjectorRepoError(err)
	}
	if len(rules) == 0 {
		return text, nil
	}

	sortedRules := sortRulesForMatching(rules)
	input := []rune(text)
	var out strings.Builder
	out.Grow(len(text))

	for i := 0; i < len(input); {
		if rule, matched := matchRuleAt(input, i, sortedRules); matched {
			out.WriteByte('/')
			out.WriteString(rule.IPA)
			out.WriteByte('/')
			i += utf8.RuneCountInString(rule.StringToReplace)
			continue
		}
		out.WriteRune(input[i])
		i++
	}

	return out.String(), nil
}

func sortRulesForMatching(rules []models.PronunciationRule) []models.PronunciationRule {
	sortedRules := slices.Clone(rules)
	slices.SortFunc(sortedRules, func(a, b models.PronunciationRule) int {
		aLen := utf8.RuneCountInString(a.StringToReplace)
		bLen := utf8.RuneCountInString(b.StringToReplace)
		if aLen != bLen {
			return bLen - aLen
		}
		return strings.Compare(a.StringToReplace, b.StringToReplace)
	})
	return sortedRules
}

func matchRuleAt(
	input []rune,
	pos int,
	rules []models.PronunciationRule,
) (models.PronunciationRule, bool) {
	for _, rule := range rules {
		if rule.StringToReplace == "" {
			continue
		}
		if !ruleMatchesAt(input, pos, rule) {
			continue
		}
		return rule, true
	}
	return models.PronunciationRule{}, false
}

func ruleMatchesAt(input []rune, pos int, rule models.PronunciationRule) bool {
	pattern := []rune(rule.StringToReplace)
	if len(pattern) == 0 || pos+len(pattern) > len(input) {
		return false
	}

	if rule.WordBoundaries && !hasWordBoundaries(input, pos, len(pattern)) {
		return false
	}

	segment := string(input[pos : pos+len(pattern)])
	if rule.CaseSensitive {
		return segment == rule.StringToReplace
	}
	return strings.EqualFold(segment, rule.StringToReplace)
}

func hasWordBoundaries(input []rune, pos, patternLen int) bool {
	if pos > 0 && isWordChar(input[pos-1]) {
		return false
	}
	after := pos + patternLen
	if after < len(input) && isWordChar(input[after]) {
		return false
	}
	return true
}

func isWordChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func translatePronunciationInjectorRepoError(err error) error {
	if errors.Is(err, repository.ErrSchemaUnavailable) {
		return apperrors.NotInitialized(
			"pronunciation_rules",
			"apply migrations/001_complete_schema.sql or migrations/007_pronunciation_rules.sql",
			err,
		)
	}
	return apperrors.Database("PronunciationRules", "query", err)
}
