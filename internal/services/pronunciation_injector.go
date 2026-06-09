package services

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// PronunciationInjector wraps matched story text terms in ElevenLabs v3 inline IPA tags.
type PronunciationInjector struct {
	repo *repository.PronunciationRuleRepository
}

// NewPronunciationInjector returns an inline-IPA injector backed by repo.
func NewPronunciationInjector(repo *repository.PronunciationRuleRepository) *PronunciationInjector {
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

	return applyPronunciationRules(text, rules), nil
}

func applyPronunciationRules(text string, rules []models.PronunciationRule) string {
	sortedRules := compileRulesForMatching(rules)
	input := []rune(text)
	var out strings.Builder
	out.Grow(len(text))

	for i := 0; i < len(input); {
		if rule, matched := matchRuleAt(input, i, sortedRules); matched {
			out.WriteByte('/')
			out.WriteString(rule.IPA)
			out.WriteByte('/')
			i += len(rule.pattern)
			continue
		}
		out.WriteRune(input[i])
		i++
	}

	return out.String()
}

type compiledPronunciationRule struct {
	models.PronunciationRule
	pattern []rune
}

func compileRulesForMatching(rules []models.PronunciationRule) []compiledPronunciationRule {
	compiled := make([]compiledPronunciationRule, 0, len(rules))
	for _, rule := range rules {
		compiled = append(compiled, compiledPronunciationRule{
			PronunciationRule: rule,
			pattern:           []rune(rule.StringToReplace),
		})
	}

	slices.SortFunc(compiled, func(a, b compiledPronunciationRule) int {
		if len(a.pattern) != len(b.pattern) {
			return len(b.pattern) - len(a.pattern)
		}
		return strings.Compare(a.StringToReplace, b.StringToReplace)
	})
	return compiled
}

func matchRuleAt(
	input []rune,
	pos int,
	rules []compiledPronunciationRule,
) (compiledPronunciationRule, bool) {
	for _, rule := range rules {
		if len(rule.pattern) == 0 {
			continue
		}
		if !ruleMatchesAt(input, pos, rule) {
			continue
		}
		return rule, true
	}
	return compiledPronunciationRule{}, false
}

func ruleMatchesAt(input []rune, pos int, rule compiledPronunciationRule) bool {
	if len(rule.pattern) == 0 || pos+len(rule.pattern) > len(input) {
		return false
	}

	if rule.WordBoundaries && !hasWordBoundaries(input, pos, len(rule.pattern)) {
		return false
	}

	segment := string(input[pos : pos+len(rule.pattern)])
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
