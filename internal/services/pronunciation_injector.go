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

// PronunciationInjector wraps matched story text terms in ElevenLabs v3 /<ipa>/ tags.
type PronunciationInjector struct {
	repo pronunciationRuleLister
}

// NewPronunciationInjector returns an inline-IPA injector backed by repo.
func NewPronunciationInjector(repo pronunciationRuleLister) *PronunciationInjector {
	if repo == nil {
		panic("services: NewPronunciationInjector requires a non-nil pronunciation rule repository")
	}
	return &PronunciationInjector{repo: repo}
}

// Apply wraps each match of any rule's string_to_replace in /<ipa>/.
// Empty input skips repository access, and replacements are non-recursive.
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

	// Compare rune-by-rune against the precompiled pattern instead of
	// materializing a substring per candidate check.
	for i, patternRune := range rule.pattern {
		inputRune := input[pos+i]
		if rule.CaseSensitive {
			if inputRune != patternRune {
				return false
			}
			continue
		}
		if !runesEqualFold(inputRune, patternRune) {
			return false
		}
	}
	return true
}

// runesEqualFold reports whether two runes are equal under Unicode simple
// case folding, mirroring the per-rune comparison of strings.EqualFold.
func runesEqualFold(sr, tr rune) bool {
	if sr == tr {
		return true
	}
	if tr < sr {
		tr, sr = sr, tr
	}
	// Fast path for ASCII: only uppercase letters fold to lowercase.
	if tr < utf8.RuneSelf {
		return 'A' <= sr && sr <= 'Z' && tr == sr+'a'-'A'
	}
	// General case: SimpleFold(x) returns the next rune in the fold orbit,
	// wrapping around, so walk sr's orbit looking for tr.
	r := unicode.SimpleFold(sr)
	for r != sr && r < tr {
		r = unicode.SimpleFold(r)
	}
	return r == tr
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
