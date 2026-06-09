package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// MaxPronunciationRules caps the number of inline-IPA rules saved in one set.
const MaxPronunciationRules = 1000

const maxPronunciationFieldRunes = 255

// PronunciationRulesService manages the global inline-IPA rule table.
type PronunciationRulesService struct {
	repo      *repository.PronunciationRuleRepository
	txManager repository.TxManager
}

// NewPronunciationRulesService binds pronunciation rule validation and persistence.
func NewPronunciationRulesService(
	repo *repository.PronunciationRuleRepository,
	txManager repository.TxManager,
) *PronunciationRulesService {
	return &PronunciationRulesService{
		repo:      repo,
		txManager: txManager,
	}
}

// PronunciationRuleUpdate carries one incoming rule before boolean defaults are materialized.
type PronunciationRuleUpdate struct {
	StringToReplace string
	IPA             string
	CaseSensitive   *bool
	WordBoundaries  *bool
}

// UpdatePronunciationRulesRequest carries a full replacement rule set.
type UpdatePronunciationRulesRequest struct {
	Rules       []PronunciationRuleUpdate
	ActorUserID *int64
}

// PronunciationRulesResponse is the service-level response for both GET and PUT.
type PronunciationRulesResponse struct {
	Rules     []models.PronunciationRule
	UpdatedAt *time.Time
}

type pronunciationRulesTxResult struct {
	before    []models.PronunciationRule
	after     []models.PronunciationRule
	updatedAt *time.Time
}

type pronunciationRulesDiff struct {
	added       int
	removed     int
	changed     int
	unchanged   int
	totalBefore int
	totalAfter  int
}

// Get returns the current local inline-IPA rules.
func (s *PronunciationRulesService) Get(ctx context.Context) (*PronunciationRulesResponse, error) {
	rules, err := s.repo.List(ctx)
	if err != nil {
		return nil, translatePronunciationRulesRepoError(apperrors.OpQuery, err)
	}
	updatedAt, err := s.repo.MaxUpdatedAt(ctx)
	if err != nil {
		return nil, translatePronunciationRulesRepoError(apperrors.OpQuery, err)
	}
	return &PronunciationRulesResponse{
		Rules:     rules,
		UpdatedAt: updatedAt,
	}, nil
}

// Update validates and replaces the full local inline-IPA rule set.
func (s *PronunciationRulesService) Update(
	ctx context.Context,
	req *UpdatePronunciationRulesRequest,
) (*PronunciationRulesResponse, error) {
	rules, err := materializePronunciationRules(req)
	if err != nil {
		return nil, err
	}

	var result pronunciationRulesTxResult
	if err := s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.repo.LockSingletonForWrite(ctx); err != nil {
			return err
		}

		before, err := s.repo.List(ctx)
		if err != nil {
			return err
		}
		if err := s.repo.ReplaceAll(ctx, rules); err != nil {
			return err
		}
		after, err := s.repo.List(ctx)
		if err != nil {
			return err
		}
		updatedAt, err := s.repo.MaxUpdatedAt(ctx)
		if err != nil {
			return err
		}

		result = pronunciationRulesTxResult{
			before:    before,
			after:     after,
			updatedAt: updatedAt,
		}
		return nil
	}); err != nil {
		return nil, translatePronunciationRulesRepoError(apperrors.OpUpdate, err)
	}

	logPronunciationRulesAudit(req, diffPronunciationRules(result.before, result.after))
	return &PronunciationRulesResponse{
		Rules:     result.after,
		UpdatedAt: result.updatedAt,
	}, nil
}

func materializePronunciationRules(req *UpdatePronunciationRulesRequest) ([]models.PronunciationRule, error) {
	input := []PronunciationRuleUpdate{}
	if req != nil {
		input = req.Rules
	}

	errs := []apperrors.ValidationError{}
	if len(input) > MaxPronunciationRules {
		errs = append(errs, fieldError("rules", fmt.Sprintf("must contain at most %d rules", MaxPronunciationRules)))
	}

	rules := make([]models.PronunciationRule, 0, len(input))
	for i, rule := range input {
		fieldPrefix := fmt.Sprintf("rules[%d]", i)
		stringToReplace := strings.TrimSpace(rule.StringToReplace)
		ipa := strings.TrimSpace(rule.IPA)

		errs = append(errs, validatePronunciationTextField(
			fieldPrefix+".string_to_replace",
			stringToReplace,
			false,
		)...)
		errs = append(errs, validatePronunciationTextField(fieldPrefix+".ipa", ipa, true)...)

		caseSensitive := true
		if rule.CaseSensitive != nil {
			caseSensitive = *rule.CaseSensitive
		}
		wordBoundaries := true
		if rule.WordBoundaries != nil {
			wordBoundaries = *rule.WordBoundaries
		}

		rules = append(rules, models.PronunciationRule{
			StringToReplace: stringToReplace,
			IPA:             ipa,
			CaseSensitive:   caseSensitive,
			WordBoundaries:  wordBoundaries,
		})
	}

	errs = append(errs, validatePronunciationRuleConflicts(rules)...)
	if len(errs) > 0 {
		return nil, apperrors.NewValidationProblemError(
			"pronunciation_rules",
			"One or more fields failed validation",
			errs,
		)
	}
	return rules, nil
}

func validatePronunciationTextField(field, value string, disallowSlash bool) []apperrors.ValidationError {
	errs := []apperrors.ValidationError{}
	if value == "" {
		errs = append(errs, fieldError(field, "cannot be empty or whitespace only"))
	}
	if utf8.RuneCountInString(value) > maxPronunciationFieldRunes {
		errs = append(errs, fieldError(field, "must be at most 255 characters"))
	}
	if disallowSlash && strings.Contains(value, "/") {
		errs = append(errs, fieldError(field, "cannot contain forward slash"))
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			errs = append(errs, fieldError(field, "cannot contain control characters"))
			break
		}
	}
	return errs
}

func validatePronunciationRuleConflicts(rules []models.PronunciationRule) []apperrors.ValidationError {
	errs := []apperrors.ValidationError{}
	exact := make(map[string]int, len(rules))
	for i, rule := range rules {
		if previous, exists := exact[rule.StringToReplace]; exists {
			errs = append(errs, fieldError(
				fmt.Sprintf("rules[%d].string_to_replace", i),
				fmt.Sprintf("duplicates rules[%d]", previous),
			))
			continue
		}
		exact[rule.StringToReplace] = i
	}

	for i, rule := range rules {
		if rule.CaseSensitive {
			continue
		}
		for j, other := range rules {
			if i == j || rule.StringToReplace == other.StringToReplace {
				continue
			}
			if strings.EqualFold(rule.StringToReplace, other.StringToReplace) {
				errs = append(errs, fieldError(
					fmt.Sprintf("rules[%d].string_to_replace", i),
					fmt.Sprintf("conflicts with rules[%d] under case-insensitive matching", j),
				))
				break
			}
		}
	}
	return errs
}

func translatePronunciationRulesRepoError(op apperrors.Operation, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, repository.ErrSchemaUnavailable) {
		return apperrors.NotInitialized(
			"pronunciation_rules",
			"apply migrations/001_complete_schema.sql or migrations/007_pronunciation_rules.sql",
			err,
		)
	}
	if errors.Is(err, repository.ErrNotFound) {
		return apperrors.NotInitializedWithCode(
			"tts_settings",
			"tts_settings.row_missing",
			"tts_settings singleton row missing",
			"restore the id=1 row from migrations/001_complete_schema.sql seed data",
			err,
		)
	}
	return apperrors.TranslateRepoError("PronunciationRules", op, err)
}

func diffPronunciationRules(before, after []models.PronunciationRule) pronunciationRulesDiff {
	beforeByTerm := make(map[string]models.PronunciationRule, len(before))
	for _, rule := range before {
		beforeByTerm[rule.StringToReplace] = rule
	}

	afterByTerm := make(map[string]models.PronunciationRule, len(after))
	for _, rule := range after {
		afterByTerm[rule.StringToReplace] = rule
	}

	diff := pronunciationRulesDiff{
		totalBefore: len(before),
		totalAfter:  len(after),
	}

	for term, afterRule := range afterByTerm {
		beforeRule, existed := beforeByTerm[term]
		if !existed {
			diff.added++
			continue
		}
		if pronunciationRuleContentEqual(beforeRule, afterRule) {
			diff.unchanged++
			continue
		}
		diff.changed++
	}

	for term := range beforeByTerm {
		if _, exists := afterByTerm[term]; !exists {
			diff.removed++
		}
	}

	return diff
}

func pronunciationRuleContentEqual(a, b models.PronunciationRule) bool {
	return a.IPA == b.IPA &&
		a.CaseSensitive == b.CaseSensitive &&
		a.WordBoundaries == b.WordBoundaries
}

func logPronunciationRulesAudit(req *UpdatePronunciationRulesRequest, diff pronunciationRulesDiff) {
	fields := map[string]any{
		"added":        diff.added,
		"removed":      diff.removed,
		"changed":      diff.changed,
		"unchanged":    diff.unchanged,
		"total_before": diff.totalBefore,
		"total_after":  diff.totalAfter,
	}
	if req != nil && req.ActorUserID != nil {
		fields["user_id"] = *req.ActorUserID
	}
	logger.WithFields(fields).Info("pronunciation rules updated")
}
