package services

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
// Must match maxItems in openapi.yaml (PronunciationRulesUpdate).
const MaxPronunciationRules = 1000

const maxPronunciationFieldRunes = 255

type pronunciationRuleLister interface {
	List(ctx context.Context) ([]models.PronunciationRule, error)
}

type pronunciationRuleRepo interface {
	pronunciationRuleLister
	ReplaceAll(ctx context.Context, rules []models.PronunciationRule) error
	MaxUpdatedAt(ctx context.Context) (*time.Time, error)
}

// PronunciationRulesService manages the global inline-IPA rule table.
type PronunciationRulesService struct {
	repo      pronunciationRuleRepo
	txManager repository.TxManager
}

// NewPronunciationRulesService binds pronunciation rule validation and persistence.
func NewPronunciationRulesService(
	repo pronunciationRuleRepo,
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
	Rules []models.PronunciationRule
	// UpdatedAt is nil when the rule table is empty.
	UpdatedAt *time.Time
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
	sortPronunciationRules(rules)

	var persistedRules []models.PronunciationRule
	var updatedAt *time.Time
	if err := s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.repo.ReplaceAll(ctx, rules); err != nil {
			return err
		}
		var err error
		persistedRules, err = s.repo.List(ctx)
		if err != nil {
			return fmt.Errorf("list_after_replace: %w", err)
		}
		updatedAt, err = s.repo.MaxUpdatedAt(ctx)
		if err != nil {
			return fmt.Errorf("max_updated_at: %w", err)
		}
		return nil
	}); err != nil {
		return nil, translatePronunciationRulesRepoError(apperrors.OpUpdate, err)
	}

	logPronunciationRulesAudit(req, len(persistedRules))
	return &PronunciationRulesResponse{
		Rules:     persistedRules,
		UpdatedAt: updatedAt,
	}, nil
}

func materializePronunciationRules(req *UpdatePronunciationRulesRequest) ([]models.PronunciationRule, error) {
	input := req.Rules

	var errs []apperrors.FieldError
	if len(input) > MaxPronunciationRules {
		errs = append(errs, fieldError("rules", apperrors.CodeTooLong, fmt.Sprintf("must contain at most %d rules", MaxPronunciationRules)))
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
		return nil, &apperrors.ValidationError{Errors: errs}
	}
	return rules, nil
}

func sortPronunciationRules(rules []models.PronunciationRule) {
	slices.SortFunc(rules, func(a, b models.PronunciationRule) int {
		return strings.Compare(a.StringToReplace, b.StringToReplace)
	})
}

func validatePronunciationTextField(field, value string, disallowSlash bool) []apperrors.FieldError {
	var errs []apperrors.FieldError
	if value == "" {
		errs = append(errs, fieldError(field, apperrors.CodeBlank, "cannot be empty or whitespace only"))
	}
	if utf8.RuneCountInString(value) > maxPronunciationFieldRunes {
		errs = append(errs, fieldError(field, apperrors.CodeTooLong, "must be at most 255 characters"))
	}
	if disallowSlash && strings.Contains(value, "/") {
		errs = append(errs, fieldError(field, apperrors.CodeInvalidFormat, "cannot contain forward slash"))
	}
	if strings.ContainsFunc(value, unicode.IsControl) {
		errs = append(errs, fieldError(field, apperrors.CodeInvalidFormat, "cannot contain control characters"))
	}
	return errs
}

func validatePronunciationRuleConflicts(rules []models.PronunciationRule) []apperrors.FieldError {
	var errs []apperrors.FieldError
	exact := make(map[string]int, len(rules))
	for i, rule := range rules {
		if previous, exists := exact[rule.StringToReplace]; exists {
			errs = append(errs, fieldError(
				fmt.Sprintf("rules[%d].string_to_replace", i),
				apperrors.CodeDuplicate,
				fmt.Sprintf("duplicates rules[%d]", previous),
			))
			continue
		}
		exact[rule.StringToReplace] = i
	}

	byLowercase := make(map[string]int, len(rules))
	for i, rule := range rules {
		key := strings.ToLower(rule.StringToReplace)
		previous, exists := byLowercase[key]
		if !exists {
			byLowercase[key] = i
			continue
		}
		if rules[previous].StringToReplace == rule.StringToReplace {
			continue
		}
		if !rule.CaseSensitive {
			errs = append(errs, fieldError(
				fmt.Sprintf("rules[%d].string_to_replace", i),
				apperrors.CodeDuplicate,
				fmt.Sprintf("conflicts with rules[%d] under case-insensitive matching", previous),
			))
			continue
		}
		if !rules[previous].CaseSensitive {
			errs = append(errs, fieldError(
				fmt.Sprintf("rules[%d].string_to_replace", previous),
				apperrors.CodeDuplicate,
				fmt.Sprintf("conflicts with rules[%d] under case-insensitive matching", i),
			))
		}
	}
	return errs
}

func translatePronunciationRulesRepoError(op apperrors.Operation, err error) error {
	if errors.Is(err, repository.ErrSchemaUnavailable) {
		return apperrors.NotInitialized(
			"pronunciation_rules",
			"apply migrations/001_complete_schema.sql or migrations/007_pronunciation_rules.sql",
			err,
		)
	}
	return apperrors.TranslateRepoError("PronunciationRules", op, err)
}

func logPronunciationRulesAudit(req *UpdatePronunciationRulesRequest, totalAfter int) {
	fields := map[string]any{
		"total_after": totalAfter,
	}
	if req.ActorUserID != nil {
		fields["user_id"] = *req.ActorUserID
	} else {
		fields["user_id"] = "unknown"
	}
	logger.WithFields(fields).Info("pronunciation rules updated")
}
