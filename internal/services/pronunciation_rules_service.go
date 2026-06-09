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
	StringToReplace string `json:"string_to_replace"`
	IPA             string `json:"ipa"`
	CaseSensitive   *bool  `json:"case_sensitive,omitempty"`
	WordBoundaries  *bool  `json:"word_boundaries,omitempty"`
}

// UpdatePronunciationRulesRequest carries a full replacement rule set.
type UpdatePronunciationRulesRequest struct {
	Rules       []PronunciationRuleUpdate `json:"rules" binding:"required"`
	ActorUserID *int64                    `json:"-"`
}

// PronunciationRulesResponse is the service-level response for both GET and PUT.
type PronunciationRulesResponse struct {
	Rules     []models.PronunciationRule
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

	var updatedAt *time.Time
	if err := s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.repo.ReplaceAll(ctx, rules); err != nil {
			return err
		}
		var err error
		updatedAt, err = s.repo.MaxUpdatedAt(ctx)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, translatePronunciationRulesRepoError(apperrors.OpUpdate, err)
	}

	logPronunciationRulesAudit(req, len(rules))
	return &PronunciationRulesResponse{
		Rules:     rules,
		UpdatedAt: updatedAt,
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

func sortPronunciationRules(rules []models.PronunciationRule) {
	slices.SortFunc(rules, func(a, b models.PronunciationRule) int {
		return strings.Compare(a.StringToReplace, b.StringToReplace)
	})
}

func validatePronunciationTextField(field, value string, disallowSlash bool) []apperrors.ValidationError {
	var errs []apperrors.ValidationError
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
	var errs []apperrors.ValidationError
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
				fmt.Sprintf("conflicts with rules[%d] under case-insensitive matching", previous),
			))
			continue
		}
		if !rules[previous].CaseSensitive {
			errs = append(errs, fieldError(
				fmt.Sprintf("rules[%d].string_to_replace", previous),
				fmt.Sprintf("conflicts with rules[%d] under case-insensitive matching", i),
			))
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
	return apperrors.TranslateRepoError("PronunciationRules", op, err)
}

func logPronunciationRulesAudit(req *UpdatePronunciationRulesRequest, totalAfter int) {
	fields := map[string]any{
		"total_after": totalAfter,
	}
	if req != nil && req.ActorUserID != nil {
		fields["user_id"] = *req.ActorUserID
	}
	logger.WithFields(fields).Info("pronunciation rules updated")
}
