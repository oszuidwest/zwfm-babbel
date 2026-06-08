package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// ManagedPronunciationDictionaryName is the name Babbel uses for the singleton
// pronunciation dictionary it creates on ElevenLabs. Exported so other packages
// (e.g. story_service error messages) reference one source of truth.
const ManagedPronunciationDictionaryName = "Babbel"

// MaxPronunciationRules caps the number of rules accepted in a single Update so
// a malformed or malicious request cannot exhaust memory before reaching
// ElevenLabs. Chosen to comfortably exceed any realistic editorial workflow.
const MaxPronunciationRules = 5000

const (
	managedPronunciationDictionaryDescription = "Auto-managed by " + ManagedPronunciationDictionaryName

	missingPronunciationDictionaryWarning = "The " + ManagedPronunciationDictionaryName +
		" dictionary on ElevenLabs is missing; it will be recreated on the next save."
)

var errPronunciationDictionaryChangedConcurrently = errors.New("pronunciation dictionary id changed concurrently")

type pronunciationRulesAuditAction string

const (
	pronunciationRulesAuditActionInit         pronunciationRulesAuditAction = "init"
	pronunciationRulesAuditActionIDCleared    pronunciationRulesAuditAction = "id_cleared"
	pronunciationRulesAuditActionRulesReplace pronunciationRulesAuditAction = "rules_replace"
)

// PronunciationRulesService manages the flat editor-facing rule list backed by
// a single ElevenLabs pronunciation dictionary.
type PronunciationRulesService struct {
	settingsRepo pronunciationSettingsRepository
	client       tts.PronunciationDictionaryClient
}

type pronunciationSettingsRepository interface {
	Get(ctx context.Context) (*models.TTSSettings, error)
	CompareAndSetPronunciationDictionaryID(ctx context.Context, currentID *string, id *string) (bool, error)
}

// NewPronunciationRulesService returns a service that stores the managed
// dictionary ID in settingsRepo and performs upstream dictionary calls through client.
func NewPronunciationRulesService(
	settingsRepo *repository.TTSSettingsRepository,
	client tts.PronunciationDictionaryClient,
) *PronunciationRulesService {
	return &PronunciationRulesService{
		settingsRepo: settingsRepo,
		client:       client,
	}
}

// PronunciationRuleUpdate carries one incoming alias rule before boolean
// defaults are materialised.
type PronunciationRuleUpdate struct {
	StringToReplace string
	Alias           string
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
	Rules           []tts.Rule
	LatestVersionID *string
	CreatedAt       *time.Time
	Warning         *string
}

type pronunciationRulesAuditEvent struct {
	Action       pronunciationRulesAuditAction
	ActorUserID  *int64
	DictionaryID string
	Added        int
	Removed      int
	Changed      int
	Unchanged    int
	TotalBefore  int
	TotalAfter   int
}

type pronunciationRulesDiff struct {
	Added       int
	Removed     int
	Changed     int
	Unchanged   int
	TotalBefore int
	TotalAfter  int
}

// Get returns the current alias rules from ElevenLabs.
// It returns an empty rule list when no dictionary has been created yet, and an
// empty list with a warning when the stored dictionary is missing upstream.
func (s *PronunciationRulesService) Get(ctx context.Context) (*PronunciationRulesResponse, error) {
	settings, err := s.settingsRepo.Get(ctx)
	if err != nil {
		return nil, translateTTSSettingsRepoError(err)
	}

	if settings.PronunciationDictionaryID == nil || *settings.PronunciationDictionaryID == "" {
		return emptyPronunciationRulesResponse(), nil
	}

	state, err := s.client.GetDictionary(ctx, *settings.PronunciationDictionaryID)
	if err != nil {
		if errors.Is(err, tts.ErrDictionaryNotFound) {
			response := emptyPronunciationRulesResponse()
			response.Warning = stringPtr(missingPronunciationDictionaryWarning)
			return response, nil
		}
		return nil, translatePronunciationRulesUpstreamError(err)
	}

	return pronunciationRulesResponseFromState(state), nil
}

// Update validates and replaces the full alias-rule set.
// It creates the managed ElevenLabs dictionary on first write or after a missing
// upstream dictionary, and records audit details for successful changes.
func (s *PronunciationRulesService) Update(
	ctx context.Context,
	req *UpdatePronunciationRulesRequest,
) (*PronunciationRulesResponse, error) {
	rules, err := materializePronunciationRules(req)
	if err != nil {
		return nil, err
	}

	settings, err := s.settingsRepo.Get(ctx)
	if err != nil {
		return nil, translateTTSSettingsRepoError(err)
	}

	actorID := actorUserID(req)

	if settings.PronunciationDictionaryID == nil || *settings.PronunciationDictionaryID == "" {
		return s.runCreatePath(ctx, rules, nil, actorID)
	}

	currentID := *settings.PronunciationDictionaryID
	baseline, err := s.client.GetDictionary(ctx, currentID)
	if err != nil {
		if errors.Is(err, tts.ErrDictionaryNotFound) {
			return s.runCreatePath(ctx, rules, &currentID, actorID)
		}
		return nil, translatePronunciationRulesUpstreamError(err)
	}

	result, err := s.client.SetRules(ctx, currentID, rules)
	if err != nil {
		if errors.Is(err, tts.ErrDictionaryNotFound) {
			return s.runCreatePath(ctx, rules, &currentID, actorID)
		}
		return nil, translatePronunciationRulesUpstreamError(err)
	}

	diff := diffPronunciationRules(baseline.Rules, rules)
	logPronunciationRulesAudit(pronunciationRulesAuditEvent{
		Action:       pronunciationRulesAuditActionRulesReplace,
		ActorUserID:  actorID,
		DictionaryID: currentID,
		Added:        diff.Added,
		Removed:      diff.Removed,
		Changed:      diff.Changed,
		Unchanged:    diff.Unchanged,
		TotalBefore:  diff.TotalBefore,
		TotalAfter:   diff.TotalAfter,
	})

	return &PronunciationRulesResponse{
		Rules:           rules,
		LatestVersionID: stringPtr(result.LatestVersionID),
		CreatedAt:       timePtr(baseline.CreationTime),
	}, nil
}

func (s *PronunciationRulesService) runCreatePath(
	ctx context.Context,
	rules []tts.Rule,
	currentID *string,
	actorID *int64,
) (*PronunciationRulesResponse, error) {
	if len(rules) == 0 {
		if currentID == nil {
			return emptyPronunciationRulesResponse(), nil
		}
		updated, err := s.settingsRepo.CompareAndSetPronunciationDictionaryID(ctx, currentID, nil)
		if err != nil {
			return nil, translatePronunciationRulesRepoWriteError("clear_dictionary_id", err)
		}
		if !updated {
			return nil, pronunciationDictionaryChangedConcurrentlyError()
		}
		logPronunciationRulesAudit(pronunciationRulesAuditEvent{
			Action:       pronunciationRulesAuditActionIDCleared,
			ActorUserID:  actorID,
			DictionaryID: *currentID,
			TotalAfter:   0,
		})
		return emptyPronunciationRulesResponse(), nil
	}

	state, err := s.client.CreateDictionaryFromRules(
		ctx,
		ManagedPronunciationDictionaryName,
		managedPronunciationDictionaryDescription,
		rules,
	)
	if err != nil {
		return nil, translatePronunciationRulesUpstreamError(err)
	}

	newID := strings.TrimSpace(state.ID)
	if newID == "" {
		return nil, translatePronunciationRulesUpstreamError(
			errors.New("pronunciation dictionary create response missing id"),
		)
	}

	updated, err := s.settingsRepo.CompareAndSetPronunciationDictionaryID(ctx, currentID, &newID)
	if err != nil {
		logger.Error(
			"orphan pronunciation dictionary: created on ElevenLabs but DB persist failed; manual cleanup required",
			"dictionary_id", newID,
			"error", err.Error(),
		)
		return nil, translatePronunciationRulesRepoWriteError("persist_dictionary_id", err)
	}
	if !updated {
		logger.Error(
			"orphan pronunciation dictionary: created on ElevenLabs but DB pointer changed concurrently; manual cleanup required",
			"dictionary_id", newID,
		)
		return nil, pronunciationDictionaryChangedConcurrentlyError()
	}

	logPronunciationRulesAudit(pronunciationRulesAuditEvent{
		Action:       pronunciationRulesAuditActionInit,
		ActorUserID:  actorID,
		DictionaryID: newID,
		TotalAfter:   len(rules),
	})
	response := pronunciationRulesResponseFromState(state)
	response.Rules = rules
	return response, nil
}

func pronunciationDictionaryChangedConcurrentlyError() error {
	return apperrors.ConflictWithCode(
		"PronunciationRules",
		"pronunciation_rules.conflict",
		"Pronunciation dictionary changed concurrently",
		"Another request changed the pronunciation dictionary; reload and try again",
		errPronunciationDictionaryChangedConcurrently,
	)
}

func materializePronunciationRules(req *UpdatePronunciationRulesRequest) ([]tts.Rule, error) {
	if req == nil || req.Rules == nil {
		return nil, apperrors.NewValidationProblemError(
			"pronunciation_rules",
			"One or more fields failed validation",
			[]apperrors.ValidationError{fieldError("rules", "is required")},
		)
	}

	if len(req.Rules) > MaxPronunciationRules {
		return nil, apperrors.NewValidationProblemError(
			"pronunciation_rules",
			"One or more fields failed validation",
			[]apperrors.ValidationError{fieldError(
				"rules",
				fmt.Sprintf("exceeds maximum of %d entries (got %d)", MaxPronunciationRules, len(req.Rules)),
			)},
		)
	}

	errs := []apperrors.ValidationError{}
	seen := map[string]int{}
	rules := make([]tts.Rule, 0, len(req.Rules))

	for i, rule := range req.Rules {
		fieldPrefix := fmt.Sprintf("rules[%d]", i)
		stringToReplace := strings.TrimSpace(rule.StringToReplace)
		alias := strings.TrimSpace(rule.Alias)

		if stringToReplace == "" {
			errs = append(errs, fieldError(fieldPrefix+".string_to_replace", "cannot be empty or whitespace only"))
		}
		if alias == "" {
			errs = append(errs, fieldError(fieldPrefix+".alias", "cannot be empty or whitespace only"))
		}
		if stringToReplace != "" {
			if previous, ok := seen[stringToReplace]; ok {
				errs = append(errs, fieldError(
					fieldPrefix+".string_to_replace",
					fmt.Sprintf("duplicates rules[%d].string_to_replace value %q", previous, stringToReplace),
				))
			} else {
				seen[stringToReplace] = i
			}
		}

		caseSensitive := true
		if rule.CaseSensitive != nil {
			caseSensitive = *rule.CaseSensitive
		}
		wordBoundaries := true
		if rule.WordBoundaries != nil {
			wordBoundaries = *rule.WordBoundaries
		}

		rules = append(rules, tts.Rule{
			StringToReplace: stringToReplace,
			Alias:           alias,
			CaseSensitive:   caseSensitive,
			WordBoundaries:  wordBoundaries,
		})
	}

	if len(errs) > 0 {
		return nil, apperrors.NewValidationProblemError(
			"pronunciation_rules",
			"One or more fields failed validation",
			errs,
		)
	}
	return rules, nil
}

func pronunciationRulesResponseFromState(state tts.DictionaryState) *PronunciationRulesResponse {
	response := &PronunciationRulesResponse{
		Rules:           state.Rules,
		LatestVersionID: stringPtr(state.LatestVersionID),
		CreatedAt:       timePtr(state.CreationTime),
	}
	if state.NonAliasRuleCount > 0 {
		response.Warning = stringPtr(fmt.Sprintf(
			"%d non-alias rule(s) detected on ElevenLabs (added externally). They will be discarded on the next save.",
			state.NonAliasRuleCount,
		))
	}
	return response
}

func emptyPronunciationRulesResponse() *PronunciationRulesResponse {
	return &PronunciationRulesResponse{
		Rules:           []tts.Rule{},
		LatestVersionID: nil,
		CreatedAt:       nil,
	}
}

func translatePronunciationRulesRepoWriteError(operation string, err error) error {
	if isTTSSettingsInitializationError(err) {
		return translateTTSSettingsRepoError(err)
	}
	switch {
	case errors.Is(err, repository.ErrDuplicateKey):
		return apperrors.DuplicateWithCause("PronunciationRules", "", "", err)
	case errors.Is(err, repository.ErrForeignKeyViolation):
		return apperrors.ValidationWithCause("PronunciationRules", "reference", "references non-existent resource", err)
	case errors.Is(err, repository.ErrDataTooLong):
		return apperrors.ValidationWithCause("PronunciationRules", "field", "exceeds maximum length", err)
	}
	return apperrors.Database("PronunciationRules", operation, err)
}

func isTTSSettingsInitializationError(err error) bool {
	return errors.Is(err, repository.ErrSchemaUnavailable) || errors.Is(err, repository.ErrNotFound)
}

func translatePronunciationRulesUpstreamError(err error) error {
	if _, ok := errors.AsType[*tts.ClientError](err); ok {
		return err
	}
	if apiErr, ok := errors.AsType[*tts.APIError](err); ok {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return apperrors.Upstream(
				"PronunciationRules",
				"ElevenLabs",
				http.StatusServiceUnavailable,
				"Check the ElevenLabs API key and account access",
				apiErr,
			)
		case http.StatusUnprocessableEntity:
			field, message := upstreamRulesValidationFieldAndMessage(apiErr)
			return apperrors.NewValidationProblemErrorWithCause(
				"pronunciation_rules",
				"ElevenLabs rejected the pronunciation rules",
				[]apperrors.ValidationError{fieldError(field, message)},
				apiErr,
			)
		case http.StatusTooManyRequests:
			return apperrors.RateLimited("PronunciationRules", apiErr.RetryAfter, apiErr)
		default:
			return apperrors.Upstream(
				"PronunciationRules",
				"ElevenLabs",
				http.StatusBadGateway,
				"Please try again later",
				apiErr,
			)
		}
	}
	return apperrors.Upstream(
		"PronunciationRules",
		"ElevenLabs",
		http.StatusBadGateway,
		"Please try again later",
		err,
	)
}

func upstreamRulesValidationFieldAndMessage(apiErr *tts.APIError) (string, string) {
	if hasDictionaryNameCollisionCode(apiErr.Body) {
		return "dictionary", "A " + ManagedPronunciationDictionaryName +
			" pronunciation dictionary already exists on ElevenLabs. " +
			"Reconnect the stored pronunciation_dictionary_id or remove the duplicate upstream dictionary."
	}
	return "rules", upstreamRulesValidationMessage(apiErr)
}

func upstreamRulesValidationMessage(apiErr *tts.APIError) string {
	const fallback = "ElevenLabs rejected the pronunciation rules"
	if apiErr == nil {
		return fallback
	}

	body := strings.TrimSpace(apiErr.Body)
	if body == "" {
		return fallback
	}

	var payload struct {
		Detail  any `json:"detail"`
		Message any `json:"message"`
		Error   any `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return fallback
	}

	for _, value := range []any{payload.Detail, payload.Message, payload.Error} {
		if message := upstreamMessageString(value); message != "" {
			return message
		}
	}
	return fallback
}

func upstreamMessageString(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		for _, key := range []string{"message", "msg", "detail", "error"} {
			if message, ok := v[key].(string); ok && strings.TrimSpace(message) != "" {
				return strings.TrimSpace(message)
			}
		}
	case []any:
		messages := make([]string, 0, len(v))
		for _, item := range v {
			if message := upstreamMessageString(item); message != "" {
				messages = append(messages, message)
			}
		}
		return strings.Join(messages, "; ")
	}
	return ""
}

func hasDictionaryNameCollisionCode(body string) bool {
	body = strings.TrimSpace(body)
	if body == "" {
		return false
	}

	var payload any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return false
	}
	return containsDictionaryNameCollisionCode(payload)
}

func containsDictionaryNameCollisionCode(value any) bool {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) == "dictionary_already_exists"
	case map[string]any:
		for _, child := range v {
			if containsDictionaryNameCollisionCode(child) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if containsDictionaryNameCollisionCode(item) {
				return true
			}
		}
	}
	return false
}

func diffPronunciationRules(before, after []tts.Rule) pronunciationRulesDiff {
	beforeByString := make(map[string]tts.Rule, len(before))
	for _, rule := range before {
		beforeByString[rule.StringToReplace] = rule
	}

	afterStrings := make(map[string]bool, len(after))
	diff := pronunciationRulesDiff{
		TotalBefore: len(before),
		TotalAfter:  len(after),
	}

	for _, rule := range after {
		afterStrings[rule.StringToReplace] = true
		beforeRule, ok := beforeByString[rule.StringToReplace]
		switch {
		case !ok:
			diff.Added++
		case pronunciationRulesEqual(beforeRule, rule):
			diff.Unchanged++
		default:
			diff.Changed++
		}
	}

	for _, rule := range before {
		if !afterStrings[rule.StringToReplace] {
			diff.Removed++
		}
	}
	return diff
}

func pronunciationRulesEqual(a, b tts.Rule) bool {
	return a.StringToReplace == b.StringToReplace &&
		a.Alias == b.Alias &&
		a.CaseSensitive == b.CaseSensitive &&
		a.WordBoundaries == b.WordBoundaries
}

func logPronunciationRulesAudit(event pronunciationRulesAuditEvent) {
	fields := map[string]any{
		"action":        string(event.Action),
		"dictionary_id": event.DictionaryID,
		"total_after":   event.TotalAfter,
	}
	if event.ActorUserID != nil {
		fields["user_id"] = *event.ActorUserID
	}
	if event.Action == pronunciationRulesAuditActionRulesReplace {
		fields["added"] = event.Added
		fields["removed"] = event.Removed
		fields["changed"] = event.Changed
		fields["unchanged"] = event.Unchanged
		fields["total_before"] = event.TotalBefore
	}
	logger.WithFields(fields).Info("pronunciation rules updated")
}

func actorUserID(req *UpdatePronunciationRulesRequest) *int64 {
	if req == nil {
		return nil
	}
	return req.ActorUserID
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}
