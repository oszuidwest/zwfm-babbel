package tts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrDictionaryNotFound is returned when the managed pronunciation dictionary
// is missing, inaccessible, or archived upstream.
var ErrDictionaryNotFound = errors.New("elevenlabs: pronunciation dictionary not found")

// Rule is the alias-only pronunciation rule shape Babbel manages.
type Rule struct {
	StringToReplace string
	Alias           string
	CaseSensitive   bool
	WordBoundaries  bool
}

// DictionaryLocator identifies the pronunciation dictionary to attach to a TTS
// request. VersionID is omitted so ElevenLabs uses the latest version.
type DictionaryLocator struct {
	PronunciationDictionaryID string  `json:"pronunciation_dictionary_id"`
	VersionID                 *string `json:"version_id,omitempty"`
}

// DictionaryState is the parsed state of an ElevenLabs pronunciation dictionary.
type DictionaryState struct {
	ID                    string
	Name                  string
	LatestVersionID       string
	LatestVersionRulesNum int
	CreationTime          time.Time
	ArchivedTime          *time.Time
	Rules                 []Rule
	NonAliasRuleCount     int
}

// SetRulesResult is returned by ElevenLabs after replacing all dictionary rules.
type SetRulesResult struct {
	ID                    string
	LatestVersionID       string
	LatestVersionRulesNum int
}

// PronunciationDictionaryClient is the service-facing contract for dictionary
// operations. Service tests mock this interface; *Service implements it.
type PronunciationDictionaryClient interface {
	CreateDictionaryFromRules(ctx context.Context, name, description string, rules []Rule) (DictionaryState, error)
	GetDictionary(ctx context.Context, id string) (DictionaryState, error)
	SetRules(ctx context.Context, id string, rules []Rule) (SetRulesResult, error)
}

type pronunciationRulePayload struct {
	Type            string `json:"type"`
	StringToReplace string `json:"string_to_replace"`
	Alias           string `json:"alias"`
	CaseSensitive   bool   `json:"case_sensitive"`
	WordBoundaries  bool   `json:"word_boundaries"`
}

type incomingPronunciationRule struct {
	Type            string `json:"type"`
	StringToReplace string `json:"string_to_replace"`
	Alias           string `json:"alias"`
	CaseSensitive   *bool  `json:"case_sensitive,omitempty"`
	WordBoundaries  *bool  `json:"word_boundaries,omitempty"`
}

type addFromRulesRequest struct {
	Name            string                     `json:"name"`
	Description     string                     `json:"description"`
	Rules           []pronunciationRulePayload `json:"rules"`
	WorkspaceAccess string                     `json:"workspace_access"`
}

type setRulesRequest struct {
	Rules []pronunciationRulePayload `json:"rules"`
}

type dictionaryResponse struct {
	ID                    string                      `json:"id"`
	Name                  string                      `json:"name"`
	LatestVersionID       string                      `json:"latest_version_id"`
	VersionID             string                      `json:"version_id"`
	LatestVersionRulesNum int                         `json:"latest_version_rules_num"`
	VersionRulesNum       int                         `json:"version_rules_num"`
	CreationTimeUnix      int64                       `json:"creation_time_unix"`
	ArchivedTimeUnix      *int64                      `json:"archived_time_unix"`
	Rules                 []incomingPronunciationRule `json:"rules"`
}

type setRulesResponse struct {
	ID              string `json:"id"`
	VersionID       string `json:"version_id"`
	VersionRulesNum int    `json:"version_rules_num"`
}

func (r incomingPronunciationRule) toRule() Rule {
	caseSensitive := true
	if r.CaseSensitive != nil {
		caseSensitive = *r.CaseSensitive
	}
	wordBoundaries := true
	if r.WordBoundaries != nil {
		wordBoundaries = *r.WordBoundaries
	}

	return Rule{
		StringToReplace: r.StringToReplace,
		Alias:           r.Alias,
		CaseSensitive:   caseSensitive,
		WordBoundaries:  wordBoundaries,
	}
}

// CreateDictionaryFromRules creates the managed Babbel dictionary with an
// initial alias-rule set.
func (s *Service) CreateDictionaryFromRules(
	ctx context.Context,
	name string,
	description string,
	rules []Rule,
) (DictionaryState, error) {
	reqBody := addFromRulesRequest{
		Name:            name,
		Description:     description,
		Rules:           outgoingRules(rules),
		WorkspaceAccess: "admin",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return DictionaryState{}, fmt.Errorf("failed to marshal pronunciation dictionary create request: %w", err)
	}

	req, err := s.newJSONRequest(
		ctx,
		http.MethodPost,
		"/v1/pronunciation-dictionaries/add-from-rules",
		body,
	)
	if err != nil {
		return DictionaryState{}, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return DictionaryState{}, fmt.Errorf("pronunciation dictionary create request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return DictionaryState{}, readAPIError(resp)
	}

	var wire dictionaryResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return DictionaryState{}, fmt.Errorf("failed to decode pronunciation dictionary create response: %w", err)
	}
	return wire.toState(), nil
}

// GetDictionary reads the managed dictionary and collapses missing or archived
// dictionaries to ErrDictionaryNotFound.
func (s *Service) GetDictionary(ctx context.Context, id string) (DictionaryState, error) {
	req, err := s.newJSONRequest(
		ctx,
		http.MethodGet,
		"/v1/pronunciation-dictionaries/"+url.PathEscape(id),
		nil,
	)
	if err != nil {
		return DictionaryState{}, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return DictionaryState{}, fmt.Errorf("pronunciation dictionary get request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		apiErr := readAPIError(resp)
		if classified := classifyAPIError(apiErr); classified != nil {
			return DictionaryState{}, classified
		}
		return DictionaryState{}, apiErr
	}

	var wire dictionaryResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return DictionaryState{}, fmt.Errorf("failed to decode pronunciation dictionary get response: %w", err)
	}

	state := wire.toState()
	if state.ArchivedTime != nil {
		return DictionaryState{}, ErrDictionaryNotFound
	}
	return state, nil
}

// SetRules replaces all rules in the managed dictionary in one upstream call.
func (s *Service) SetRules(ctx context.Context, id string, rules []Rule) (SetRulesResult, error) {
	body, err := json.Marshal(setRulesRequest{Rules: outgoingRules(rules)})
	if err != nil {
		return SetRulesResult{}, fmt.Errorf("failed to marshal pronunciation dictionary set-rules request: %w", err)
	}

	req, err := s.newJSONRequest(
		ctx,
		http.MethodPost,
		"/v1/pronunciation-dictionaries/"+url.PathEscape(id)+"/set-rules",
		body,
	)
	if err != nil {
		return SetRulesResult{}, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return SetRulesResult{}, fmt.Errorf("pronunciation dictionary set-rules request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		apiErr := readAPIError(resp)
		if classified := classifyAPIError(apiErr); classified != nil {
			return SetRulesResult{}, classified
		}
		return SetRulesResult{}, apiErr
	}

	var wire setRulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return SetRulesResult{}, fmt.Errorf("failed to decode pronunciation dictionary set-rules response: %w", err)
	}
	return SetRulesResult{
		ID:                    wire.ID,
		LatestVersionID:       wire.VersionID,
		LatestVersionRulesNum: wire.VersionRulesNum,
	}, nil
}

// ClassifyDictionaryError returns ErrDictionaryNotFound for upstream responses
// that mean the managed dictionary is missing or archived.
func ClassifyDictionaryError(apiErr *APIError) error {
	if apiErr == nil {
		return nil
	}
	if apiErr.StatusCode == http.StatusNotFound {
		return ErrDictionaryNotFound
	}
	if apiErr.StatusCode == http.StatusUnprocessableEntity && looksLikeDictionaryMissing(apiErr.Body) {
		return ErrDictionaryNotFound
	}
	return apiErr
}

func classifyAPIError(apiErr *APIError) error {
	classified := ClassifyDictionaryError(apiErr)
	if errors.Is(classified, ErrDictionaryNotFound) {
		return classified
	}
	return nil
}

func looksLikeDictionaryMissing(body string) bool {
	normalized := strings.ToLower(body)
	markers := []string{
		"pronunciation_dictionary_not_found",
		"pronunciation dictionary not found",
		"dictionary not found",
		"dictionary archived",
		"dictionary does not exist",
	}
	for _, marker := range markers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func outgoingRules(rules []Rule) []pronunciationRulePayload {
	payload := make([]pronunciationRulePayload, 0, len(rules))
	for _, rule := range rules {
		payload = append(payload, pronunciationRulePayload{
			Type:            "alias",
			StringToReplace: rule.StringToReplace,
			Alias:           rule.Alias,
			CaseSensitive:   rule.CaseSensitive,
			WordBoundaries:  rule.WordBoundaries,
		})
	}
	return payload
}

func (r dictionaryResponse) toState() DictionaryState {
	rules := []Rule{}
	nonAliasRuleCount := 0
	for _, wireRule := range r.Rules {
		if wireRule.Type != "alias" {
			nonAliasRuleCount++
			continue
		}
		rules = append(rules, wireRule.toRule())
	}

	var archivedTime *time.Time
	if r.ArchivedTimeUnix != nil {
		parsed := time.Unix(*r.ArchivedTimeUnix, 0).UTC()
		archivedTime = &parsed
	}

	latestVersionID := r.LatestVersionID
	if latestVersionID == "" {
		latestVersionID = r.VersionID
	}

	rulesNum := r.LatestVersionRulesNum
	if rulesNum == 0 {
		rulesNum = r.VersionRulesNum
	}

	return DictionaryState{
		ID:                    r.ID,
		Name:                  r.Name,
		LatestVersionID:       latestVersionID,
		LatestVersionRulesNum: rulesNum,
		CreationTime:          time.Unix(r.CreationTimeUnix, 0).UTC(),
		ArchivedTime:          archivedTime,
		Rules:                 rules,
		NonAliasRuleCount:     nonAliasRuleCount,
	}
}

func (s *Service) newJSONRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	reqURL := s.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create pronunciation dictionary request: %w", err)
	}
	req.Header.Set("xi-api-key", s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func readAPIError(resp *http.Response) *APIError {
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		respBody = []byte(fmt.Sprintf("failed to read response body: %s", err.Error()))
	}
	return &APIError{
		StatusCode: resp.StatusCode,
		Body:       string(respBody),
		RetryAfter: resp.Header.Get("Retry-After"),
	}
}
