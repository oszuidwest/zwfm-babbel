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

const maxDictionaryResponseBytes int64 = 1024 * 1024
const maxAPIErrorResponseBytes int64 = 1024

// ErrDictionaryNotFound is returned when the managed pronunciation dictionary
// is missing or archived upstream.
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
	// CreateDictionaryFromRules creates a managed dictionary from the supplied alias rules.
	CreateDictionaryFromRules(ctx context.Context, name, description string, rules []Rule) (DictionaryState, error)

	// GetDictionary reads a managed dictionary by ID.
	GetDictionary(ctx context.Context, id string) (DictionaryState, error)

	// SetRules replaces all alias rules in a managed dictionary.
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
	ID                    string `json:"id"`
	LatestVersionID       string `json:"latest_version_id"`
	LatestVersionRulesNum int    `json:"latest_version_rules_num"`
	VersionID             string `json:"version_id"`
	VersionRulesNum       int    `json:"version_rules_num"`
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

// CreateDictionaryFromRules creates the managed Babbel dictionary with an initial alias-rule set.
// It returns APIError for ElevenLabs rejections and ClientError for request construction failures.
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
		return DictionaryState{}, newClientError("marshal pronunciation dictionary create request", err)
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

	if !isSuccessStatus(resp.StatusCode) {
		apiErr, err := readAPIError(resp)
		if err != nil {
			return DictionaryState{}, err
		}
		return DictionaryState{}, apiErr
	}

	var wire dictionaryResponse
	if err := decodeLimitedJSON(resp.Body, &wire); err != nil {
		return DictionaryState{}, fmt.Errorf("failed to decode pronunciation dictionary create response: %w", err)
	}
	state := wire.toState()
	if strings.TrimSpace(state.ID) == "" {
		return DictionaryState{}, fmt.Errorf("pronunciation dictionary create response missing id")
	}
	return state, nil
}

// GetDictionary reads the managed dictionary and collapses missing or archived
// dictionaries to ErrDictionaryNotFound.
// It returns APIError for other ElevenLabs rejections and ClientError for request construction failures.
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

	if !isSuccessStatus(resp.StatusCode) {
		apiErr, err := readAPIError(resp)
		if err != nil {
			return DictionaryState{}, err
		}
		return DictionaryState{}, ClassifyDictionaryError(apiErr)
	}

	var wire dictionaryResponse
	if err := decodeLimitedJSON(resp.Body, &wire); err != nil {
		return DictionaryState{}, fmt.Errorf("failed to decode pronunciation dictionary get response: %w", err)
	}

	state := wire.toState()
	if state.ArchivedTime != nil {
		return DictionaryState{}, ErrDictionaryNotFound
	}
	return state, nil
}

// SetRules replaces all rules in the managed dictionary in one upstream call.
// It returns ErrDictionaryNotFound when ElevenLabs reports the dictionary as missing or archived.
func (s *Service) SetRules(ctx context.Context, id string, rules []Rule) (SetRulesResult, error) {
	body, err := json.Marshal(setRulesRequest{Rules: outgoingRules(rules)})
	if err != nil {
		return SetRulesResult{}, newClientError("marshal pronunciation dictionary set-rules request", err)
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

	if !isSuccessStatus(resp.StatusCode) {
		apiErr, err := readAPIError(resp)
		if err != nil {
			return SetRulesResult{}, err
		}
		return SetRulesResult{}, ClassifyDictionaryError(apiErr)
	}

	var wire setRulesResponse
	if err := decodeLimitedJSON(resp.Body, &wire); err != nil {
		return SetRulesResult{}, fmt.Errorf("failed to decode pronunciation dictionary set-rules response: %w", err)
	}
	latestVersionID := wire.LatestVersionID
	if latestVersionID == "" {
		latestVersionID = wire.VersionID
	}
	rulesNum := wire.LatestVersionRulesNum
	if rulesNum == 0 {
		rulesNum = wire.VersionRulesNum
	}
	return SetRulesResult{
		ID:                    wire.ID,
		LatestVersionID:       latestVersionID,
		LatestVersionRulesNum: rulesNum,
	}, nil
}

// ClassifyDictionaryError returns ErrDictionaryNotFound for upstream responses
// that indicate the managed dictionary is missing or archived. Used by the
// resource-specific dictionary CRUD endpoints (GET /pronunciation-dictionaries/{id},
// set-rules), where a 404 unambiguously means the resource does not exist; a 422
// is only classified when the body carries an explicit marker.
// It returns nil for nil input and the original APIError for unrelated responses.
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

// ClassifyDictionaryLocatorError returns ErrDictionaryNotFound only when a TTS
// request error body explicitly points at a missing pronunciation dictionary.
// Unlike ClassifyDictionaryError, a bare 404 is NOT enough — the TTS endpoint
// can 404 for unrelated reasons (e.g. missing voice), so the dictionary marker
// must be present.
// It returns nil for nil input and the original APIError for unrelated responses.
func ClassifyDictionaryLocatorError(apiErr *APIError) error {
	if apiErr == nil {
		return nil
	}
	if (apiErr.StatusCode == http.StatusNotFound ||
		apiErr.StatusCode == http.StatusUnprocessableEntity) &&
		looksLikeDictionaryMissing(apiErr.Body) {
		return ErrDictionaryNotFound
	}
	return apiErr
}

func isSuccessStatus(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

func decodeLimitedJSON(body io.Reader, target any) error {
	respBody, err := io.ReadAll(io.LimitReader(body, maxDictionaryResponseBytes+1))
	if err != nil {
		return err
	}
	if int64(len(respBody)) > maxDictionaryResponseBytes {
		return fmt.Errorf("response body exceeded maximum allowed size of %d bytes", maxDictionaryResponseBytes)
	}
	return json.Unmarshal(respBody, target)
}

func looksLikeDictionaryMissing(body string) bool {
	normalized := strings.ToLower(body)
	markers := []string{
		"pronunciation_dictionary_not_found",
		"pronunciation_dictionary_archived",
		"pronunciation_dictionary_does_not_exist",
		"pronunciation dictionary not found",
		"pronunciation dictionary archived",
		"pronunciation dictionary does not exist",
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
	if r.ArchivedTimeUnix != nil && *r.ArchivedTimeUnix > 0 {
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

	var creationTime time.Time
	if r.CreationTimeUnix > 0 {
		creationTime = time.Unix(r.CreationTimeUnix, 0).UTC()
	}

	return DictionaryState{
		ID:                    r.ID,
		Name:                  r.Name,
		LatestVersionID:       latestVersionID,
		LatestVersionRulesNum: rulesNum,
		CreationTime:          creationTime,
		ArchivedTime:          archivedTime,
		Rules:                 rules,
		NonAliasRuleCount:     nonAliasRuleCount,
	}
}

func (s *Service) newJSONRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	reqURL := s.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, newClientError("create pronunciation dictionary request", err)
	}
	req.Header.Set("xi-api-key", s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func readAPIError(resp *http.Response) (*APIError, error) {
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIErrorResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read ElevenLabs error response body for status %d: %w", resp.StatusCode, err)
	}
	return &APIError{
		StatusCode: resp.StatusCode,
		Body:       string(respBody),
		RetryAfter: resp.Header.Get("Retry-After"),
	}, nil
}
