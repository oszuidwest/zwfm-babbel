package tts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestService_CreateDictionaryFromRules_RequestBody(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pronunciation-dictionaries/add-from-rules" {
			t.Fatalf("path = %q, want add-from-rules", r.URL.Path)
		}
		captured = decodePronunciationDictionaryRequest(t, r)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"id":"dict-123",
			"name":"Babbel",
			"latest_version_id":"v1",
			"latest_version_rules_num":1,
			"creation_time_unix":1717200000,
			"rules":[{"type":"alias","string_to_replace":"Albert Heijn","alias":"albert hijn"}]
		}`))
	}))
	defer server.Close()

	service := testTTSService(server.URL)

	state, err := service.CreateDictionaryFromRules(context.Background(), "Babbel", "Auto-managed by Babbel", []Rule{{
		StringToReplace: "Albert Heijn",
		Alias:           "albert hijn",
		CaseSensitive:   false,
		WordBoundaries:  true,
	}})
	if err != nil {
		t.Fatalf("CreateDictionaryFromRules() error = %v", err)
	}
	if state.ID != "dict-123" || state.LatestVersionID != "v1" {
		t.Fatalf("state = %#v, want dict-123 v1", state)
	}

	if captured["name"] != "Babbel" || captured["workspace_access"] != "admin" {
		t.Fatalf("captured create body = %#v", captured)
	}
	rules, ok := captured["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("rules = %#v, want one rule", captured["rules"])
	}
	rule := rules[0].(map[string]any)
	if rule["type"] != "alias" || rule["case_sensitive"] != false || rule["word_boundaries"] != true {
		t.Fatalf("rule payload = %#v, want alias with explicit booleans", rule)
	}
}

func TestService_CreateDictionaryFromRules_UpstreamValidationReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"detail":"dictionary_already_exists"}`))
	}))
	defer server.Close()

	_, err := testTTSService(server.URL).CreateDictionaryFromRules(
		context.Background(),
		"Babbel",
		"Auto-managed by Babbel",
		[]Rule{{StringToReplace: "A", Alias: "aa"}},
	)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("CreateDictionaryFromRules() error type = %T, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(apiErr.Body, "dictionary_already_exists") {
		t.Fatalf("APIError = %#v, want 422 dictionary_already_exists", apiErr)
	}
}

func TestService_CreateDictionaryFromRules_MissingIDFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"id":"",
			"name":"Babbel",
			"latest_version_id":"v1",
			"creation_time_unix":1717200000,
			"rules":[]
		}`))
	}))
	defer server.Close()

	_, err := testTTSService(server.URL).CreateDictionaryFromRules(
		context.Background(),
		"Babbel",
		"Auto-managed by Babbel",
		[]Rule{{StringToReplace: "A", Alias: "aa"}},
	)
	if err == nil || !strings.Contains(err.Error(), "create response missing id") {
		t.Fatalf("CreateDictionaryFromRules() error = %v, want missing id error", err)
	}
}

func TestService_GetDictionary_RequestConstructionFailureIsClientError(t *testing.T) {
	service := testTTSService(":// invalid")

	_, err := service.GetDictionary(context.Background(), "dict-123")
	var clientErr *ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("GetDictionary() error type = %T, want *ClientError", err)
	}
}

func TestService_GetDictionary_ParsesAliasRulesAndDefaults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pronunciation-dictionaries/dict-123" {
			t.Fatalf("path = %q, want dictionary path", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"dict-123",
			"name":"Babbel",
			"latest_version_id":"v2",
			"latest_version_rules_num":3,
			"creation_time_unix":1717200000,
			"archived_time_unix":null,
			"rules":[
				{"type":"alias","string_to_replace":"Albert Heijn","alias":"albert hijn"},
				{"type":"phoneme","string_to_replace":"ignored","phoneme":"abc"},
				{"type":"alias","string_to_replace":"ZuidWest","alias":"zuit west","case_sensitive":false,"word_boundaries":false}
			]
		}`))
	}))
	defer server.Close()

	state, err := testTTSService(server.URL).GetDictionary(context.Background(), "dict-123")
	if err != nil {
		t.Fatalf("GetDictionary() error = %v", err)
	}

	if state.NonAliasRuleCount != 1 {
		t.Fatalf("NonAliasRuleCount = %d, want 1", state.NonAliasRuleCount)
	}
	if len(state.Rules) != 2 {
		t.Fatalf("rules len = %d, want 2: %#v", len(state.Rules), state.Rules)
	}
	if !state.Rules[0].CaseSensitive || !state.Rules[0].WordBoundaries {
		t.Fatalf("first rule booleans = %t,%t want true,true", state.Rules[0].CaseSensitive, state.Rules[0].WordBoundaries)
	}
	if state.Rules[1].CaseSensitive || state.Rules[1].WordBoundaries {
		t.Fatalf("second rule booleans = %t,%t want false,false", state.Rules[1].CaseSensitive, state.Rules[1].WordBoundaries)
	}
	if !state.CreationTime.Equal(time.Unix(1717200000, 0).UTC()) {
		t.Fatalf("CreationTime = %s, want unix 1717200000", state.CreationTime)
	}
}

func TestService_GetDictionary_LimitsResponseSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Repeat(" ", int(maxDictionaryResponseBytes)+1)))
	}))
	defer server.Close()

	_, err := testTTSService(server.URL).GetDictionary(context.Background(), "dict-123")
	if err == nil || !strings.Contains(err.Error(), "exceeded maximum allowed size") {
		t.Fatalf("GetDictionary() error = %v, want response size limit error", err)
	}
}

func TestService_GetDictionary_MissingAndArchivedCollapseToSentinel(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "404",
			status: http.StatusNotFound,
			body:   `{"detail":"missing"}`,
		},
		{
			name:   "classified 422",
			status: http.StatusUnprocessableEntity,
			body:   `{"detail":"pronunciation_dictionary_not_found"}`,
		},
		{
			name:   "archived 200",
			status: http.StatusOK,
			body: `{
				"id":"dict-123",
				"name":"Babbel",
				"latest_version_id":"v2",
				"creation_time_unix":1717200000,
				"archived_time_unix":1717200100,
				"rules":[]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			_, err := testTTSService(server.URL).GetDictionary(context.Background(), "dict-123")
			if !errors.Is(err, ErrDictionaryNotFound) {
				t.Fatalf("GetDictionary() error = %v, want ErrDictionaryNotFound", err)
			}
		})
	}
}

func TestService_SetRules_SendsEmptyRulesArray(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pronunciation-dictionaries/dict-123/set-rules" {
			t.Fatalf("path = %q, want set-rules path", r.URL.Path)
		}
		captured = decodePronunciationDictionaryRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"dict-123","version_id":"v3","version_rules_num":0}`))
	}))
	defer server.Close()

	result, err := testTTSService(server.URL).SetRules(context.Background(), "dict-123", []Rule{})
	if err != nil {
		t.Fatalf("SetRules() error = %v", err)
	}
	if result.LatestVersionID != "v3" || result.LatestVersionRulesNum != 0 {
		t.Fatalf("result = %#v, want v3/0", result)
	}
	rules, ok := captured["rules"].([]any)
	if !ok || len(rules) != 0 {
		t.Fatalf("rules = %#v, want empty array", captured["rules"])
	}
}

func TestService_SetRules_SendsNonEmptyRulesArray(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pronunciation-dictionaries/dict-123/set-rules" {
			t.Fatalf("path = %q, want set-rules path", r.URL.Path)
		}
		captured = decodePronunciationDictionaryRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"dict-123","version_id":"v4","version_rules_num":1}`))
	}))
	defer server.Close()

	result, err := testTTSService(server.URL).SetRules(context.Background(), "dict-123", []Rule{{
		StringToReplace: "Albert Heijn",
		Alias:           "albert hijn",
		CaseSensitive:   false,
		WordBoundaries:  true,
	}})
	if err != nil {
		t.Fatalf("SetRules() error = %v", err)
	}
	if result.LatestVersionID != "v4" || result.LatestVersionRulesNum != 1 {
		t.Fatalf("result = %#v, want v4/1", result)
	}

	rules, ok := captured["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("rules = %#v, want one rule", captured["rules"])
	}
	rule := rules[0].(map[string]any)
	if rule["type"] != "alias" ||
		rule["string_to_replace"] != "Albert Heijn" ||
		rule["alias"] != "albert hijn" ||
		rule["case_sensitive"] != false ||
		rule["word_boundaries"] != true {
		t.Fatalf("rule payload = %#v, want full alias rule", rule)
	}
}

func TestService_SetRules_ErrorClassification(t *testing.T) {
	t.Run("classified 422 returns sentinel", func(t *testing.T) {
		err := setRulesWithErrorResponse(t, http.StatusUnprocessableEntity, `{"detail":"dictionary does not exist"}`)
		if !errors.Is(err, ErrDictionaryNotFound) {
			t.Fatalf("SetRules() error = %v, want ErrDictionaryNotFound", err)
		}
	})

	t.Run("generic 422 stays API error", func(t *testing.T) {
		err := setRulesWithErrorResponse(t, http.StatusUnprocessableEntity, `{"detail":"rule too long"}`)
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("SetRules() error type = %T, want *APIError", err)
		}
		if errors.Is(err, ErrDictionaryNotFound) {
			t.Fatalf("SetRules() error = %v, did not want ErrDictionaryNotFound", err)
		}
	})
}

func setRulesWithErrorResponse(t *testing.T, status int, body string) error {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	_, err := testTTSService(server.URL).SetRules(context.Background(), "dict-123", []Rule{})
	return err
}

func TestClassifyDictionaryError(t *testing.T) {
	tests := []struct {
		name      string
		apiErr    *APIError
		wantFound bool
	}{
		{
			name:      "404",
			apiErr:    &APIError{StatusCode: http.StatusNotFound, Body: "not found"},
			wantFound: true,
		},
		{
			name:      "dictionary not found marker",
			apiErr:    &APIError{StatusCode: http.StatusUnprocessableEntity, Body: "dictionary not found"},
			wantFound: true,
		},
		{
			name:      "dictionary archived marker",
			apiErr:    &APIError{StatusCode: http.StatusUnprocessableEntity, Body: "Dictionary archived"},
			wantFound: true,
		},
		{
			name:      "generic validation",
			apiErr:    &APIError{StatusCode: http.StatusUnprocessableEntity, Body: "invalid alias"},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyDictionaryError(tt.apiErr)
			if errors.Is(got, ErrDictionaryNotFound) != tt.wantFound {
				t.Fatalf("ClassifyDictionaryError() = %v, want found=%t", got, tt.wantFound)
			}
			var apiErr *APIError
			if !tt.wantFound && (!errors.As(got, &apiErr) || apiErr != tt.apiErr) {
				t.Fatalf("ClassifyDictionaryError() = %v, want original APIError", got)
			}
		})
	}
}

func TestClassifyDictionaryLocatorError(t *testing.T) {
	tests := []struct {
		name      string
		apiErr    *APIError
		wantFound bool
	}{
		{
			name:      "404 with dictionary marker",
			apiErr:    &APIError{StatusCode: http.StatusNotFound, Body: "dictionary not found"},
			wantFound: true,
		},
		{
			name:      "404 with voice marker",
			apiErr:    &APIError{StatusCode: http.StatusNotFound, Body: "voice not found"},
			wantFound: false,
		},
		{
			name:      "422 with dictionary marker",
			apiErr:    &APIError{StatusCode: http.StatusUnprocessableEntity, Body: "pronunciation_dictionary_not_found"},
			wantFound: true,
		},
		{
			name:      "422 generic validation",
			apiErr:    &APIError{StatusCode: http.StatusUnprocessableEntity, Body: "invalid alias"},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyDictionaryLocatorError(tt.apiErr)
			if errors.Is(got, ErrDictionaryNotFound) != tt.wantFound {
				t.Fatalf("ClassifyDictionaryLocatorError() = %v, want found=%t", got, tt.wantFound)
			}
			var apiErr *APIError
			if !tt.wantFound && (!errors.As(got, &apiErr) || apiErr != tt.apiErr) {
				t.Fatalf("ClassifyDictionaryLocatorError() = %v, want original APIError", got)
			}
		})
	}
}

func TestReadAPIError_ReadFailureIsDistinctError(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusUnprocessableEntity,
		Body:       failingReadCloser{},
		Header:     http.Header{},
	}

	apiErr, err := readAPIError(resp)
	if err == nil {
		t.Fatal("readAPIError() error = nil, want read failure")
	}
	if apiErr != nil {
		t.Fatalf("readAPIError() apiErr = %#v, want nil on read failure", apiErr)
	}
	if !strings.Contains(err.Error(), "failed to read ElevenLabs error response body") {
		t.Fatalf("readAPIError() error = %v, want distinct read failure", err)
	}
}

type failingReadCloser struct{}

func (failingReadCloser) Read(p []byte) (int, error) {
	return 0, errors.New("read failed")
}

func (failingReadCloser) Close() error {
	return nil
}

func decodePronunciationDictionaryRequest(t *testing.T, r *http.Request) map[string]any {
	t.Helper()

	if got := r.Header.Get("xi-api-key"); got != "test-key" {
		t.Fatalf("xi-api-key = %q, want test-key", got)
	}

	var captured map[string]any
	if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return captured
}

func testTTSService(baseURL string) *Service {
	return &Service{
		apiKey:  "test-key",
		baseURL: baseURL,
		client:  &http.Client{Timeout: time.Second},
	}
}
