package tts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

func TestService_SetRules_RequestBodyAndErrorClassification(t *testing.T) {
	t.Run("sends empty rules array", func(t *testing.T) {
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
	})

	t.Run("classified 422 returns sentinel", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"detail":"dictionary does not exist"}`))
		}))
		defer server.Close()

		_, err := testTTSService(server.URL).SetRules(context.Background(), "dict-123", []Rule{})
		if !errors.Is(err, ErrDictionaryNotFound) {
			t.Fatalf("SetRules() error = %v, want ErrDictionaryNotFound", err)
		}
	})

	t.Run("generic 422 stays API error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"detail":"rule too long"}`))
		}))
		defer server.Close()

		_, err := testTTSService(server.URL).SetRules(context.Background(), "dict-123", []Rule{})
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("SetRules() error type = %T, want *APIError", err)
		}
		if errors.Is(err, ErrDictionaryNotFound) {
			t.Fatalf("SetRules() error = %v, did not want ErrDictionaryNotFound", err)
		}
	})
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
