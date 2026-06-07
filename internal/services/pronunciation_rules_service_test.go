package services

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
)

func TestMaterializePronunciationRules(t *testing.T) {
	falseValue := false

	t.Run("defaults omitted booleans to true", func(t *testing.T) {
		rules, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
			Rules: []PronunciationRuleUpdate{{
				StringToReplace: " Albert Heijn ",
				Alias:           "\talbert hijn\n",
			}},
		})
		if err != nil {
			t.Fatalf("materializePronunciationRules() error = %v", err)
		}
		if rules[0].StringToReplace != "Albert Heijn" || rules[0].Alias != "albert hijn" {
			t.Fatalf("rule = %#v, want trimmed values", rules[0])
		}
		if !rules[0].CaseSensitive || !rules[0].WordBoundaries {
			t.Fatalf("booleans = %t,%t want true,true", rules[0].CaseSensitive, rules[0].WordBoundaries)
		}
	})

	t.Run("preserves explicit false", func(t *testing.T) {
		rules, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
			Rules: []PronunciationRuleUpdate{{
				StringToReplace: "ZuidWest",
				Alias:           "zuit west",
				CaseSensitive:   &falseValue,
				WordBoundaries:  &falseValue,
			}},
		})
		if err != nil {
			t.Fatalf("materializePronunciationRules() error = %v", err)
		}
		if rules[0].CaseSensitive || rules[0].WordBoundaries {
			t.Fatalf("booleans = %t,%t want false,false", rules[0].CaseSensitive, rules[0].WordBoundaries)
		}
	})

	t.Run("validates empty and duplicate fields", func(t *testing.T) {
		_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
			Rules: []PronunciationRuleUpdate{
				{StringToReplace: " ZuidWest", Alias: "zuit west"},
				{StringToReplace: "ZuidWest ", Alias: "zuit west opnieuw"},
				{StringToReplace: " ", Alias: "\t"},
			},
		})
		var validationErr *apperrors.ValidationProblemError
		if !errors.As(err, &validationErr) {
			t.Fatalf("error type = %T, want *ValidationProblemError", err)
		}
		gotFields := make([]string, 0, len(validationErr.Errors))
		for _, fieldErr := range validationErr.Errors {
			gotFields = append(gotFields, fieldErr.Field)
		}
		wantFields := []string{
			"rules[1].string_to_replace",
			"rules[2].string_to_replace",
			"rules[2].alias",
		}
		if !reflect.DeepEqual(gotFields, wantFields) {
			t.Fatalf("fields = %v, want %v", gotFields, wantFields)
		}
	})
}

func TestMaterializePronunciationRules_DoesNotDeduplicateEmptyKeys(t *testing.T) {
	_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
		Rules: []PronunciationRuleUpdate{
			{StringToReplace: " ", Alias: "aa"},
			{StringToReplace: "\t", Alias: "bb"},
		},
	})
	var validationErr *apperrors.ValidationProblemError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error type = %T, want *ValidationProblemError", err)
	}
	gotFields := make([]string, 0, len(validationErr.Errors))
	for _, fieldErr := range validationErr.Errors {
		gotFields = append(gotFields, fieldErr.Field)
		if strings.Contains(fieldErr.Message, "duplicates") {
			t.Fatalf("unexpected duplicate error for whitespace-only key: %#v", fieldErr)
		}
	}
	wantFields := []string{
		"rules[0].string_to_replace",
		"rules[1].string_to_replace",
	}
	if !reflect.DeepEqual(gotFields, wantFields) {
		t.Fatalf("fields = %v, want %v", gotFields, wantFields)
	}
}

func TestPronunciationRulesService_Update_FirstWriteCreatesDictionary(t *testing.T) {
	repo := &pronunciationSettingsRepoMock{settings: &models.TTSSettings{}}
	client := &pronunciationDictionaryClientMock{
		createFn: func(ctx context.Context, name, description string, rules []tts.Rule) (tts.DictionaryState, error) {
			if name != "Babbel" || description == "" {
				t.Fatalf("create name/description = %q/%q", name, description)
			}
			if len(rules) != 1 || rules[0].StringToReplace != "Albert Heijn" {
				t.Fatalf("create rules = %#v", rules)
			}
			return tts.DictionaryState{
				ID:              "dict-new",
				LatestVersionID: "v1",
				CreationTime:    time.Unix(1717200000, 0).UTC(),
				Rules:           rules,
			}, nil
		},
	}
	service := &PronunciationRulesService{settingsRepo: repo, client: client}

	result, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{
		Rules: []PronunciationRuleUpdate{{
			StringToReplace: "Albert Heijn",
			Alias:           "albert hijn",
		}},
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if len(repo.setIDs) != 1 || repo.setIDs[0] == nil || *repo.setIDs[0] != "dict-new" {
		t.Fatalf("set IDs = %#v, want dict-new", repo.setIDs)
	}
	if result.LatestVersionID == nil || *result.LatestVersionID != "v1" {
		t.Fatalf("latest_version_id = %v, want v1", result.LatestVersionID)
	}
	if len(result.Rules) != 1 || !result.Rules[0].CaseSensitive || !result.Rules[0].WordBoundaries {
		t.Fatalf("result rules = %#v, want defaulted rule", result.Rules)
	}
}

func TestPronunciationRulesService_Update_CreateWithEmptyDictionaryIDFailsBeforePersist(t *testing.T) {
	repo := &pronunciationSettingsRepoMock{settings: &models.TTSSettings{}}
	client := &pronunciationDictionaryClientMock{
		createFn: func(ctx context.Context, name, description string, rules []tts.Rule) (tts.DictionaryState, error) {
			return tts.DictionaryState{ID: "   ", LatestVersionID: "v1", Rules: rules}, nil
		},
	}
	service := &PronunciationRulesService{settingsRepo: repo, client: client}

	_, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{
		Rules: []PronunciationRuleUpdate{{StringToReplace: "A", Alias: "aa"}},
	})
	var upstreamErr *apperrors.UpstreamError
	if !errors.As(err, &upstreamErr) {
		t.Fatalf("error type = %T, want *UpstreamError", err)
	}
	if len(repo.setIDs) != 0 {
		t.Fatalf("set IDs = %#v, want no DB persist for empty upstream ID", repo.setIDs)
	}
}

func TestPronunciationRulesService_Update_FirstWriteWithEmptyRulesIsNoop(t *testing.T) {
	repo := &pronunciationSettingsRepoMock{settings: &models.TTSSettings{}}
	client := &pronunciationDictionaryClientMock{}
	service := &PronunciationRulesService{settingsRepo: repo, client: client}

	result, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{Rules: []PronunciationRuleUpdate{}})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if len(client.createCalls) != 0 || len(repo.setIDs) != 0 {
		t.Fatalf("createCalls=%d setIDs=%d, want no calls", len(client.createCalls), len(repo.setIDs))
	}
	if len(result.Rules) != 0 || result.CreatedAt != nil || result.LatestVersionID != nil {
		t.Fatalf("result = %#v, want empty response", result)
	}
}

func TestPronunciationRulesService_Update_SelfHealPaths(t *testing.T) {
	t.Run("missing stored dictionary with empty request clears ID", func(t *testing.T) {
		repo := &pronunciationSettingsRepoMock{settings: &models.TTSSettings{PronunciationDictionaryID: ptr("dict-old")}}
		client := &pronunciationDictionaryClientMock{
			getFn: func(ctx context.Context, id string) (tts.DictionaryState, error) {
				return tts.DictionaryState{}, tts.ErrDictionaryNotFound
			},
		}
		service := &PronunciationRulesService{settingsRepo: repo, client: client}

		result, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{Rules: []PronunciationRuleUpdate{}})
		if err != nil {
			t.Fatalf("Update() error = %v", err)
		}
		if len(repo.setIDs) != 1 || repo.setIDs[0] != nil {
			t.Fatalf("set IDs = %#v, want one nil clear", repo.setIDs)
		}
		if len(result.Rules) != 0 || result.CreatedAt != nil || result.LatestVersionID != nil {
			t.Fatalf("result = %#v, want empty response", result)
		}
	})

	t.Run("set-rules missing dictionary recreates and persists new ID", func(t *testing.T) {
		repo := &pronunciationSettingsRepoMock{settings: &models.TTSSettings{PronunciationDictionaryID: ptr("dict-old")}}
		client := &pronunciationDictionaryClientMock{
			getFn: func(ctx context.Context, id string) (tts.DictionaryState, error) {
				return tts.DictionaryState{
					ID:              id,
					LatestVersionID: "old-v",
					CreationTime:    time.Unix(1717200000, 0).UTC(),
				}, nil
			},
			setFn: func(ctx context.Context, id string, rules []tts.Rule) (tts.SetRulesResult, error) {
				return tts.SetRulesResult{}, tts.ErrDictionaryNotFound
			},
			createFn: func(ctx context.Context, name, description string, rules []tts.Rule) (tts.DictionaryState, error) {
				return tts.DictionaryState{
					ID:              "dict-new",
					LatestVersionID: "new-v",
					CreationTime:    time.Unix(1717200100, 0).UTC(),
					Rules:           rules,
				}, nil
			},
		}
		service := &PronunciationRulesService{settingsRepo: repo, client: client}

		result, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{
			Rules: []PronunciationRuleUpdate{{StringToReplace: "A", Alias: "aa"}},
		})
		if err != nil {
			t.Fatalf("Update() error = %v", err)
		}
		if len(repo.setIDs) != 1 || repo.setIDs[0] == nil || *repo.setIDs[0] != "dict-new" {
			t.Fatalf("set IDs = %#v, want dict-new", repo.setIDs)
		}
		if result.LatestVersionID == nil || *result.LatestVersionID != "new-v" {
			t.Fatalf("latest_version_id = %v, want new-v", result.LatestVersionID)
		}
	})
}

func TestPronunciationRulesService_Update_SetRules(t *testing.T) {
	createdAt := time.Unix(1717200000, 0).UTC()
	repo := &pronunciationSettingsRepoMock{settings: &models.TTSSettings{PronunciationDictionaryID: ptr("dict-123")}}
	client := &pronunciationDictionaryClientMock{
		getFn: func(ctx context.Context, id string) (tts.DictionaryState, error) {
			return tts.DictionaryState{
				ID:              id,
				LatestVersionID: "old-v",
				CreationTime:    createdAt,
				Rules: []tts.Rule{
					{StringToReplace: "A", Alias: "aa", CaseSensitive: true, WordBoundaries: true},
				},
			}, nil
		},
		setFn: func(ctx context.Context, id string, rules []tts.Rule) (tts.SetRulesResult, error) {
			if id != "dict-123" || len(rules) != 0 {
				t.Fatalf("SetRules(%q, %#v), want dict-123 empty rules", id, rules)
			}
			return tts.SetRulesResult{ID: id, LatestVersionID: "v2", LatestVersionRulesNum: 0}, nil
		},
	}
	service := &PronunciationRulesService{settingsRepo: repo, client: client}

	result, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{Rules: []PronunciationRuleUpdate{}})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if len(repo.setIDs) != 0 {
		t.Fatalf("set IDs = %#v, want no DB write", repo.setIDs)
	}
	if result.CreatedAt == nil || !result.CreatedAt.Equal(createdAt) {
		t.Fatalf("created_at = %v, want %s", result.CreatedAt, createdAt)
	}
	if result.LatestVersionID == nil || *result.LatestVersionID != "v2" {
		t.Fatalf("latest_version_id = %v, want v2", result.LatestVersionID)
	}
}

func TestPronunciationRulesService_GetWarnings(t *testing.T) {
	t.Run("missing dictionary returns warning", func(t *testing.T) {
		repo := &pronunciationSettingsRepoMock{settings: &models.TTSSettings{PronunciationDictionaryID: ptr("dict-missing")}}
		client := &pronunciationDictionaryClientMock{
			getFn: func(ctx context.Context, id string) (tts.DictionaryState, error) {
				return tts.DictionaryState{}, tts.ErrDictionaryNotFound
			},
		}
		service := &PronunciationRulesService{settingsRepo: repo, client: client}

		result, err := service.Get(context.Background())
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if result.Warning == nil || *result.Warning != missingPronunciationDictionaryWarning {
			t.Fatalf("warning = %v, want missing dictionary warning", result.Warning)
		}
	})

	t.Run("non-alias rules return warning", func(t *testing.T) {
		repo := &pronunciationSettingsRepoMock{settings: &models.TTSSettings{PronunciationDictionaryID: ptr("dict-123")}}
		client := &pronunciationDictionaryClientMock{
			getFn: func(ctx context.Context, id string) (tts.DictionaryState, error) {
				return tts.DictionaryState{
					ID:                id,
					LatestVersionID:   "v1",
					CreationTime:      time.Unix(1717200000, 0).UTC(),
					Rules:             []tts.Rule{},
					NonAliasRuleCount: 3,
				}, nil
			},
		}
		service := &PronunciationRulesService{settingsRepo: repo, client: client}

		result, err := service.Get(context.Background())
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		want := "3 non-alias rule(s) detected on ElevenLabs (added externally). They will be discarded on the next save."
		if result.Warning == nil || *result.Warning != want {
			t.Fatalf("warning = %v, want %q", result.Warning, want)
		}
	})
}

func TestTranslatePronunciationRulesUpstreamError_StatusMatrix(t *testing.T) {
	tests := []struct {
		name        string
		apiErr      *tts.APIError
		wantKind    string
		wantStatus  int
		wantField   string
		wantRetry   string
		wantMessage string
	}{
		{
			name:       "401 maps to service unavailable",
			apiErr:     &tts.APIError{StatusCode: http.StatusUnauthorized, Body: "bad key"},
			wantKind:   "upstream",
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "403 maps to service unavailable",
			apiErr:     &tts.APIError{StatusCode: http.StatusForbidden, Body: "forbidden"},
			wantKind:   "upstream",
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "422 maps sanitized upstream message to validation problem",
			apiErr: &tts.APIError{
				StatusCode: http.StatusUnprocessableEntity,
				Body:       `{"detail":"invalid rule"}`,
			},
			wantKind:    "validation",
			wantField:   "rules",
			wantMessage: "invalid rule",
		},
		{
			name: "422 maps FastAPI detail list message to validation problem",
			apiErr: &tts.APIError{
				StatusCode: http.StatusUnprocessableEntity,
				Body:       `{"detail":[{"loc":["body","rules",0],"msg":"alias is required"}]}`,
			},
			wantKind:    "validation",
			wantField:   "rules",
			wantMessage: "alias is required",
		},
		{
			name: "422 dictionary name collision maps to dictionary field",
			apiErr: &tts.APIError{
				StatusCode: http.StatusUnprocessableEntity,
				Body:       `{"detail":"dictionary_already_exists"}`,
			},
			wantKind:  "validation",
			wantField: "dictionary",
			wantMessage: "A Babbel pronunciation dictionary already exists on ElevenLabs. " +
				"Reconnect the stored pronunciation_dictionary_id or remove the duplicate upstream dictionary.",
		},
		{
			name: "422 dictionary name collision code nested in detail maps to dictionary field",
			apiErr: &tts.APIError{
				StatusCode: http.StatusUnprocessableEntity,
				Body:       `{"detail":[{"type":"dictionary_already_exists","msg":"dictionary already exists"}]}`,
			},
			wantKind:  "validation",
			wantField: "dictionary",
			wantMessage: "A Babbel pronunciation dictionary already exists on ElevenLabs. " +
				"Reconnect the stored pronunciation_dictionary_id or remove the duplicate upstream dictionary.",
		},
		{
			name: "422 dictionary already exists text without code stays on rules field",
			apiErr: &tts.APIError{
				StatusCode: http.StatusUnprocessableEntity,
				Body:       `{"detail":"dictionary rule already exists"}`,
			},
			wantKind:    "validation",
			wantField:   "rules",
			wantMessage: "dictionary rule already exists",
		},
		{
			name: "422 raw dictionary collision code body uses sanitized fallback",
			apiErr: &tts.APIError{
				StatusCode: http.StatusUnprocessableEntity,
				Body:       `dictionary_already_exists`,
			},
			wantKind:    "validation",
			wantField:   "rules",
			wantMessage: "ElevenLabs rejected the pronunciation rules",
		},
		{
			name: "422 non-JSON body uses sanitized fallback",
			apiErr: &tts.APIError{
				StatusCode: http.StatusUnprocessableEntity,
				Body:       `<html>private upstream details</html>`,
			},
			wantKind:    "validation",
			wantField:   "rules",
			wantMessage: "ElevenLabs rejected the pronunciation rules",
		},
		{
			name:      "429 preserves retry after",
			apiErr:    &tts.APIError{StatusCode: http.StatusTooManyRequests, Body: "slow down", RetryAfter: "17"},
			wantKind:  "rate_limited",
			wantRetry: "17",
		},
		{
			name:       "500 maps to bad gateway",
			apiErr:     &tts.APIError{StatusCode: http.StatusInternalServerError, Body: "upstream failed"},
			wantKind:   "upstream",
			wantStatus: http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translatePronunciationRulesUpstreamError(tt.apiErr)
			assertWrapsAPIError(t, got)
			assertPronunciationRulesTranslation(
				t,
				got,
				tt.wantKind,
				tt.wantStatus,
				tt.wantField,
				tt.wantRetry,
				tt.wantMessage,
			)
		})
	}
}

func TestTranslatePronunciationRulesUpstreamError_ClientErrorStaysInternal(t *testing.T) {
	clientErr := &tts.ClientError{Operation: "create pronunciation dictionary request", Err: errors.New("bad url")}

	err := translatePronunciationRulesUpstreamError(clientErr)
	if !errors.Is(err, clientErr) {
		t.Fatalf("translated error = %v, want original client error", err)
	}
	var upstreamErr *apperrors.UpstreamError
	if errors.As(err, &upstreamErr) {
		t.Fatalf("error type = %T, did not want UpstreamError", err)
	}
}

func TestTranslatePronunciationRulesUpstreamError_PlainError(t *testing.T) {
	err := translatePronunciationRulesUpstreamError(errors.New("transport failed"))
	assertUpstreamError(t, err, http.StatusBadGateway)
}

func TestPronunciationRulesService_Translations(t *testing.T) {
	t.Run("create persist failure returns PronunciationRules database error", func(t *testing.T) {
		repo := &pronunciationSettingsRepoMock{
			settings: &models.TTSSettings{},
			setErr:   errors.New("write failed"),
		}
		client := &pronunciationDictionaryClientMock{
			createFn: func(ctx context.Context, name, description string, rules []tts.Rule) (tts.DictionaryState, error) {
				return tts.DictionaryState{ID: "orph-123", LatestVersionID: "v1", Rules: rules}, nil
			},
		}
		service := &PronunciationRulesService{settingsRepo: repo, client: client}

		_, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{
			Rules: []PronunciationRuleUpdate{{StringToReplace: "A", Alias: "aa"}},
		})
		var dbErr *apperrors.DatabaseError
		if !errors.As(err, &dbErr) {
			t.Fatalf("error type = %T, want *DatabaseError", err)
		}
		if dbErr.Resource != "PronunciationRules" || dbErr.Operation != "persist_dictionary_id" {
			t.Fatalf("db error = %#v, want PronunciationRules persist_dictionary_id", dbErr)
		}
	})

	t.Run("create persist missing settings row returns not initialized error", func(t *testing.T) {
		repo := &pronunciationSettingsRepoMock{
			settings: &models.TTSSettings{},
			setErr:   repository.ErrNotFound,
		}
		client := &pronunciationDictionaryClientMock{
			createFn: func(ctx context.Context, name, description string, rules []tts.Rule) (tts.DictionaryState, error) {
				return tts.DictionaryState{ID: "dict-new", LatestVersionID: "v1", Rules: rules}, nil
			},
		}
		service := &PronunciationRulesService{settingsRepo: repo, client: client}

		_, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{
			Rules: []PronunciationRuleUpdate{{StringToReplace: "A", Alias: "aa"}},
		})
		var notInitialized *apperrors.NotInitializedError
		if !errors.As(err, &notInitialized) {
			t.Fatalf("error type = %T, want *NotInitializedError", err)
		}
		if notInitialized.Code != "tts_settings.row_missing" {
			t.Fatalf("code = %q, want tts_settings.row_missing", notInitialized.Code)
		}
	})
}

func assertWrapsAPIError(t *testing.T, got error) {
	t.Helper()

	var apiErr *tts.APIError
	if !errors.As(got, &apiErr) {
		t.Fatalf("translated error does not wrap original API error: %v", got)
	}
}

func assertPronunciationRulesTranslation(
	t *testing.T,
	got error,
	wantKind string,
	wantStatus int,
	wantField string,
	wantRetry string,
	wantMessage string,
) {
	t.Helper()

	switch wantKind {
	case "upstream":
		assertUpstreamError(t, got, wantStatus)
	case "validation":
		assertPronunciationRulesValidationProblem(t, got, wantField, wantMessage)
	case "rate_limited":
		assertPronunciationRulesRateLimited(t, got, wantRetry)
	default:
		t.Fatalf("unknown wantKind %q", wantKind)
	}
}

func assertPronunciationRulesValidationProblem(t *testing.T, got error, wantField, wantMessage string) {
	t.Helper()

	var validationErr *apperrors.ValidationProblemError
	if !errors.As(got, &validationErr) {
		t.Fatalf("error type = %T, want *ValidationProblemError", got)
	}
	if validationErr.Detail != "ElevenLabs rejected the pronunciation rules" {
		t.Fatalf("detail = %q, want sanitized detail", validationErr.Detail)
	}
	if len(validationErr.Errors) != 1 ||
		validationErr.Errors[0].Field != wantField ||
		validationErr.Errors[0].Message != wantMessage {
		t.Fatalf("validation errors = %#v, want %s %q", validationErr.Errors, wantField, wantMessage)
	}
	if strings.Contains(validationErr.Error(), "private upstream details") ||
		strings.Contains(validationErr.Errors[0].Message, "private upstream details") {
		t.Fatalf("validation error leaked raw body: %#v", validationErr)
	}
}

func assertPronunciationRulesRateLimited(t *testing.T, got error, wantRetry string) {
	t.Helper()

	var rateLimited *apperrors.RateLimitedError
	if !errors.As(got, &rateLimited) {
		t.Fatalf("error type = %T, want *RateLimitedError", got)
	}
	if rateLimited.RetryAfter != wantRetry {
		t.Fatalf("RetryAfter = %q, want %q", rateLimited.RetryAfter, wantRetry)
	}
}

func TestDiffPronunciationRules(t *testing.T) {
	before := []tts.Rule{
		{StringToReplace: "A", Alias: "aa", CaseSensitive: true, WordBoundaries: true},
		{StringToReplace: "B", Alias: "bb", CaseSensitive: true, WordBoundaries: true},
		{StringToReplace: "C", Alias: "cc", CaseSensitive: true, WordBoundaries: true},
	}
	after := []tts.Rule{
		{StringToReplace: "A", Alias: "aa", CaseSensitive: true, WordBoundaries: true},
		{StringToReplace: "B", Alias: "bee", CaseSensitive: true, WordBoundaries: true},
		{StringToReplace: "D", Alias: "dd", CaseSensitive: true, WordBoundaries: true},
	}

	diff := diffPronunciationRules(before, after)
	if diff.Added != 1 || diff.Changed != 1 || diff.Removed != 1 || diff.Unchanged != 1 {
		t.Fatalf("diff = %#v, want 1 added/changed/removed/unchanged", diff)
	}
	if diff.Added+diff.Changed+diff.Unchanged != diff.TotalAfter {
		t.Fatalf("after invariant failed: %#v", diff)
	}
	if diff.Removed+diff.Changed+diff.Unchanged != diff.TotalBefore {
		t.Fatalf("before invariant failed: %#v", diff)
	}
}

type pronunciationSettingsRepoMock struct {
	settings *models.TTSSettings
	getErr   error
	setErr   error
	setIDs   []*string
}

func (m *pronunciationSettingsRepoMock) Get(ctx context.Context) (*models.TTSSettings, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.settings, nil
}

func (m *pronunciationSettingsRepoMock) SetPronunciationDictionaryID(ctx context.Context, id *string) error {
	if m.setErr != nil {
		return m.setErr
	}
	if id == nil {
		m.setIDs = append(m.setIDs, nil)
		return nil
	}
	value := *id
	m.setIDs = append(m.setIDs, &value)
	return nil
}

type createDictionaryCall struct {
	name        string
	description string
	rules       []tts.Rule
}

type pronunciationDictionaryClientMock struct {
	createFn func(ctx context.Context, name, description string, rules []tts.Rule) (tts.DictionaryState, error)
	getFn    func(ctx context.Context, id string) (tts.DictionaryState, error)
	setFn    func(ctx context.Context, id string, rules []tts.Rule) (tts.SetRulesResult, error)

	createCalls []createDictionaryCall
}

func (m *pronunciationDictionaryClientMock) CreateDictionaryFromRules(
	ctx context.Context,
	name string,
	description string,
	rules []tts.Rule,
) (tts.DictionaryState, error) {
	m.createCalls = append(m.createCalls, createDictionaryCall{name: name, description: description, rules: rules})
	if m.createFn != nil {
		return m.createFn(ctx, name, description, rules)
	}
	return tts.DictionaryState{}, errors.New("unexpected CreateDictionaryFromRules call")
}

func (m *pronunciationDictionaryClientMock) GetDictionary(ctx context.Context, id string) (tts.DictionaryState, error) {
	if m.getFn != nil {
		return m.getFn(ctx, id)
	}
	return tts.DictionaryState{}, errors.New("unexpected GetDictionary call")
}

func (m *pronunciationDictionaryClientMock) SetRules(
	ctx context.Context,
	id string,
	rules []tts.Rule,
) (tts.SetRulesResult, error) {
	if m.setFn != nil {
		return m.setFn(ctx, id, rules)
	}
	return tts.SetRulesResult{}, errors.New("unexpected SetRules call")
}
