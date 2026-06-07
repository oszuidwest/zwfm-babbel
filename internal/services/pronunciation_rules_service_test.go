package services

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
)

func TestMaterializePronunciationRules(t *testing.T) {
	falseValue := false

	t.Run("defaults omitted booleans to true", func(t *testing.T) {
		rules, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
			Rules: []PronunciationRuleUpdate{{
				StringToReplace: "Albert Heijn",
				Alias:           "albert hijn",
			}},
		})
		if err != nil {
			t.Fatalf("materializePronunciationRules() error = %v", err)
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
				{StringToReplace: "ZuidWest", Alias: "zuit west"},
				{StringToReplace: "ZuidWest", Alias: "zuit west opnieuw"},
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

func TestPronunciationRulesService_Translations(t *testing.T) {
	t.Run("upstream 422 maps to validation problem", func(t *testing.T) {
		err := translatePronunciationRulesUpstreamError(&tts.APIError{
			StatusCode: http.StatusUnprocessableEntity,
			Body:       `{"detail":"invalid rule"}`,
		})
		var validationErr *apperrors.ValidationProblemError
		if !errors.As(err, &validationErr) {
			t.Fatalf("error type = %T, want *ValidationProblemError", err)
		}
	})

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
