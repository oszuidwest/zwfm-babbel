package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"gorm.io/gorm"
)

func TestPronunciationRulesResponseMapping(t *testing.T) {
	updatedAt := time.Unix(1717200000, 0).UTC()
	got := toPronunciationRulesResponse(&services.PronunciationRulesResponse{
		Rules: []models.PronunciationRule{{
			StringToReplace: "Albert Heijn",
			IPA:             "ˈɑlbərt ˈɦɛin",
			CaseSensitive:   true,
			WordBoundaries:  false,
		}},
		UpdatedAt: &updatedAt,
	})

	if len(got.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(got.Rules))
	}
	rule := got.Rules[0]
	if rule.StringToReplace != "Albert Heijn" ||
		rule.IPA != "ˈɑlbərt ˈɦɛin" ||
		!rule.CaseSensitive ||
		rule.WordBoundaries {
		t.Fatalf("rule = %#v, want mapped pronunciation rule", rule)
	}
	if got.UpdatedAt == nil || !got.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("updated_at = %v, want %v", got.UpdatedAt, updatedAt)
	}
}

func TestPronunciationRulesServiceRequestMapping(t *testing.T) {
	caseSensitive := false
	req := pronunciationRulesUpdateRequest{
		Rules: []pronunciationRuleUpdateRequest{{
			StringToReplace: "PSV",
			IPA:             "piː ɛs veː",
			CaseSensitive:   &caseSensitive,
		}},
	}

	got := toPronunciationRulesServiceRequest(req)

	if len(got.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(got.Rules))
	}
	rule := got.Rules[0]
	if rule.StringToReplace != "PSV" || rule.IPA != "piː ɛs veː" {
		t.Fatalf("rule text = %#v, want mapped fields", rule)
	}
	if rule.CaseSensitive == nil || *rule.CaseSensitive {
		t.Fatalf("case_sensitive = %v, want explicit false pointer", rule.CaseSensitive)
	}
	if rule.WordBoundaries != nil {
		t.Fatalf("word_boundaries = %v, want nil preserved for service defaulting", rule.WordBoundaries)
	}
}

func TestPronunciationRulesHandlers_UpdateBinding(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantCode  int
		wantField string
	}{
		{
			name:      "missing rules",
			body:      `{}`,
			wantCode:  http.StatusUnprocessableEntity,
			wantField: "Rules",
		},
		{
			name:      "alias is an unknown strict-binding field",
			body:      `{"rules":[{"string_to_replace":"A","alias":"aa"}]}`,
			wantCode:  http.StatusBadRequest,
			wantField: "alias",
		},
		{
			name:      "unknown actor user id is rejected",
			body:      `{"rules":[],"actor_user_id":1}`,
			wantCode:  http.StatusBadRequest,
			wantField: "actor_user_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{}

			recorder := performPronunciationRulesHandlerRequest(
				t,
				http.MethodPut,
				tt.body,
				h.UpdatePronunciationRules,
			)

			if recorder.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, tt.wantCode, recorder.Body.String())
			}
			assertValidationField(t, recorder, tt.wantField)
		})
	}
}

func TestPronunciationRulesHandlers_UpdateEmptyRulesSuccess(t *testing.T) {
	h := &Handlers{
		pronunciationRulesSvc: services.NewPronunciationRulesService(
			&handlerPronunciationRuleRepo{},
			&handlerTxManager{},
		),
	}

	recorder := performPronunciationRulesHandlerRequest(
		t,
		http.MethodPut,
		`{"rules":[]}`,
		h.UpdatePronunciationRules,
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var body pronunciationRulesResponse
	decodeHandlerJSON(t, recorder, &body)
	if len(body.Rules) != 0 {
		t.Fatalf("rules len = %d, want 0", len(body.Rules))
	}
}

func TestPronunciationRulesHandlers_GetSuccess(t *testing.T) {
	updatedAt := time.Unix(1717200000, 0).UTC()
	h := &Handlers{
		pronunciationRulesSvc: services.NewPronunciationRulesService(
			&handlerPronunciationRuleRepo{
				rules: []models.PronunciationRule{{
					StringToReplace: "PSV",
					IPA:             "piː ɛs veː",
					CaseSensitive:   true,
					WordBoundaries:  false,
				}},
				updatedAt: &updatedAt,
			},
			nil,
		),
	}

	recorder := performPronunciationRulesHandlerRequest(t, http.MethodGet, "", h.GetPronunciationRules)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var body pronunciationRulesResponse
	decodeHandlerJSON(t, recorder, &body)
	if len(body.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(body.Rules))
	}
	if body.Rules[0].StringToReplace != "PSV" ||
		body.Rules[0].IPA != "piː ɛs veː" ||
		!body.Rules[0].CaseSensitive ||
		body.Rules[0].WordBoundaries {
		t.Fatalf("rule = %#v, want mapped response", body.Rules[0])
	}
	if body.UpdatedAt == nil || !body.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("updated_at = %v, want %v", body.UpdatedAt, updatedAt)
	}
}

func TestPronunciationRulesHandlers_GetServiceError(t *testing.T) {
	h := &Handlers{
		pronunciationRulesSvc: services.NewPronunciationRulesService(
			&handlerPronunciationRuleRepo{listErr: errors.New("database down")},
			nil,
		),
	}

	recorder := performPronunciationRulesHandlerRequest(t, http.MethodGet, "", h.GetPronunciationRules)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/problem+json" {
		t.Fatalf("content-type = %q, want application/problem+json", contentType)
	}
	problem := decodeProblem(t, recorder)
	if problem.Status != http.StatusInternalServerError || problem.Code != "internal.database_error" {
		t.Fatalf("problem = %#v, want database problem details", problem)
	}
}

func TestPronunciationRulesHandlers_GetNotInitialized(t *testing.T) {
	h := &Handlers{
		pronunciationRulesSvc: services.NewPronunciationRulesService(
			&handlerPronunciationRuleRepo{listErr: repository.ErrSchemaUnavailable},
			nil,
		),
	}

	recorder := performPronunciationRulesHandlerRequest(t, http.MethodGet, "", h.GetPronunciationRules)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}
	problem := decodeProblem(t, recorder)
	if problem.Status != http.StatusServiceUnavailable || problem.Code != "pronunciation_rules.not_initialized" {
		t.Fatalf("problem = %#v, want not-initialized problem details", problem)
	}
}

func performPronunciationRulesHandlerRequest(
	t *testing.T,
	method string,
	body string,
	handler gin.HandlerFunc,
) *httptest.ResponseRecorder {
	t.Helper()

	const path = "/settings/tts/pronunciations"

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Handle(method, path, handler)

	reader := bytes.NewReader([]byte(body))
	request := httptest.NewRequestWithContext(context.Background(), method, path, reader)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)
	return recorder
}

func decodeHandlerJSON(t *testing.T, recorder *httptest.ResponseRecorder, out any) {
	t.Helper()

	if err := json.Unmarshal(recorder.Body.Bytes(), out); err != nil {
		t.Fatalf("decode response JSON: %v; body=%s", err, recorder.Body.String())
	}
}

func assertValidationField(t *testing.T, recorder *httptest.ResponseRecorder, want string) {
	t.Helper()

	var body struct {
		Errors []apperrors.ValidationError `json:"errors"`
	}
	decodeHandlerJSON(t, recorder, &body)
	if len(body.Errors) == 0 {
		t.Fatalf("errors = %#v, want at least one field", body.Errors)
	}
	if body.Errors[0].Field != want {
		t.Fatalf("first field = %q, want %q; body=%s", body.Errors[0].Field, want, recorder.Body.String())
	}
}

type handlerPronunciationRuleRepo struct {
	rules     []models.PronunciationRule
	listErr   error
	updatedAt *time.Time
	maxErr    error
}

func (h *handlerPronunciationRuleRepo) List(context.Context) ([]models.PronunciationRule, error) {
	if h.listErr != nil {
		return nil, h.listErr
	}
	rules := make([]models.PronunciationRule, len(h.rules))
	copy(rules, h.rules)
	return rules, nil
}

func (h *handlerPronunciationRuleRepo) ReplaceAll(context.Context, []models.PronunciationRule) error {
	return nil
}

func (h *handlerPronunciationRuleRepo) MaxUpdatedAt(context.Context) (*time.Time, error) {
	if h.maxErr != nil {
		return nil, h.maxErr
	}
	return h.updatedAt, nil
}

type handlerTxManager struct{}

func (h *handlerTxManager) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (h *handlerTxManager) DB() *gorm.DB {
	return nil
}
