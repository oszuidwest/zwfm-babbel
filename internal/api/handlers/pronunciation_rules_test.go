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
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
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

// TestPronunciationRulesHandlers_UpdateAppliesPointerSemantics drives JSON
// through the full handler → mapper → service round-trip to verify that
// *bool fields keep "explicit false" and that omitted flags default to true.
func TestPronunciationRulesHandlers_UpdateAppliesPointerSemantics(t *testing.T) {
	tests := []struct {
		name              string
		body              string
		seedRules         []models.PronunciationRule
		wantLen           int
		wantCaseSensitive bool
		wantWordBound     bool
	}{
		{
			name:              "explicit false case_sensitive preserved, missing word_boundaries defaults to true",
			body:              `{"rules":[{"string_to_replace":"PSV","ipa":"piː ɛs veː","case_sensitive":false}]}`,
			wantLen:           1,
			wantCaseSensitive: false,
			wantWordBound:     true,
		},
		{
			name:              "explicit false word_boundaries preserved, missing case_sensitive defaults to true",
			body:              `{"rules":[{"string_to_replace":"PSV","ipa":"piː ɛs veː","word_boundaries":false}]}`,
			wantLen:           1,
			wantCaseSensitive: true,
			wantWordBound:     false,
		},
		{
			name:      "empty rules array clears a previously populated table",
			body:      `{"rules":[]}`,
			seedRules: []models.PronunciationRule{{StringToReplace: "OLD", IPA: "oʊld"}},
			wantLen:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{
				pronunciationRulesSvc: services.NewPronunciationRulesService(
					&handlerPronunciationRuleRepo{rules: tt.seedRules},
					&handlerTxManager{},
				),
			}

			recorder := performPronunciationRulesHandlerRequest(
				t, http.MethodPut, tt.body, h.UpdatePronunciationRules,
			)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
			}
			var body pronunciationRulesResponse
			decodeHandlerJSON(t, recorder, &body)
			if len(body.Rules) != tt.wantLen {
				t.Fatalf("rules len = %d, want %d", len(body.Rules), tt.wantLen)
			}
			if tt.wantLen == 0 {
				return
			}
			if body.Rules[0].CaseSensitive != tt.wantCaseSensitive {
				t.Fatalf("case_sensitive = %v, want %v", body.Rules[0].CaseSensitive, tt.wantCaseSensitive)
			}
			if body.Rules[0].WordBoundaries != tt.wantWordBound {
				t.Fatalf("word_boundaries = %v, want %v", body.Rules[0].WordBoundaries, tt.wantWordBound)
			}
		})
	}
}

// TestPronunciationRulesHandlers_UpdatePropagatesActorUserID locks in the
// audit-trail contract: the authenticated user from the gin context must reach
// the service request as ActorUserID, and an unauthenticated request must leave
// it nil (the service logs user_id=unknown in that case). A request-capturing
// fake stands in for the real service so the assertion fails if the handler's
// auth.UserID -> ActorUserID assignment is dropped or retargeted.
func TestPronunciationRulesHandlers_UpdatePropagatesActorUserID(t *testing.T) {
	const userID int64 = 42

	tests := []struct {
		name         string
		withAuth     bool
		wantActorSet bool
	}{
		{name: "auth context populates actor user id", withAuth: true, wantActorSet: true},
		{name: "missing auth context leaves actor user id nil", withAuth: false, wantActorSet: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &capturingPronunciationRulesService{
				updateResp: &services.PronunciationRulesResponse{},
			}
			h := &Handlers{pronunciationRulesSvc: svc}

			var middlewares []gin.HandlerFunc
			if tt.withAuth {
				middlewares = append(middlewares, func(c *gin.Context) {
					auth.SetUserContext(c, auth.UserContext{UserID: userID})
				})
			}

			recorder := performPronunciationRulesHandlerRequest(
				t, http.MethodPut, `{"rules":[]}`, h.UpdatePronunciationRules, middlewares...,
			)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
			}
			if svc.capturedReq == nil {
				t.Fatalf("Update was not called")
			}

			got := svc.capturedReq.ActorUserID
			if tt.wantActorSet {
				if got == nil || *got != userID {
					t.Fatalf("ActorUserID = %v, want %d", got, userID)
				}
			} else if got != nil {
				t.Fatalf("ActorUserID = %d, want nil", *got)
			}
		})
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
	middlewares ...gin.HandlerFunc,
) *httptest.ResponseRecorder {
	t.Helper()

	const path = "/settings/tts/pronunciations"

	gin.SetMode(gin.TestMode)
	router := gin.New()
	chain := append(append([]gin.HandlerFunc{}, middlewares...), handler)
	router.Handle(method, path, chain...)

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

// capturingPronunciationRulesService records the request passed to Update so a
// test can assert how the handler populated it (notably ActorUserID).
type capturingPronunciationRulesService struct {
	updateResp  *services.PronunciationRulesResponse
	capturedReq *services.UpdatePronunciationRulesRequest
}

// Get exists only to satisfy pronunciationRulesService; no test exercises it.
func (s *capturingPronunciationRulesService) Get(context.Context) (*services.PronunciationRulesResponse, error) {
	return nil, nil
}

func (s *capturingPronunciationRulesService) Update(
	_ context.Context,
	req *services.UpdatePronunciationRulesRequest,
) (*services.PronunciationRulesResponse, error) {
	s.capturedReq = req
	return s.updateResp, nil
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

func (h *handlerPronunciationRuleRepo) ReplaceAll(_ context.Context, rules []models.PronunciationRule) error {
	h.rules = rules
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

// DB is unused by PronunciationRulesService; nil is safe here.
func (h *handlerTxManager) DB() *gorm.DB {
	return nil
}
