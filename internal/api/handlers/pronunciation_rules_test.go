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
	"github.com/oszuidwest/zwfm-babbel/internal/services"
)

func TestPronunciationRulesHandlers_Get(t *testing.T) {
	updatedAt := time.Unix(1717200000, 0).UTC()
	svc := &pronunciationRulesHandlerServiceMock{
		getResp: &services.PronunciationRulesResponse{
			Rules: []models.PronunciationRule{{
				StringToReplace: "Albert Heijn",
				IPA:             "ˈɑlbərt ˈɦɛin",
				CaseSensitive:   true,
				WordBoundaries:  false,
			}},
			UpdatedAt: &updatedAt,
		},
	}
	h := &Handlers{ttsEnabled: false, pronunciationRulesSvc: svc}

	recorder := performPronunciationRulesHandlerRequest(t, http.MethodGet, "", h.GetPronunciationRules)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Rules []struct {
			StringToReplace string `json:"string_to_replace"`
			IPA             string `json:"ipa"`
			CaseSensitive   bool   `json:"case_sensitive"`
			WordBoundaries  bool   `json:"word_boundaries"`
		} `json:"rules"`
		UpdatedAt *time.Time `json:"updated_at"`
	}
	decodeHandlerJSON(t, recorder, &body)
	if len(body.Rules) != 1 || body.Rules[0].IPA != "ˈɑlbərt ˈɦɛin" {
		t.Fatalf("body = %#v, want IPA rule", body)
	}
	if body.UpdatedAt == nil || !body.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("updated_at = %v, want %v", body.UpdatedAt, updatedAt)
	}
}

func TestPronunciationRulesHandlers_GetServiceError(t *testing.T) {
	svc := &pronunciationRulesHandlerServiceMock{
		getErr: apperrors.Database("PronunciationRules", "query", errors.New("db failed")),
	}
	h := &Handlers{ttsEnabled: false, pronunciationRulesSvc: svc}

	recorder := performPronunciationRulesHandlerRequest(t, http.MethodGet, "", h.GetPronunciationRules)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	decodeHandlerJSON(t, recorder, &body)
	if body["code"] != "internal.database_error" {
		t.Fatalf("code = %#v, want internal.database_error", body["code"])
	}
}

// TestPronunciationRulesHandlers_NilServiceGuard pins the requirePronunciationRulesService
// guard: a misconfigured Handlers struct must return 500 instead of nil-derefing.
func TestPronunciationRulesHandlers_NilServiceGuard(t *testing.T) {
	h := &Handlers{ttsEnabled: true, pronunciationRulesSvc: nil}

	recorder := performPronunciationRulesHandlerRequest(t, http.MethodGet, "", h.GetPronunciationRules)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body.String())
	}
}

func TestPronunciationRulesHandlers_UpdateBinding(t *testing.T) {
	t.Run("missing rules returns 422 with top-level Go field", func(t *testing.T) {
		svc := &pronunciationRulesHandlerServiceMock{}
		h := &Handlers{ttsEnabled: false, pronunciationRulesSvc: svc}

		recorder := performPronunciationRulesHandlerRequest(
			t,
			http.MethodPut,
			`{}`,
			h.UpdatePronunciationRules,
		)

		if recorder.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422: %s", recorder.Code, recorder.Body.String())
		}
		if svc.updateReq != nil {
			t.Fatalf("service was called for invalid request: %#v", svc.updateReq)
		}
		assertValidationField(t, recorder, "Rules")
	})

	t.Run("empty rules array reaches service for clear path", func(t *testing.T) {
		svc := &pronunciationRulesHandlerServiceMock{
			updateResp: &services.PronunciationRulesResponse{Rules: []models.PronunciationRule{}},
		}
		h := &Handlers{ttsEnabled: false, pronunciationRulesSvc: svc}

		recorder := performPronunciationRulesHandlerRequest(
			t,
			http.MethodPut,
			`{"rules":[]}`,
			h.UpdatePronunciationRules,
		)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
		}
		if svc.updateReq == nil || len(svc.updateReq.Rules) != 0 {
			t.Fatalf("update request = %#v, want empty rules", svc.updateReq)
		}
	})

	t.Run("null booleans are passed as nil for service defaults", func(t *testing.T) {
		svc := &pronunciationRulesHandlerServiceMock{
			updateResp: &services.PronunciationRulesResponse{Rules: []models.PronunciationRule{}},
		}
		h := &Handlers{ttsEnabled: false, pronunciationRulesSvc: svc}

		recorder := performPronunciationRulesHandlerRequest(
			t,
			http.MethodPut,
			`{"rules":[{"string_to_replace":"A","ipa":"aː","case_sensitive":null,"word_boundaries":null}]}`,
			h.UpdatePronunciationRules,
		)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
		}
		if svc.updateReq == nil || len(svc.updateReq.Rules) != 1 {
			t.Fatalf("update request = %#v, want one rule", svc.updateReq)
		}
		rule := svc.updateReq.Rules[0]
		if rule.IPA != "aː" {
			t.Fatalf("IPA = %q, want aː", rule.IPA)
		}
		if rule.CaseSensitive != nil || rule.WordBoundaries != nil {
			t.Fatalf("booleans = %v/%v, want nil/nil", rule.CaseSensitive, rule.WordBoundaries)
		}
	})

	t.Run("alias is a removed strict-binding field", func(t *testing.T) {
		svc := &pronunciationRulesHandlerServiceMock{}
		h := &Handlers{ttsEnabled: false, pronunciationRulesSvc: svc}

		recorder := performPronunciationRulesHandlerRequest(
			t,
			http.MethodPut,
			`{"rules":[{"string_to_replace":"A","alias":"aa"}]}`,
			h.UpdatePronunciationRules,
		)

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
		}
		if svc.updateReq != nil {
			t.Fatalf("service was called for invalid request: %#v", svc.updateReq)
		}
		assertValidationField(t, recorder, "alias")
	})

	t.Run("service validation returns JSON path field", func(t *testing.T) {
		svc := &pronunciationRulesHandlerServiceMock{
			updateErr: apperrors.NewValidationProblemError(
				"pronunciation_rules",
				"One or more fields failed validation",
				[]apperrors.ValidationError{{Field: "rules[0].ipa", Message: "cannot be empty"}},
			),
		}
		h := &Handlers{ttsEnabled: false, pronunciationRulesSvc: svc}

		recorder := performPronunciationRulesHandlerRequest(
			t,
			http.MethodPut,
			`{"rules":[{"string_to_replace":"A","ipa":" "}]}`,
			h.UpdatePronunciationRules,
		)

		if recorder.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422: %s", recorder.Code, recorder.Body.String())
		}
		assertValidationField(t, recorder, "rules[0].ipa")
	})
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

	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
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
		Errors []struct {
			Field string `json:"field"`
		} `json:"errors"`
	}
	decodeHandlerJSON(t, recorder, &body)
	if len(body.Errors) == 0 {
		t.Fatalf("errors = %#v, want at least one field", body.Errors)
	}
	if body.Errors[0].Field != want {
		t.Fatalf("first field = %q, want %q; body=%s", body.Errors[0].Field, want, recorder.Body.String())
	}
}

type pronunciationRulesHandlerServiceMock struct {
	getResp    *services.PronunciationRulesResponse
	getErr     error
	updateResp *services.PronunciationRulesResponse
	updateErr  error
	updateReq  *services.UpdatePronunciationRulesRequest
}

func (m *pronunciationRulesHandlerServiceMock) Get(ctx context.Context) (*services.PronunciationRulesResponse, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.getResp == nil {
		return &services.PronunciationRulesResponse{Rules: []models.PronunciationRule{}}, nil
	}
	return m.getResp, nil
}

func (m *pronunciationRulesHandlerServiceMock) Update(
	ctx context.Context,
	req *services.UpdatePronunciationRulesRequest,
) (*services.PronunciationRulesResponse, error) {
	m.updateReq = req
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	if m.updateResp == nil {
		return nil, errors.New("unexpected Update call")
	}
	return m.updateResp, nil
}
