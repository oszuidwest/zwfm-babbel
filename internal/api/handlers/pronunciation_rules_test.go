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
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
)

func TestPronunciationRulesHandlers_Get(t *testing.T) {
	createdAt := time.Unix(1717200000, 0).UTC()
	warning := "missing"
	svc := &pronunciationRulesHandlerServiceMock{
		getResp: &services.PronunciationRulesResponse{
			Rules: []tts.Rule{{
				StringToReplace: "Albert Heijn",
				Alias:           "albert hijn",
				CaseSensitive:   true,
				WordBoundaries:  false,
			}},
			LatestVersionID: ptr("v1"),
			CreatedAt:       &createdAt,
			Warning:         &warning,
		},
	}
	h := &Handlers{ttsEnabled: true, pronunciationRulesSvc: svc}

	recorder := performPronunciationRulesHandlerRequest(t, http.MethodGet, "", h.GetPronunciationRules)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	decodeHandlerJSON(t, recorder, &body)
	if body["warning"] != warning || body["latest_version_id"] != "v1" {
		t.Fatalf("body = %#v, want warning and latest_version_id", body)
	}
}

func TestPronunciationRulesHandlers_NotConfigured(t *testing.T) {
	h := &Handlers{ttsEnabled: false}

	recorder := performPronunciationRulesHandlerRequest(t, http.MethodGet, "", h.GetPronunciationRules)

	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501: %s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	decodeHandlerJSON(t, recorder, &body)
	if body["code"] != "tts.not_configured" {
		t.Fatalf("code = %#v, want tts.not_configured", body["code"])
	}
}

func TestPronunciationRulesHandlers_UpdateBinding(t *testing.T) {
	t.Run("missing rules returns 422 with top-level Go field", func(t *testing.T) {
		svc := &pronunciationRulesHandlerServiceMock{}
		h := &Handlers{ttsEnabled: true, pronunciationRulesSvc: svc}

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
			updateResp: &services.PronunciationRulesResponse{Rules: []tts.Rule{}},
		}
		h := &Handlers{ttsEnabled: true, pronunciationRulesSvc: svc}

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
			updateResp: &services.PronunciationRulesResponse{Rules: []tts.Rule{}},
		}
		h := &Handlers{ttsEnabled: true, pronunciationRulesSvc: svc}

		recorder := performPronunciationRulesHandlerRequest(
			t,
			http.MethodPut,
			`{"rules":[{"string_to_replace":"A","alias":"aa","case_sensitive":null,"word_boundaries":null}]}`,
			h.UpdatePronunciationRules,
		)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
		}
		if svc.updateReq == nil || len(svc.updateReq.Rules) != 1 {
			t.Fatalf("update request = %#v, want one rule", svc.updateReq)
		}
		rule := svc.updateReq.Rules[0]
		if rule.CaseSensitive != nil || rule.WordBoundaries != nil {
			t.Fatalf("booleans = %v/%v, want nil/nil", rule.CaseSensitive, rule.WordBoundaries)
		}
	})

	t.Run("service validation returns JSON path field", func(t *testing.T) {
		svc := &pronunciationRulesHandlerServiceMock{
			updateErr: apperrors.NewValidationProblemError(
				"pronunciation_rules",
				"One or more fields failed validation",
				[]apperrors.ValidationError{{Field: "rules[0].alias", Message: "cannot be empty"}},
			),
		}
		h := &Handlers{ttsEnabled: true, pronunciationRulesSvc: svc}

		recorder := performPronunciationRulesHandlerRequest(
			t,
			http.MethodPut,
			`{"rules":[{"string_to_replace":"A","alias":" "}]}`,
			h.UpdatePronunciationRules,
		)

		if recorder.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422: %s", recorder.Code, recorder.Body.String())
		}
		assertValidationField(t, recorder, "rules[0].alias")
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
		return &services.PronunciationRulesResponse{Rules: []tts.Rule{}}, nil
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

func ptr[T any](value T) *T {
	return &value
}
