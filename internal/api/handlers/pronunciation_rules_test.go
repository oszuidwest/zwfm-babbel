package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
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
			name:      "alias is a removed strict-binding field",
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
