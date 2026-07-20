package services

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
)

type generateTTSTestContextKey struct{}

func TestComposeV3TTSText(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		prefix string
		want   string
	}{
		{
			name:   "applies non-empty prefix",
			text:   "Hallo",
			prefix: "[news anchor]",
			want:   "[news anchor]\nHallo",
		},
		{
			name:   "trims blank prefix",
			text:   "Hallo",
			prefix: "  \t\n",
			want:   "Hallo",
		},
		{
			name: "empty prefix",
			text: "Hallo",
			want: "Hallo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := composeV3TTSText(tt.text, tt.prefix); got != tt.want {
				t.Fatalf("composeV3TTSText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateTTSTextLength(t *testing.T) {
	withinLimit := strings.Repeat("é", tts.MaxV3InputChars)
	overLimit := withinLimit + "ë"

	if err := validateTTSTextLength(withinLimit); err != nil {
		t.Fatalf("validateTTSTextLength within limit returned error: %v", err)
	}

	err := validateTTSTextLength(overLimit)
	if err == nil {
		t.Fatal("validateTTSTextLength over limit returned nil")
	}

	var validationErr *apperrors.ValidationProblemError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error type = %T, want *apperrors.ValidationProblemError", err)
	}
	if validationErr.Resource != "story" || len(validationErr.Errors) != 1 || validationErr.Errors[0].Field != "text" {
		t.Fatalf("validation error = %#v, want one story.text error", validationErr)
	}
	if validationErr.Detail != "Text exceeds ElevenLabs v3 input limit" {
		t.Fatalf("detail = %q, want ElevenLabs v3 limit detail", validationErr.Detail)
	}

	wantMessage := "rune count " + strconv.Itoa(tts.MaxV3InputChars+1) +
		" exceeds ElevenLabs v3 input limit of " + strconv.Itoa(tts.MaxV3InputChars)
	if !strings.Contains(validationErr.Errors[0].Message, wantMessage) {
		t.Fatalf("message = %q, want %q", validationErr.Errors[0].Message, wantMessage)
	}
}

func TestStoryService_GenerateTTSAppliesPronunciationBeforePrefix(t *testing.T) {
	stopErr := errors.New("stop after capture")
	ttsSvc := &fakeSpeechGenerator{err: stopErr}
	service := newGenerateTTSTestService(
		storyForTTSTest("PSV wint"),
		&models.TTSSettings{
			TTSStylePrefix:         "[news anchor]",
			ApplyTextNormalization: TTSNormalizationAuto,
		},
		[]models.PronunciationRule{rule("PSV", "piː ɛs ʋeː", true, true)},
		ttsSvc,
	)

	ctx := context.WithValue(context.Background(), generateTTSTestContextKey{}, "preserved")
	err := service.GenerateTTS(ctx, 99, false)
	if !errors.Is(err, stopErr) {
		t.Fatalf("GenerateTTS() error = %v, want wrapped stop error", err)
	}
	if ttsSvc.calls != 1 {
		t.Fatalf("GenerateSpeech calls = %d, want 1", ttsSvc.calls)
	}

	wantText := "[news anchor]\n/piː ɛs ʋeː/ wint"
	if ttsSvc.text != wantText {
		t.Fatalf("GenerateSpeech text = %q, want %q", ttsSvc.text, wantText)
	}
	if ttsSvc.ctx == ctx {
		t.Fatal("GenerateSpeech context is original context, want child context with story correlation")
	}
	if got := ttsSvc.ctx.Value(generateTTSTestContextKey{}); got != "preserved" {
		t.Fatalf("GenerateSpeech context preserved value = %v, want preserved", got)
	}
}

func TestStoryService_GenerateTTSValidatesComposedTextBeforeTTS(t *testing.T) {
	ttsSvc := &fakeSpeechGenerator{}
	service := newGenerateTTSTestService(
		storyForTTSTest("PSV"),
		&models.TTSSettings{
			TTSStylePrefix:         "[news anchor]",
			ApplyTextNormalization: TTSNormalizationAuto,
		},
		[]models.PronunciationRule{
			rule("PSV", strings.Repeat("a", tts.MaxV3InputChars), true, true),
		},
		ttsSvc,
	)

	err := service.GenerateTTS(context.Background(), 99, false)
	var validationErr *apperrors.ValidationProblemError
	if !errors.As(err, &validationErr) {
		t.Fatalf("GenerateTTS() error = %T, want *apperrors.ValidationProblemError", err)
	}
	if ttsSvc.calls != 0 {
		t.Fatalf("GenerateSpeech calls = %d, want 0", ttsSvc.calls)
	}
}

func TestTTSOptionsFromSettings(t *testing.T) {
	seed := uint32(42)

	options := ttsOptionsFromSettings(&models.TTSSettings{
		Stability:              0.8,
		SimilarityBoost:        0.7,
		Style:                  0.2,
		Speed:                  1.0,
		ApplyTextNormalization: TTSNormalizationAuto,
		Seed:                   &seed,
	})

	if options.Seed == nil || *options.Seed != seed {
		t.Fatalf("seed = %v, want %d", options.Seed, seed)
	}
	if options.ApplyTextNormalization != TTSNormalizationAuto {
		t.Fatalf("normalization = %q, want %q", options.ApplyTextNormalization, TTSNormalizationAuto)
	}
	if options.VoiceSettings.Stability != 0.8 ||
		options.VoiceSettings.SimilarityBoost != 0.7 ||
		options.VoiceSettings.Style != 0.2 ||
		options.VoiceSettings.Speed != 1.0 {
		t.Fatalf("voice settings = %#v", options.VoiceSettings)
	}
}

func TestTranslateTTSError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		assert func(t *testing.T, got error)
	}{
		{
			name: "unauthorized maps to upstream service unavailable",
			err:  &tts.APIError{StatusCode: http.StatusUnauthorized, Body: "bad key"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				assertUpstreamError(t, got, http.StatusServiceUnavailable)
			},
		},
		{
			name: "forbidden maps to upstream service unavailable",
			err:  &tts.APIError{StatusCode: http.StatusForbidden, Body: "forbidden"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				assertUpstreamError(t, got, http.StatusServiceUnavailable)
			},
		},
		{
			name: "voice not found maps to voice validation",
			err:  &tts.APIError{StatusCode: http.StatusNotFound, Body: "voice missing"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				assertValidationError(t, got, "Voice", "elevenlabs_voice_id")
			},
		},
		{
			name: "rate limited preserves retry after",
			err:  &tts.APIError{StatusCode: http.StatusTooManyRequests, Body: "slow down", RetryAfter: "45"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				var rateLimited *apperrors.RateLimitedError
				if !errors.As(got, &rateLimited) {
					t.Fatalf("error type = %T, want *apperrors.RateLimitedError", got)
				}
				if rateLimited.RetryAfter != "45" {
					t.Fatalf("RetryAfter = %q, want 45", rateLimited.RetryAfter)
				}
			},
		},
		{
			name: "unprocessable maps to request validation",
			err:  &tts.APIError{StatusCode: http.StatusUnprocessableEntity, Body: "invalid request"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				assertValidationError(t, got, "TTS", "request")
			},
		},
		{
			name: "server error maps to upstream bad gateway",
			err:  &tts.APIError{StatusCode: http.StatusInternalServerError, Body: "upstream failed"},
			assert: func(t *testing.T, got error) {
				t.Helper()
				assertUpstreamError(t, got, http.StatusBadGateway)
			},
		},
		{
			name: "plain error maps to audio error",
			err:  errors.New("encoder failed"),
			assert: func(t *testing.T, got error) {
				t.Helper()
				var audioErr *apperrors.AudioError
				if !errors.As(got, &audioErr) {
					t.Fatalf("error type = %T, want *apperrors.AudioError", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translateTTSError(123, tt.err)
			if got == nil {
				t.Fatal("translateTTSError returned nil")
			}
			var apiErr *tts.APIError
			if errors.As(tt.err, &apiErr) && !errors.Is(got, tt.err) {
				t.Fatalf("translated error does not wrap original API error: %v", got)
			}
			tt.assert(t, got)
		})
	}
}

func TestStoryServiceAlertTTSError(t *testing.T) {
	tests := []struct {
		name                  string
		err                   error
		wantKey               string
		wantRequiresThreshold bool
	}{
		{name: "invalid credentials", err: &tts.APIError{StatusCode: http.StatusUnauthorized}, wantKey: "tts:credentials"},
		{name: "rate limit", err: &tts.APIError{StatusCode: http.StatusTooManyRequests}, wantKey: "tts:rate-limit", wantRequiresThreshold: true},
		{name: "server error", err: &tts.APIError{StatusCode: http.StatusServiceUnavailable}, wantKey: "tts:upstream", wantRequiresThreshold: true},
		{name: "request timeout", err: context.DeadlineExceeded, wantKey: "tts:upstream", wantRequiresThreshold: true},
		{name: "voice not found is user error", err: &tts.APIError{StatusCode: http.StatusNotFound}},
		{name: "invalid request is user error", err: &tts.APIError{StatusCode: http.StatusUnprocessableEntity}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alerts := &capturingAlerter{}
			service := &StoryService{alerts: alerts}
			service.alertTTSError(t.Context(), 123, tt.err)
			if tt.wantKey == "" {
				if len(alerts.events) != 0 {
					t.Fatalf("events = %+v, want none", alerts.events)
				}
				return
			}
			if len(alerts.events) != 1 {
				t.Fatalf("event count = %d, want 1", len(alerts.events))
			}
			if got := alerts.events[0]; got.Key != tt.wantKey || got.RequiresThreshold != tt.wantRequiresThreshold {
				t.Fatalf("event = %+v, want key %q RequiresThreshold %t", got, tt.wantKey, tt.wantRequiresThreshold)
			}
		})
	}
}

type capturingAlerter struct {
	events   []notify.Event
	resolved []string
}

func (a *capturingAlerter) Alert(_ context.Context, event notify.Event) {
	a.events = append(a.events, event)
}

func (a *capturingAlerter) Resolve(_ context.Context, key, _, _ string) {
	a.resolved = append(a.resolved, key)
}

func newGenerateTTSTestService(
	story *models.Story,
	settings *models.TTSSettings,
	rules []models.PronunciationRule,
	ttsSvc *fakeSpeechGenerator,
) *StoryService {
	return &StoryService{
		storyRepo: &fakeStoryRepository{
			story: story,
		},
		ttsSettingsSvc: &fakeTTSSettingsGetter{
			settings: settings,
		},
		pronunciationInjector: NewPronunciationInjector(&fakePronunciationRuleLister{
			rules: rules,
		}),
		ttsSvc: ttsSvc,
		alerts: notify.Discard,
	}
}

func storyForTTSTest(text string) *models.Story {
	voiceID := int64(7)
	elevenLabsVoiceID := "voice-123"
	return &models.Story{
		ID:      99,
		Text:    text,
		VoiceID: &voiceID,
		Voice: &models.Voice{
			ID:                voiceID,
			ElevenLabsVoiceID: &elevenLabsVoiceID,
		},
	}
}

type fakeStoryRepository struct {
	storyRepository
	story *models.Story
	err   error
	calls int
}

func (f *fakeStoryRepository) GetByID(context.Context, int64) (*models.Story, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.story, nil
}

type fakeTTSSettingsGetter struct {
	settings *models.TTSSettings
	err      error
}

func (f *fakeTTSSettingsGetter) Get(context.Context) (*models.TTSSettings, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.settings, nil
}

type fakeSpeechGenerator struct {
	ctx   context.Context
	text  string
	err   error
	calls int
}

func (f *fakeSpeechGenerator) GenerateSpeech(ctx context.Context, text, _ string, _ tts.Options) ([]byte, error) {
	f.calls++
	f.ctx = ctx
	f.text = text
	if f.err != nil {
		return nil, f.err
	}
	return []byte("opus"), nil
}

func assertUpstreamError(t *testing.T, got error, wantStatus int) {
	t.Helper()

	var upstream *apperrors.UpstreamError
	if !errors.As(got, &upstream) {
		t.Fatalf("error type = %T, want *apperrors.UpstreamError", got)
	}
	if upstream.Status != wantStatus {
		t.Fatalf("status = %d, want %d", upstream.Status, wantStatus)
	}
}

func assertValidationError(t *testing.T, got error, wantResource, wantField string) {
	t.Helper()

	var validation *apperrors.ValidationError
	if !errors.As(got, &validation) {
		t.Fatalf("error type = %T, want *apperrors.ValidationError", got)
	}
	if validation.Resource != wantResource || validation.Field != wantField {
		t.Fatalf("validation = %#v, want %s.%s", validation, wantResource, wantField)
	}
}
