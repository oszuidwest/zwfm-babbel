package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func TestStoryService_VoiceAndAudioWritesPreserveDeletedError(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		write func(*StoryService) error
	}{
		{name: "voice update", write: func(s *StoryService) error {
			_, err := s.Update(t.Context(), 99, &UpdateStoryRequest{VoiceID: new(int64(9))})
			return err
		}},
		{name: "upload preparation", write: func(s *StoryService) error {
			_, err := s.PrepareAudio(t.Context(), 99, new(int64(9)))
			return err
		}},
		{name: "tts override", write: func(s *StoryService) error {
			return s.GenerateTTS(t.Context(), 99, new(int64(9)), true)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			deleted := &repository.StoryDeletedError{ID: 99, DeletedAt: time.Now()}
			svc := &StoryService{storyRepo: &deletedStoryRepository{deleted: deleted}}
			if err := tt.write(svc); !errors.Is(err, deleted) {
				t.Fatalf("write error = %v, want deletion timestamp preserved", err)
			}
		})
	}
}

type deletedStoryRepository struct {
	storyRepository
	deleted *repository.StoryDeletedError
}

func (r *deletedStoryRepository) GetByIDForWrite(context.Context, int64) (*models.Story, error) {
	return nil, r.deleted
}

func TestStoryService_UpdateVoiceWithAudio(t *testing.T) {
	newTitle := "Nieuwe titel"
	tests := []struct {
		name          string
		req           UpdateStoryRequest
		audioFile     string
		updateErr     error
		wantConflict  bool
		wantUpdates   int
		wantVoiceSent bool
	}{
		{
			name:         "different voice with audio conflicts",
			req:          UpdateStoryRequest{VoiceID: new(int64(9))},
			audioFile:    "story_99_voice_7_abc.wav",
			wantConflict: true,
		},
		{
			name:          "different voice without audio updates",
			req:           UpdateStoryRequest{VoiceID: new(int64(9))},
			wantUpdates:   1,
			wantVoiceSent: true,
		},
		{
			name:      "same voice only is a no-op",
			req:       UpdateStoryRequest{VoiceID: new(int64(7))},
			audioFile: "story_99_voice_7_abc.wav",
		},
		{
			name:        "same voice with other fields drops the voice",
			req:         UpdateStoryRequest{VoiceID: new(int64(7)), Title: &newTitle},
			audioFile:   "story_99_voice_7_abc.wav",
			wantUpdates: 1,
		},
		{
			name:          "audio added concurrently conflicts",
			req:           UpdateStoryRequest{VoiceID: new(int64(9))},
			updateErr:     repository.ErrStateConflict,
			wantConflict:  true,
			wantUpdates:   1,
			wantVoiceSent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			story := storyForTTSTest("Tekst")
			story.AudioFile = tt.audioFile
			repo := &fakeStoryRepository{story: story, updateErr: tt.updateErr}
			service := &StoryService{
				storyRepo: repo,
				voiceRepo: &fakeVoiceRepository{voices: map[int64]*models.Voice{9: {ID: 9}}},
				alerts:    notify.Discard,
			}

			got, err := service.Update(t.Context(), story.ID, &tt.req)

			switch {
			case tt.wantConflict:
				conflict, ok := errors.AsType[*apperrors.ConflictError](err)
				if !ok || conflict.Code != "story.voice_locked" {
					t.Fatalf("Update() error = %v, want story.voice_locked conflict", err)
				}
			case err != nil:
				t.Fatalf("Update() error = %v", err)
			case got == nil:
				t.Fatal("Update() returned nil story")
			}
			if len(repo.updates) != tt.wantUpdates {
				t.Fatalf("repository updates = %d, want %d", len(repo.updates), tt.wantUpdates)
			}
			if tt.wantUpdates > 0 && (repo.updates[0].VoiceID != nil) != tt.wantVoiceSent {
				t.Fatalf("update VoiceID = %v, want sent %t", repo.updates[0].VoiceID, tt.wantVoiceSent)
			}
		})
	}
}

func TestStoryService_PrepareAudio(t *testing.T) {
	tests := []struct {
		name         string
		story        *models.Story
		voiceID      *int64
		wantVoice    int64
		wantInvalid  bool
		wantNotFound bool
	}{
		{
			name:      "uses the story voice",
			story:     storyForTTSTest("Tekst"),
			wantVoice: 7,
		},
		{
			name:      "uses the requested voice",
			story:     storyForTTSTest("Tekst"),
			voiceID:   new(int64(9)),
			wantVoice: 9,
		},
		{
			name:      "requested voice attributes audio to a story without voice",
			story:     &models.Story{ID: 99},
			voiceID:   new(int64(9)),
			wantVoice: 9,
		},
		{
			name:        "story without voice is rejected",
			story:       &models.Story{ID: 99},
			wantInvalid: true,
		},
		{
			name:         "unknown requested voice is not found",
			story:        storyForTTSTest("Tekst"),
			voiceID:      new(int64(404)),
			wantNotFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &StoryService{
				storyRepo: &fakeStoryRepository{story: tt.story},
				voiceRepo: &fakeVoiceRepository{voices: map[int64]*models.Voice{9: {ID: 9}}},
			}

			target, err := service.PrepareAudio(t.Context(), tt.story.ID, tt.voiceID)

			switch {
			case tt.wantInvalid:
				assertValidationError(t, err, "Story", "voice_id")
			case tt.wantNotFound:
				if _, ok := errors.AsType[*apperrors.NotFoundError](err); !ok {
					t.Fatalf("PrepareAudio() error = %T, want *apperrors.NotFoundError", err)
				}
			case err != nil:
				t.Fatalf("PrepareAudio() error = %v", err)
			case target.voice.ID != tt.wantVoice:
				t.Fatalf("target voice = %d, want %d", target.voice.ID, tt.wantVoice)
			}
		})
	}
}

func TestStoryService_GenerateTTSUsesRequestedVoice(t *testing.T) {
	stopErr := errors.New("stop after capture")
	ttsSvc := &fakeSpeechGenerator{err: stopErr}
	service := newGenerateTTSTestService(
		storyForTTSTest("Tekst"),
		&models.TTSSettings{ApplyTextNormalization: TTSNormalizationAuto},
		nil,
		ttsSvc,
	)
	overrideID := "voice-override"
	service.voiceRepo = &fakeVoiceRepository{voices: map[int64]*models.Voice{
		9: {ID: 9, ElevenLabsVoiceID: &overrideID},
	}}

	err := service.GenerateTTS(t.Context(), 99, new(int64(9)), false)
	if !errors.Is(err, stopErr) {
		t.Fatalf("GenerateTTS() error = %v, want wrapped stop error", err)
	}
	if ttsSvc.voiceID != overrideID {
		t.Fatalf("GenerateSpeech voice = %q, want %q", ttsSvc.voiceID, overrideID)
	}
}

func TestStoryService_GenerateTTSRequiresVoice(t *testing.T) {
	ttsSvc := &fakeSpeechGenerator{}
	service := newGenerateTTSTestService(
		&models.Story{ID: 99, Text: "Tekst"},
		&models.TTSSettings{ApplyTextNormalization: TTSNormalizationAuto},
		nil,
		ttsSvc,
	)

	err := service.GenerateTTS(t.Context(), 99, nil, false)
	assertValidationError(t, err, "Story", "voice_id")
	if ttsSvc.calls != 0 {
		t.Fatalf("GenerateSpeech calls = %d, want 0", ttsSvc.calls)
	}
}

type fakeVoiceRepository struct {
	voices map[int64]*models.Voice
}

func (f *fakeVoiceRepository) Exists(_ context.Context, id int64) (bool, error) {
	_, ok := f.voices[id]
	return ok, nil
}

func (f *fakeVoiceRepository) GetByID(_ context.Context, id int64) (*models.Voice, error) {
	voice, ok := f.voices[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return voice, nil
}
