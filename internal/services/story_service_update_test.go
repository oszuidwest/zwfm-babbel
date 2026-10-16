package services

import (
	"errors"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func TestStoryService_UpdateChecksTargetBeforeReferences(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "missing story", err: repository.ErrNotFound},
		{name: "deleted story", err: &repository.StoryDeletedError{ID: 99, DeletedAt: time.Now()}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// A voice lookup would panic: an unavailable target must win first.
			service := &StoryService{storyRepo: &fakeStoryRepository{err: tt.err}}
			voiceID := int64(424242)
			_, err := service.Update(t.Context(), 99, &UpdateStoryRequest{VoiceID: &voiceID})
			if errors.Is(tt.err, repository.ErrNotFound) {
				missing, ok := errors.AsType[*apperrors.NotFoundError](err)
				if !ok || missing.Resource != "Story" || missing.ID == nil || *missing.ID != 99 {
					t.Fatalf("Update() error = %v, want Story 99 not found", err)
				}
				return
			}
			if !errors.Is(err, tt.err) {
				t.Fatalf("Update() error = %v, want %v", err, tt.err)
			}
		})
	}
}
