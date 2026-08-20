package services

import (
	"context"
	"errors"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

func TestBulletinJobError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		wantCode   string
		wantDetail string
	}{
		{
			name:       "no stories",
			err:        apperrors.NoStories(12),
			wantCode:   "bulletin.no_stories",
			wantDetail: "No eligible stories are available for bulletin generation",
		},
		{
			name:       "timeout",
			err:        context.DeadlineExceeded,
			wantCode:   "internal.timeout",
			wantDetail: "Bulletin generation exceeded the server-side time limit",
		},
		{
			name:       "audio failure",
			err:        apperrors.Audio("Bulletin", "generate", errors.New("ffmpeg exit status 1")),
			wantCode:   "audio.processing_failed",
			wantDetail: "Audio processing failed during bulletin generation",
		},
		{
			name:       "internal error",
			err:        errors.New("sensitive renderer failure"),
			wantCode:   "internal.generation_failed",
			wantDetail: "Bulletin generation failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			code, detail := bulletinJobError(test.err)
			if code != test.wantCode || detail != test.wantDetail {
				t.Fatalf("bulletinJobError() = %q, %q; want %q, %q", code, detail, test.wantCode, test.wantDetail)
			}
		})
	}
}
