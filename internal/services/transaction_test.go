package services

import (
	"context"
	"errors"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

func TestInTransactionReturnsErrorFromFnUntranslated(t *testing.T) {
	t.Parallel()
	invalid := apperrors.Invalid("end_date", apperrors.CodeDateOrder, "end before start")
	err := inTransaction(t.Context(), failingTxManager{}, "User", apperrors.OpUpdate,
		func(context.Context) error { return invalid })
	if _, isDBErr := errors.AsType[*apperrors.DatabaseError](err); isDBErr || !errors.Is(err, invalid) {
		t.Fatalf("inTransaction = %v, want the error from fn unchanged", err)
	}
}

func TestTransactionFailuresAreDatabaseErrors(t *testing.T) {
	t.Parallel()
	cause := errors.New("connection refused")
	beginFails := failingTxManager{beginFails: true, err: cause}

	tests := []struct {
		name     string
		resource string
		op       apperrors.Operation
		run      func(ctx context.Context) error
	}{
		{"inTransaction commit", "User", apperrors.OpUpdate, func(ctx context.Context) error {
			return inTransaction(ctx, failingTxManager{err: cause}, "User", apperrors.OpUpdate,
				func(context.Context) error { return nil })
		}},
		{"StoryService.Restore begin", "Story", apperrors.OpUpdate, func(ctx context.Context) error {
			_, err := (&StoryService{txManager: beginFails}).Restore(ctx, 1, &UpdateStoryRequest{})
			return err
		}},
		{"UserService.Update begin", "User", apperrors.OpUpdate, func(ctx context.Context) error {
			_, err := (&UserService{txManager: beginFails}).Update(ctx, 1, &UpdateUserRequest{})
			return err
		}},
		{"UserService.SoftDelete begin", "User", apperrors.OpDelete, func(ctx context.Context) error {
			return (&UserService{txManager: beginFails}).SoftDelete(ctx, 1)
		}},
		{"StationVoiceService.Create begin", "StationVoice", apperrors.OpCreate, func(ctx context.Context) error {
			_, err := (&StationVoiceService{txManager: beginFails}).Create(ctx, &CreateStationVoiceRequest{StationID: 1, VoiceID: 1})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.run(t.Context())
			dbErr, ok := errors.AsType[*apperrors.DatabaseError](err)
			if !ok || dbErr.Resource != tt.resource || dbErr.Operation != tt.op.String() || !errors.Is(err, cause) {
				t.Fatalf("error = %v, want a %s %s database error caused by %v", err, tt.resource, tt.op, cause)
			}
		})
	}
}
