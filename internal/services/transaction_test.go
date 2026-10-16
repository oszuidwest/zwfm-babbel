package services

import (
	"context"
	"errors"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

func TestInTransaction(t *testing.T) {
	t.Parallel()
	cause := errors.New("connection refused")

	t.Run("commit failure", func(t *testing.T) {
		t.Parallel()
		err := inTransaction(t.Context(), failingTxManager{err: cause}, "User", apperrors.OpUpdate,
			func(context.Context) error { return nil })
		dbErr, ok := errors.AsType[*apperrors.DatabaseError](err)
		if !ok || dbErr.Resource != "User" || dbErr.Operation != apperrors.OpUpdate.String() || !errors.Is(err, cause) {
			t.Fatalf("inTransaction = %v, want a User update database error caused by %v", err, cause)
		}
	})

	t.Run("error from fn", func(t *testing.T) {
		t.Parallel()
		invalid := apperrors.Invalid("end_date", apperrors.CodeDateOrder, "end before start")
		err := inTransaction(t.Context(), failingTxManager{}, "User", apperrors.OpUpdate,
			func(context.Context) error { return invalid })
		if _, isDBErr := errors.AsType[*apperrors.DatabaseError](err); isDBErr || !errors.Is(err, invalid) {
			t.Fatalf("inTransaction = %v, want the error from fn unchanged", err)
		}
	})
}

func TestTransactionBeginFailuresAreDatabaseErrors(t *testing.T) {
	t.Parallel()
	cause := errors.New("connection refused")
	txManager := failingTxManager{beginFails: true, err: cause}

	tests := []struct {
		name     string
		resource string
		op       apperrors.Operation
		run      func(ctx context.Context) error
	}{
		{"StoryService.Restore", "Story", apperrors.OpUpdate, func(ctx context.Context) error {
			_, err := (&StoryService{txManager: txManager}).Restore(ctx, 1, &UpdateStoryRequest{})
			return err
		}},
		{"UserService.Update", "User", apperrors.OpUpdate, func(ctx context.Context) error {
			_, err := (&UserService{txManager: txManager}).Update(ctx, 1, &UpdateUserRequest{})
			return err
		}},
		{"UserService.SoftDelete", "User", apperrors.OpDelete, func(ctx context.Context) error {
			return (&UserService{txManager: txManager}).SoftDelete(ctx, 1)
		}},
		{"StationVoiceService.Create", "StationVoice", apperrors.OpCreate, func(ctx context.Context) error {
			_, err := (&StationVoiceService{txManager: txManager}).Create(ctx, &CreateStationVoiceRequest{StationID: 1, VoiceID: 1})
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
