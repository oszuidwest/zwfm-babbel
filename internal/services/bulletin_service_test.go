package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mysqlerr "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// A stored bulletin holds only server-generated values, so insert failures are
// database errors. Only a reference deleted during generation stays a
// conflict. A transaction that never begins or rolls back (including a failed
// job finalize) removes the rendered file; a stored bulletin or a failed commit
// keeps it, since the row may exist.
func TestBulletinService_SaveFailures(t *testing.T) {
	t.Parallel()
	connLost := errors.New("connection lost")
	for _, tt := range []struct {
		name         string
		insertErr    *mysqlerr.MySQLError
		tx           failingTxManager
		finalizeErr  error
		wantCause    error
		wantConflict bool
		wantFileKept bool
	}{
		{name: "duplicate key", insertErr: &mysqlerr.MySQLError{Number: 1062}, wantCause: repository.ErrDuplicateKey},
		{name: "data too long", insertErr: &mysqlerr.MySQLError{Number: 1406}, wantCause: repository.ErrDataTooLong},
		{name: "station deleted", insertErr: &mysqlerr.MySQLError{Number: 1452}, wantConflict: true},
		{name: "begin", tx: failingTxManager{beginFails: true, err: connLost}, wantCause: connLost},
		// A job that left the running state keeps its stored outcome; the
		// worker detects this through the wrapped cause.
		{name: "job finalize", finalizeErr: repository.ErrBulletinJobStateConflict, wantCause: repository.ErrBulletinJobStateConflict},
		{name: "commit", tx: failingTxManager{err: connLost}, wantCause: connLost, wantFileKept: true},
		{name: "stored", wantFileKept: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db := insertFailingDB(t, tt.insertErr)
			service := &BulletinService{
				alerts:       notify.Discard,
				txManager:    tt.tx,
				bulletinRepo: repository.NewBulletinRepository(db),
			}
			path := filepath.Join(t.TempDir(), "bulletin.wav")
			if err := os.WriteFile(path, []byte("RIFF"), 0o600); err != nil {
				t.Fatal(err)
			}

			var finalize func(context.Context, int64) error
			if tt.finalizeErr != nil {
				finalize = func(context.Context, int64) error { return tt.finalizeErr }
			}

			_, err := service.saveBulletinToDatabase(t.Context(), saveBulletinParams{StationID: 1, BulletinPath: path}, finalize)
			switch {
			case tt.wantConflict:
				assertConflict(t, err, "bulletin.reference_missing")
			case tt.wantCause == nil:
				if err != nil {
					t.Fatalf("saveBulletinToDatabase() error = %v, want nil", err)
				}
			default:
				dbErr, ok := errors.AsType[*apperrors.DatabaseError](err)
				if !ok || dbErr.Resource != "Bulletin" || dbErr.Operation != apperrors.OpCreate.String() || !errors.Is(err, tt.wantCause) {
					t.Fatalf("saveBulletinToDatabase() error = %v, want a Bulletin create database error caused by %v", err, tt.wantCause)
				}
				if tt.wantFileKept && !strings.Contains(dbErr.Unwrap().Error(), path) {
					t.Fatalf("commit failure cause %q does not name %s", dbErr.Unwrap(), path)
				}
			}
			if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) == tt.wantFileKept {
				t.Fatalf("rendered file: %v, want kept = %v", statErr, tt.wantFileKept)
			}
		})
	}
}

// A panic in the transaction body rolls it back, so the rendered file goes too.
func TestBulletinService_SavePanicRemovesFile(t *testing.T) {
	t.Parallel()
	service := &BulletinService{
		alerts:       notify.Discard,
		txManager:    failingTxManager{},
		bulletinRepo: repository.NewBulletinRepository(insertFailingDB(t, nil)),
	}
	path := filepath.Join(t.TempDir(), "bulletin.wav")
	if err := os.WriteFile(path, []byte("RIFF"), 0o600); err != nil {
		t.Fatal(err)
	}

	func() {
		defer func() {
			if got := recover(); got != "finalize" {
				t.Fatalf("recovered %v, want the finalize panic", got)
			}
		}()
		_, _ = service.saveBulletinToDatabase(t.Context(), saveBulletinParams{StationID: 1, BulletinPath: path},
			func(context.Context, int64) error { panic("finalize") })
	}()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rendered file: %v, want removed", err)
	}
}

// insertFailingDB builds a database without a connection whose inserts fail
// with insertErr, or succeed as dry runs when it is nil.
func insertFailingDB(t *testing.T, insertErr *mysqlerr.MySQLError) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(mysql.New(mysql.Config{SkipInitializeWithVersion: true}),
		&gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open dry-run db: %v", err)
	}
	if insertErr != nil {
		if err := db.Callback().Create().Before("gorm:create").Register("test:fail_insert", func(tx *gorm.DB) {
			_ = tx.AddError(insertErr)
		}); err != nil {
			t.Fatal(err)
		}
	}
	return db
}
