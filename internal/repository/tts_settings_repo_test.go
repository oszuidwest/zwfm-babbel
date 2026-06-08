package repository

import (
	"context"
	"database/sql/driver"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	mysqlerr "github.com/go-sql-driver/mysql"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestTTSSettingsUpdate_BuildUpdateMapPreservesZeroValues(t *testing.T) {
	zero := 0.0
	falseValue := false
	empty := ""

	updateMap := BuildUpdateMap(&TTSSettingsUpdate{
		Stability:       &zero,
		Style:           &zero,
		UseSpeakerBoost: &falseValue,
		TTSStylePrefix:  &empty,
		ClearSeed:       true,
	})

	expected := map[string]any{
		"stability":         0.0,
		"style":             0.0,
		"use_speaker_boost": false,
		"tts_style_prefix":  "",
		"seed":              nil,
	}

	if len(updateMap) != len(expected) {
		t.Fatalf("update map len = %d, want %d: %#v", len(updateMap), len(expected), updateMap)
	}
	for key, want := range expected {
		if got, ok := updateMap[key]; !ok || got != want {
			t.Errorf("updateMap[%q] = %#v, %t; want %#v, true", key, got, ok, want)
		}
	}

	if _, ok := updateMap["t_t_s_style_prefix"]; ok {
		t.Fatal("update map used fallback acronym snake-case for TTSStylePrefix")
	}
}

func TestParseDBError_SchemaUnavailable(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "mysql 1146",
			err:  &mysqlerr.MySQLError{Number: 1146, Message: "Table 'babbel.tts_settings' doesn't exist"},
		},
		{
			name: "sqlite no such table fallback",
			err:  errors.New("no such table: tts_settings"),
		},
		{
			name: "raw mysql table prefix fallback",
			err:  errors.New("Table 'babbel.tts_settings' doesn't exist"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseDBError(tt.err); !errors.Is(got, ErrSchemaUnavailable) {
				t.Fatalf("ParseDBError() = %v, want ErrSchemaUnavailable", got)
			}
		})
	}
}

func TestParseDBError_DoesNotTreatColumnMissingAsSchemaUnavailable(t *testing.T) {
	err := errors.New("Error 1054 (42S22): Unknown column 'tts_style_prefix' doesn't exist")

	got := ParseDBError(err)
	if errors.Is(got, ErrSchemaUnavailable) {
		t.Fatalf("ParseDBError() = %v, should not be ErrSchemaUnavailable", got)
	}
	if got.Error() != err.Error() {
		t.Fatalf("ParseDBError() = %v, want original error message %q", got, err.Error())
	}
}

func TestTTSSettingsRepository_SetPronunciationDictionaryID(t *testing.T) {
	type existenceMode int
	const (
		noExistenceCheck existenceMode = iota
		existenceCheckRowExists
		existenceCheckRowMissing
	)

	tests := []struct {
		name      string
		id        *string
		wantValue any
		rows      int64
		existence existenceMode
		wantErr   error
	}{
		{
			name:      "sets dictionary ID",
			id:        ptr("dict-123"),
			wantValue: "dict-123",
			rows:      1,
			existence: noExistenceCheck,
		},
		{
			name:      "nil clears dictionary ID",
			id:        nil,
			wantValue: nil,
			rows:      1,
			existence: noExistenceCheck,
		},
		{
			name:      "empty string clears dictionary ID",
			id:        ptr(""),
			wantValue: nil,
			rows:      1,
			existence: noExistenceCheck,
		},
		{
			name:      "idempotent same-value write disambiguates via existence check",
			id:        ptr("dict-123"),
			wantValue: "dict-123",
			rows:      0,
			existence: existenceCheckRowExists,
		},
		{
			name:      "missing singleton row returns not found",
			id:        ptr("dict-123"),
			wantValue: "dict-123",
			rows:      0,
			existence: existenceCheckRowMissing,
			wantErr:   ErrNotFound,
		},
	}

	updatePattern := regexp.QuoteMeta("UPDATE `tts_settings` SET `pronunciation_dictionary_id`=?,`updated_at`=? WHERE id = ?")
	countPattern := regexp.QuoteMeta("SELECT count(*) FROM `tts_settings` WHERE id = ?")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := newMockTTSSettingsRepository(t)
			defer cleanup()

			mock.ExpectExec(updatePattern).
				WithArgs(tt.wantValue, sqlmock.AnyArg(), ttsSettingsSingletonID).
				WillReturnResult(sqlmock.NewResult(0, tt.rows))

			switch tt.existence {
			case existenceCheckRowExists:
				mock.ExpectQuery(countPattern).
					WithArgs(ttsSettingsSingletonID).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
			case existenceCheckRowMissing:
				mock.ExpectQuery(countPattern).
					WithArgs(ttsSettingsSingletonID).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			}

			err := repo.SetPronunciationDictionaryID(context.Background(), tt.id)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("SetPronunciationDictionaryID() error = %v, want nil", err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("SetPronunciationDictionaryID() error = %v, want %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("SQL expectations were not met: %v", err)
			}
		})
	}
}

func TestTTSSettingsRepository_CompareAndSetPronunciationDictionaryID(t *testing.T) {
	tests := []struct {
		name         string
		currentID    *string
		nextID       *string
		wantValue    any
		updateSQL    string
		updateArgs   []driver.Value
		rowsAffected int64
		rowExists    *bool
		wantUpdated  bool
		wantErr      error
	}{
		{
			name:      "first create sets only when stored ID is empty",
			currentID: nil,
			nextID:    ptr("dict-new"),
			wantValue: "dict-new",
			updateSQL: regexp.QuoteMeta(
				"UPDATE `tts_settings` SET `pronunciation_dictionary_id`=?,`updated_at`=? WHERE id = ? AND (pronunciation_dictionary_id IS NULL OR pronunciation_dictionary_id = ?)",
			),
			updateArgs:   []driver.Value{"dict-new", ttsSettingsSingletonID, ""},
			rowsAffected: 1,
			wantUpdated:  true,
		},
		{
			name:      "self heal replaces only the expected stale ID",
			currentID: ptr("dict-old"),
			nextID:    ptr("dict-new"),
			wantValue: "dict-new",
			updateSQL: regexp.QuoteMeta(
				"UPDATE `tts_settings` SET `pronunciation_dictionary_id`=?,`updated_at`=? WHERE id = ? AND pronunciation_dictionary_id = ?",
			),
			updateArgs:   []driver.Value{"dict-new", ttsSettingsSingletonID, "dict-old"},
			rowsAffected: 1,
			wantUpdated:  true,
		},
		{
			name:      "cas lost returns false when singleton row still exists",
			currentID: nil,
			nextID:    ptr("dict-new"),
			wantValue: "dict-new",
			updateSQL: regexp.QuoteMeta(
				"UPDATE `tts_settings` SET `pronunciation_dictionary_id`=?,`updated_at`=? WHERE id = ? AND (pronunciation_dictionary_id IS NULL OR pronunciation_dictionary_id = ?)",
			),
			updateArgs:   []driver.Value{"dict-new", ttsSettingsSingletonID, ""},
			rowsAffected: 0,
			rowExists:    ptr(true),
			wantUpdated:  false,
		},
		{
			name:      "missing singleton row returns not found",
			currentID: nil,
			nextID:    ptr("dict-new"),
			wantValue: "dict-new",
			updateSQL: regexp.QuoteMeta(
				"UPDATE `tts_settings` SET `pronunciation_dictionary_id`=?,`updated_at`=? WHERE id = ? AND (pronunciation_dictionary_id IS NULL OR pronunciation_dictionary_id = ?)",
			),
			updateArgs:   []driver.Value{"dict-new", ttsSettingsSingletonID, ""},
			rowsAffected: 0,
			rowExists:    ptr(false),
			wantErr:      ErrNotFound,
		},
	}

	countPattern := regexp.QuoteMeta("SELECT count(*) FROM `tts_settings` WHERE id = ?")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := newMockTTSSettingsRepository(t)
			defer cleanup()

			args := []driver.Value{tt.wantValue, sqlmock.AnyArg()}
			args = append(args, tt.updateArgs[1:]...)
			mock.ExpectExec(tt.updateSQL).
				WithArgs(args...).
				WillReturnResult(sqlmock.NewResult(0, tt.rowsAffected))

			if tt.rowExists != nil {
				count := 0
				if *tt.rowExists {
					count = 1
				}
				mock.ExpectQuery(countPattern).
					WithArgs(ttsSettingsSingletonID).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(count))
			}

			updated, err := repo.CompareAndSetPronunciationDictionaryID(
				context.Background(),
				tt.currentID,
				tt.nextID,
			)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("CompareAndSetPronunciationDictionaryID() error = %v, want nil", err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CompareAndSetPronunciationDictionaryID() error = %v, want %v", err, tt.wantErr)
			}
			if updated != tt.wantUpdated {
				t.Fatalf("updated = %t, want %t", updated, tt.wantUpdated)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("SQL expectations were not met: %v", err)
			}
		})
	}
}

func newMockTTSSettingsRepository(t *testing.T) (*TTSSettingsRepository, sqlmock.Sqlmock, func()) {
	t.Helper()

	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New(): %v", err)
	}

	gormDB, err := gorm.Open(
		gormmysql.New(gormmysql.Config{
			Conn:                      sqlDB,
			SkipInitializeWithVersion: true,
		}),
		&gorm.Config{SkipDefaultTransaction: true},
	)
	if err != nil {
		_ = sqlDB.Close()
		t.Fatalf("gorm.Open(): %v", err)
	}

	return NewTTSSettingsRepository(gormDB), mock, func() { _ = sqlDB.Close() }
}

func ptr[T any](value T) *T {
	return &value
}
