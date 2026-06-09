package repository

import (
	"errors"
	"testing"

	mysqlerr "github.com/go-sql-driver/mysql"
)

func TestTTSSettingsUpdate_BuildUpdateMapPreservesZeroValues(t *testing.T) {
	zero := 0.0
	empty := ""

	updateMap := BuildUpdateMap(&TTSSettingsUpdate{
		Stability:      &zero,
		Style:          &zero,
		TTSStylePrefix: &empty,
		ClearSeed:      true,
	})

	expected := map[string]any{
		"stability":        0.0,
		"style":            0.0,
		"tts_style_prefix": "",
		"seed":             nil,
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
