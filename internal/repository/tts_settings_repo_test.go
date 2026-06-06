package repository

import (
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"
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
			err:  &mysql.MySQLError{Number: 1146, Message: "Table 'babbel.tts_settings' doesn't exist"},
		},
		{
			name: "sqlite no such table fallback",
			err:  errors.New("no such table: tts_settings"),
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
