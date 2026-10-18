package repository

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestParseDBErrorPreservesDriverDetails(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		number   uint16
		message  string
		sentinel error
	}{
		{"duplicate key", 1062, "Duplicate entry '1-2' for key 'bulletins.unique_filename'", ErrDuplicateKey},
		{"foreign key", 1452, "Cannot add child row: foreign key constraint fails (`bulletins`, CONSTRAINT `fk_station`)", ErrForeignKeyViolation},
		{"blocked delete", 1451, "Cannot delete or update a parent row: a foreign key constraint fails (`stories`, CONSTRAINT `fk_voice`)", ErrForeignKeyViolation},
		{"long column", 1406, "Data too long for column 'filename' at row 1", ErrDataTooLong},
		{"missing table", 1146, "Table 'babbel.bulletins' doesn't exist", ErrSchemaUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			driver := &mysql.MySQLError{Number: tt.number, Message: tt.message}
			wrapped := fmt.Errorf("save bulletin: %w", driver)
			parsed := ParseDBError(wrapped)
			if !errors.Is(parsed, tt.sentinel) || !errors.Is(parsed, driver) || !strings.Contains(parsed.Error(), tt.message) {
				t.Fatalf("ParseDBError = %v, want sentinel %v and original driver details", parsed, tt.sentinel)
			}
			fallback := errors.New(tt.message)
			parsed = ParseDBError(fallback)
			if !errors.Is(parsed, tt.sentinel) || !errors.Is(parsed, fallback) || !strings.Contains(parsed.Error(), tt.message) {
				t.Fatalf("message-only ParseDBError = %v, want original details and sentinel %v", parsed, tt.sentinel)
			}
		})
	}
}
