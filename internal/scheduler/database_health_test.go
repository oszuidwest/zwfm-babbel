package scheduler

import (
	"errors"
	"testing"

	"gorm.io/gorm"
)

func TestCheckDatabaseAcceptsNilAlerter(t *testing.T) {
	db := &gorm.DB{Config: &gorm.Config{}}

	err := CheckDatabase(t.Context(), db, nil)
	if !errors.Is(err, gorm.ErrInvalidDB) {
		t.Fatalf("CheckDatabase error = %v, want invalid database", err)
	}
}
