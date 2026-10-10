//go:build integration

package services

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/gorm"
)

func TestUserService_ConcurrentDemotionsKeepAnActiveAdmin(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	ids := onlyTwoActiveAdmins(t, db)

	service := NewUserService(repository.NewUserRepository(db), repository.NewTxManager(db), PasswordPolicy{})
	editor := string(models.RoleEditor)
	// One round can miss the race window, so repeat it.
	for round := range 20 {
		if err := db.Model(&models.User{}).Where("id IN ?", ids).Update("role", models.RoleAdmin).Error; err != nil {
			t.Fatal(err)
		}

		errs := make([]error, len(ids))
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, id := range ids {
			wg.Go(func() {
				<-start
				_, errs[i] = service.Update(t.Context(), id, &UpdateUserRequest{Role: &editor})
			})
		}
		close(start)
		wg.Wait()

		var active int64
		if err := activeAdmins(db).Count(&active).Error; err != nil {
			t.Fatal(err)
		}
		rejected := 0
		for _, err := range errs {
			if conflict, ok := errors.AsType[*apperrors.ConflictError](err); ok && conflict.Code == "user.last_admin" {
				rejected++
			} else if err != nil {
				t.Fatalf("round %d: Update() error = %v", round, err)
			}
		}
		if active != 1 || rejected != 1 {
			t.Fatalf("round %d: %d active admins and %d last_admin rejections, want 1 and 1", round, active, rejected)
		}
	}
}

// onlyTwoActiveAdmins suspends the existing admins and creates two active
// ones, restoring the original state on cleanup.
func onlyTwoActiveAdmins(t *testing.T, db *gorm.DB) []int64 {
	t.Helper()
	var existing []int64
	if err := activeAdmins(db).Pluck("id", &existing).Error; err != nil {
		t.Fatal(err)
	}
	if len(existing) > 0 {
		if err := db.Model(&models.User{}).Where("id IN ?", existing).Update("suspended_at", time.Now()).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := db.Model(&models.User{}).Where("id IN ?", existing).Update("suspended_at", nil).Error; err != nil {
				t.Errorf("restore admins: %v", err)
			}
		})
	}

	ids := make([]int64, 2)
	for i := range ids {
		admin := models.User{Username: fmt.Sprintf("%s%d", t.Name(), i), FullName: t.Name(), Role: models.RoleAdmin}
		if err := db.Create(&admin).Error; err != nil {
			t.Fatal(err)
		}
		ids[i] = admin.ID
		t.Cleanup(func() {
			if err := db.Unscoped().Delete(&models.User{}, admin.ID).Error; err != nil {
				t.Errorf("delete admin: %v", err)
			}
		})
	}
	return ids
}

func activeAdmins(db *gorm.DB) *gorm.DB {
	return db.Model(&models.User{}).Where("role = ? AND suspended_at IS NULL", models.RoleAdmin)
}
