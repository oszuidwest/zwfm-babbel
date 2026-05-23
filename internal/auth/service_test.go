package auth

import (
	"testing"
	"time"
)

func TestLoginFailureUpdates(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	service := &Service{
		config: &Config{
			Local: LocalConfig{
				MaxFailedAttempts:      3,
				LockoutDurationMinutes: 15,
			},
		},
	}

	t.Run("below threshold", func(t *testing.T) {
		t.Parallel()

		updates := service.loginFailureUpdates(1, now)

		if got := updates["failed_login_attempts"]; got != 2 {
			t.Fatalf("failed_login_attempts = %v, want 2", got)
		}
		if got := updates["locked_until"]; got != nil {
			t.Fatalf("locked_until = %v, want nil", got)
		}
	})

	t.Run("at threshold", func(t *testing.T) {
		t.Parallel()

		updates := service.loginFailureUpdates(2, now)

		if got := updates["failed_login_attempts"]; got != 3 {
			t.Fatalf("failed_login_attempts = %v, want 3", got)
		}

		got, ok := updates["locked_until"].(time.Time)
		if !ok {
			t.Fatalf("locked_until = %T, want time.Time", updates["locked_until"])
		}
		if want := now.Add(15 * time.Minute); !got.Equal(want) {
			t.Fatalf("locked_until = %v, want %v", got, want)
		}
	})
}
