//go:build integration

package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openOAuthIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("BABBEL_TEST_DB_DSN")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("BABBEL_TEST_DB_DSN is required in CI")
		}
		t.Skip("BABBEL_TEST_DB_DSN not set")
	}
	db, err := gorm.Open(gormmysql.Open(dsn), &gorm.Config{
		SkipDefaultTransaction: true, Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetMaxIdleConns(100)
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("close db: %v", err)
		}
	})
	return db
}

type oauthFixture struct {
	svc    *Service
	prefix string
	issuer string
}

func newOAuthFixture(t *testing.T) oauthFixture {
	t.Helper()
	db := openOAuthIntegrationDB(t)
	prefix := fmt.Sprintf("oauth%d", time.Now().UnixNano())
	f := oauthFixture{svc: &Service{db: db}, prefix: prefix, issuer: "https://" + prefix + ".example"}
	t.Cleanup(func() {
		if err := db.Exec("DELETE FROM users WHERE oidc_issuer LIKE ? OR username LIKE ?", f.issuer+"%", prefix+"%").Error; err != nil {
			t.Errorf("cleanup users: %v", err)
		}
		if err := db.Exec("DELETE FROM voices WHERE name LIKE ?", prefix+"%").Error; err != nil {
			t.Errorf("cleanup voices: %v", err)
		}
	})
	return f
}

func (f oauthFixture) identity(subject string) oauthIdentity {
	return oauthIdentity{Issuer: f.issuer, Subject: subject, Claims: oauthClaims{
		Email: f.prefix + "@example.com", Name: "OAuth Test", PreferredUsername: f.prefix,
	}}
}

func (f oauthFixture) createUser(t *testing.T, user oauthUser) oauthUser {
	t.Helper()
	user.Username = f.prefix + user.Username
	query := f.svc.db.Table("users")
	if user.OIDCSubject == "" {
		query = query.Omit("OIDCIssuer", "OIDCSubject")
	}
	if user.Role == "" {
		user.Role = "viewer"
	}
	if err := query.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	return user
}

func (f oauthFixture) login(t *testing.T, identity oauthIdentity) oauthUser {
	t.Helper()
	id, err := f.svc.findOrCreateOAuthUser(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	var row oauthUser
	if err := f.svc.db.Table("users").Where("id = ?", id).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.OIDCIssuer != identity.Issuer || row.OIDCSubject != identity.Subject {
		t.Fatalf("returned id %d belongs to %q/%q, want %q/%q", id, row.OIDCIssuer, row.OIDCSubject, identity.Issuer, identity.Subject)
	}
	return row
}

func TestExistingOAuthSubjectIntegration(t *testing.T) {
	f := newOAuthFixture(t)
	identity := f.identity("existing")
	existing := f.createUser(t, oauthUser{OIDCIssuer: identity.Issuer, OIDCSubject: identity.Subject, Role: "admin", Email: "old@example.com"})
	row := f.login(t, identity)
	if row.ID != existing.ID || row.Role != "admin" {
		t.Fatalf("user = %+v, want existing admin", row)
	}
}

func TestNewOAuthUserIntegration(t *testing.T) {
	f := newOAuthFixture(t)
	identity := f.identity("new")
	row := f.login(t, identity)
	if row.Role != "viewer" || row.FullName != identity.Claims.Name || row.Email != identity.Claims.Email {
		t.Fatalf("new user = %+v", row)
	}
	if again := f.login(t, identity); again.ID != row.ID {
		t.Fatalf("repeat id = %d, want %d", again.ID, row.ID)
	}
}

func TestEmailLessOAuthUsersIntegration(t *testing.T) {
	f := newOAuthFixture(t)
	first := f.identity("first")
	first.Claims.Email = ""
	first.Claims.EmailVerified = true
	f.createUser(t, oauthUser{Username: "legacy", Email: "", Role: "admin"})
	first.Claims.PreferredUsername = ""
	second := first
	second.Subject = "second"
	a, b := f.login(t, first), f.login(t, second)
	if a.ID == b.ID || a.Username == "" || b.Username == "" {
		t.Fatalf("users = %+v / %+v", a, b)
	}
	if again := f.login(t, first); again.ID != a.ID {
		t.Fatalf("repeat id = %d, want %d", again.ID, a.ID)
	}
}

func TestExactOAuthIdentityIntegration(t *testing.T) {
	f := newOAuthFixture(t)
	identities := []oauthIdentity{f.identity("subject"), f.identity("Subject"), f.identity("subject "), f.identity("subject")}
	identities[3].Issuer += "/other"
	ids := map[int64]bool{}
	for _, identity := range identities {
		row := f.login(t, identity)
		if ids[row.ID] {
			t.Fatalf("identity %q/%q reused id %d", identity.Issuer, identity.Subject, row.ID)
		}
		ids[row.ID] = true
	}
}

func TestDuplicateOAuthUsernameIntegration(t *testing.T) {
	f := newOAuthFixture(t)
	now := time.Now()
	f.createUser(t, oauthUser{DeletedAt: &now})
	row := f.login(t, f.identity("one"))
	second := f.login(t, f.identity("two"))
	if row.Username != f.prefix+"_1" || second.Username != f.prefix+"_2" {
		t.Fatalf("usernames = %q/%q", row.Username, second.Username)
	}
}

func TestInactiveOAuthUserIntegration(t *testing.T) {
	for _, status := range []string{"suspended", "deleted"} {
		t.Run(status+" subject rejected", func(t *testing.T) {
			f := newOAuthFixture(t)
			identity := f.identity(status)
			user := oauthUser{OIDCIssuer: identity.Issuer, OIDCSubject: identity.Subject}
			now := time.Now()
			if status == "suspended" {
				user.SuspendedAt = &now
			} else {
				user.DeletedAt = &now
			}
			f.createUser(t, user)
			if _, err := f.svc.findOrCreateOAuthUser(t.Context(), identity); err == nil || !strings.Contains(err.Error(), status) {
				t.Fatalf("error = %v, want %s", err, status)
			}
		})
	}
}

func TestLegacyOAuthLinkIntegration(t *testing.T) {
	tests := []struct {
		name                                            string
		verified, password, bound, suspended, ambiguous bool
		wantLink, wantError                             bool
	}{
		{name: "verified email", verified: true, wantLink: true},
		{name: "unverified or absent claim"},
		{name: "local password excluded", verified: true, password: true},
		{name: "bound account excluded", verified: true, bound: true},
		{name: "suspended legacy rejected", verified: true, suspended: true, wantError: true},
		{name: "ambiguous email rejected", verified: true, ambiguous: true, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newOAuthFixture(t)
			identity := f.identity("new-subject")
			identity.Claims.EmailVerified = tt.verified
			legacy := oauthUser{Email: identity.Claims.Email, Role: "admin"}
			if tt.password {
				legacy.PasswordHash = "local-password-hash"
			}
			if tt.bound {
				legacy.OIDCIssuer, legacy.OIDCSubject = f.issuer, "old-subject"
			}
			if tt.suspended {
				now := time.Now()
				legacy.SuspendedAt = &now
			}
			legacy = f.createUser(t, legacy)
			if tt.ambiguous {
				f.createUser(t, oauthUser{Username: "second", Email: identity.Claims.Email})
			}
			if tt.wantError {
				if _, err := f.svc.findOrCreateOAuthUser(t.Context(), identity); err == nil {
					t.Fatal("expected login error")
				}
				return
			}
			row := f.login(t, identity)
			if (row.ID == legacy.ID) != tt.wantLink {
				t.Fatalf("login id = %d, legacy id = %d, want link %t", row.ID, legacy.ID, tt.wantLink)
			}
			if tt.wantLink && row.Role != "admin" {
				t.Fatalf("linked role = %s, want admin", row.Role)
			}
			if !tt.wantLink && row.Role != "viewer" {
				t.Fatalf("new role = %s, want viewer", row.Role)
			}
		})
	}
}

func TestConcurrentOAuthFirstLoginIntegration(t *testing.T) {
	f := newOAuthFixture(t)
	start := make(chan struct{})
	var wg sync.WaitGroup
	// Unrelated auto-increment inserts share the pool, exercising connection reuse.
	for worker := range 8 {
		wg.Go(func() {
			<-start
			for n := range 100 {
				err := f.svc.db.WithContext(t.Context()).Table("voices").Create(map[string]any{
					"name": fmt.Sprintf("%s-%d-%d", f.prefix, worker, n),
				}).Error
				if err != nil {
					t.Errorf("background insert: %v", err)
					return
				}
			}
		})
	}
	for n := range 300 {
		wg.Go(func() {
			<-start
			identity := f.identity(fmt.Sprintf("subject-%d", n))
			// Shared preferred names also exercise duplicate-key insertion retries.
			id, err := f.svc.findOrCreateOAuthUser(t.Context(), identity)
			if err != nil {
				t.Errorf("login %d: %v", n, err)
				return
			}
			var row oauthUser
			if err := f.svc.db.Table("users").Where("id = ?", id).First(&row).Error; err != nil {
				t.Errorf("read id %d: %v", id, err)
				return
			}
			if row.OIDCIssuer != identity.Issuer || row.OIDCSubject != identity.Subject {
				t.Errorf("login %d returned id %d for %q/%q", n, id, row.OIDCIssuer, row.OIDCSubject)
			}
		})
	}
	close(start)
	wg.Wait()
	var count int64
	if err := f.svc.db.Table("users").Where("oidc_issuer = ?", f.issuer).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 300 {
		t.Fatalf("users = %d, want 300", count)
	}
}

func TestConcurrentSameOAuthIdentityIntegration(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy_%t", legacy), func(t *testing.T) {
			f := newOAuthFixture(t)
			identity := f.identity("shared")
			identity.Claims.EmailVerified = true
			if legacy {
				f.createUser(t, oauthUser{Email: identity.Claims.Email})
			}
			ids := make(chan int64, 30)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for range 30 {
				wg.Go(func() {
					<-start
					id, err := f.svc.findOrCreateOAuthUser(t.Context(), identity)
					if err != nil {
						t.Errorf("login: %v", err)
						return
					}
					ids <- id
				})
			}
			close(start)
			wg.Wait()
			close(ids)
			var first int64
			for id := range ids {
				if first == 0 {
					first = id
				}
				if id != first {
					t.Errorf("id = %d, want %d", id, first)
				}
			}
			var count int64
			if err := f.svc.db.Table("users").Where("oidc_issuer = ?", f.issuer).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("users = %d, want 1", count)
			}
		})
	}
}
