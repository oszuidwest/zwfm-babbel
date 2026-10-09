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
	row, err := f.loginOwned(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// loginOwned logs in and checks that the returned ID belongs to the identity.
func (f oauthFixture) loginOwned(ctx context.Context, identity oauthIdentity) (oauthUser, error) {
	var row oauthUser
	id, err := f.svc.findOrCreateOAuthUser(ctx, identity)
	if err != nil {
		return row, err
	}
	if err := f.svc.db.Table("users").Where("id = ?", id).First(&row).Error; err != nil {
		return row, err
	}
	if row.OIDCIssuer != identity.Issuer || row.OIDCSubject != identity.Subject {
		return row, fmt.Errorf("returned id %d belongs to %q/%q, want %q/%q", id, row.OIDCIssuer, row.OIDCSubject, identity.Issuer, identity.Subject)
	}
	return row, nil
}

func TestNewOAuthUserIntegration(t *testing.T) {
	f := newOAuthFixture(t)
	identity := f.identity("new")
	row := f.login(t, identity)
	if row.Role != "viewer" || row.FullName != identity.Claims.Name || row.Email != identity.Claims.Email {
		t.Fatalf("new user = %+v", row)
	}
	identity.Claims.Email = "changed@example.com"
	if again := f.login(t, identity); again.ID != row.ID {
		t.Fatalf("repeat id = %d, want %d", again.ID, row.ID)
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
	now := time.Now()
	for status, user := range map[string]oauthUser{"suspended": {SuspendedAt: &now}, "deleted": {DeletedAt: &now}} {
		t.Run(status+" subject rejected", func(t *testing.T) {
			f := newOAuthFixture(t)
			identity := f.identity(status)
			user.OIDCIssuer, user.OIDCSubject = identity.Issuer, identity.Subject
			f.createUser(t, user)
			if _, err := f.svc.findOrCreateOAuthUser(t.Context(), identity); err == nil || !strings.Contains(err.Error(), status) {
				t.Fatalf("error = %v, want %s", err, status)
			}
		})
	}
}

func TestLegacyOAuthLinkIntegration(t *testing.T) {
	tests := []struct {
		name                                                       string
		verified                                                   any
		emptyEmail, password, bound, suspended, deleted, ambiguous bool
		wantLink, wantError                                        bool
	}{
		{name: "absent claim (Entra ID)", wantLink: true},
		{name: "verified email", verified: true, wantLink: true},
		{name: "empty verified email excluded", verified: true, emptyEmail: true},
		{name: "explicitly unverified email", verified: false},
		{name: "deleted account excluded", deleted: true},
		{name: "local password excluded", password: true},
		{name: "bound account excluded", bound: true},
		{name: "suspended legacy rejected", suspended: true, wantError: true},
		{name: "ambiguous email rejected", ambiguous: true, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newOAuthFixture(t)
			identity := f.identity("new-subject")
			identity.Claims.EmailVerified = tt.verified
			if tt.emptyEmail {
				identity.Claims.Email = ""
			}
			legacy := oauthUser{Email: identity.Claims.Email, Role: "admin"}
			if tt.password {
				legacy.PasswordHash = "local-password-hash"
			}
			if tt.bound {
				legacy.OIDCIssuer, legacy.OIDCSubject = f.issuer, "old-subject"
			}
			now := time.Now()
			if tt.suspended {
				legacy.SuspendedAt = &now
			}
			if tt.deleted {
				legacy.DeletedAt = &now
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
				t.Fatalf("linked role = %s, want admin kept", row.Role)
			}
		})
	}
}

func TestLegacyOAuthLinkSingleWinnerIntegration(t *testing.T) {
	f := newOAuthFixture(t)
	first, second := f.identity("first"), f.identity("second")
	legacy := f.createUser(t, oauthUser{Email: first.Claims.Email, Role: "admin"})
	// Simulate two logins selecting the same account before either binds it.
	for _, tt := range []struct {
		identity oauthIdentity
		want     bool
	}{{first, true}, {second, false}} {
		if bound, err := f.svc.bindLegacyOAuthUser(t.Context(), legacy.ID, tt.identity); err != nil || bound != tt.want {
			t.Fatalf("bind %s = %t, %v; want %t", tt.identity.Subject, bound, err, tt.want)
		}
	}
	var row oauthUser
	if err := f.svc.db.Table("users").Where("id = ?", legacy.ID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.OIDCSubject != first.Subject {
		t.Fatalf("legacy bound to %q, want %q", row.OIDCSubject, first.Subject)
	}
	if id, err := f.svc.findOrCreateOAuthUser(t.Context(), second); err != nil || id == legacy.ID {
		t.Fatalf("second login = %d, %v; want a new account, not legacy %d", id, err, legacy.ID)
	}
}

// concurrentLogins checks identity ownership and counts users for the fixture's issuer.
func (f oauthFixture) concurrentLogins(t *testing.T, n int, identity func(int) oauthIdentity) int64 {
	t.Helper()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			if _, err := f.loginOwned(t.Context(), identity(i)); err != nil {
				t.Errorf("login %d: %v", i, err)
			}
		})
	}
	close(start)
	wg.Wait()
	var count int64
	if err := f.svc.db.Table("users").Where("oidc_issuer = ?", f.issuer).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}

func TestConcurrentOAuthFirstLoginIntegration(t *testing.T) {
	f := newOAuthFixture(t)
	// Unrelated inserts expose LAST_INSERT_ID() reads on the wrong connection.
	done := make(chan struct{})
	var background sync.WaitGroup
	background.Go(func() {
		for n := 0; ; n++ {
			select {
			case <-done:
				return
			default:
			}
			if err := f.svc.db.Exec("INSERT INTO voices (name) VALUES (?)", fmt.Sprintf("%s-%d", f.prefix, n)).Error; err != nil {
				t.Errorf("background insert: %v", err)
				return
			}
		}
	})
	defer background.Wait()
	defer close(done)
	// Shared usernames exercise duplicate-key retries.
	if count := f.concurrentLogins(t, 300, func(i int) oauthIdentity { return f.identity(fmt.Sprintf("subject-%d", i)) }); count != 300 {
		t.Fatalf("users = %d, want 300", count)
	}
}

func TestConcurrentSameOAuthIdentityIntegration(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy_%t", legacy), func(t *testing.T) {
			f := newOAuthFixture(t)
			identity := f.identity("shared")
			if legacy {
				f.createUser(t, oauthUser{Email: identity.Claims.Email})
			}
			if count := f.concurrentLogins(t, 30, func(int) oauthIdentity { return identity }); count != 1 {
				t.Fatalf("users = %d, want 1", count)
			}
		})
	}
}
