package auth

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

// ErrLoginRejected marks OIDC login errors safe to show to the user.
var ErrLoginRejected = errors.New("OIDC login rejected")

type oauthClaims struct {
	Email             string `json:"email"`
	EmailVerified     any    `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

// emailMayLink permits linking by non-empty email when email_verified is absent
// (as with Entra ID), true, or "true".
func (c oauthClaims) emailMayLink() bool {
	v := c.EmailVerified
	return c.Email != "" && (v == nil || v == true || v == "true")
}

type oauthIdentity struct {
	Issuer  string
	Subject string
	Claims  oauthClaims
}

type oauthUser struct {
	ID           int64 `gorm:"primaryKey"`
	Username     string
	FullName     string
	Email        string
	PasswordHash string
	Role         string
	OIDCIssuer   string `gorm:"column:oidc_issuer"`
	OIDCSubject  string `gorm:"column:oidc_subject"`
	SuspendedAt  *time.Time
	DeletedAt    *time.Time
}

func (u oauthUser) activeID() (int64, error) {
	if u.DeletedAt != nil {
		return 0, fmt.Errorf("%w: account is deleted", ErrLoginRejected)
	}
	if u.SuspendedAt != nil {
		return 0, fmt.Errorf("%w: account is suspended", ErrLoginRejected)
	}
	return u.ID, nil
}

// findOrCreateOAuthUser requires an identity from a verified ID token.
func (s *Service) findOrCreateOAuthUser(ctx context.Context, identity oauthIdentity) (int64, error) {
	// Length limits match the database columns.
	if identity.Subject == "" || len(identity.Subject) > 255 || len(identity.Issuer) > 512 {
		return 0, fmt.Errorf("%w: token is missing sub or has an oversized issuer/subject", ErrLoginRejected)
	}
	if id, err := s.findOAuthUser(ctx, identity); !errors.Is(err, gorm.ErrRecordNotFound) {
		return id, err
	}
	if id, err := s.linkLegacyOAuthUser(ctx, identity); !errors.Is(err, gorm.ErrRecordNotFound) {
		return id, err
	}
	base := sanitizeUsername(cmp.Or(identity.Claims.PreferredUsername, identity.Claims.Email))
	username, err := s.ensureUniqueUsername(ctx, base)
	if err != nil {
		return 0, err
	}
	for range 10 {
		user := oauthUser{
			Username: username, FullName: identity.Claims.Name, Email: identity.Claims.Email,
			Role: "viewer", OIDCIssuer: identity.Issuer, OIDCSubject: identity.Subject,
		}
		err = s.db.WithContext(ctx).Table("users").Create(&user).Error
		if err == nil {
			return user.ID, nil
		}
		if !isOAuthConflict(err) {
			return 0, fmt.Errorf("failed to create OAuth user: %w", err)
		}
		// A concurrent login may have created this identity.
		if id, err := s.findOAuthUser(ctx, identity); !errors.Is(err, gorm.ErrRecordNotFound) {
			return id, err
		}
		// Random suffixes reduce collisions between concurrent signups.
		username = oauthUsernameSuffix(base, rand.Text()[:8])
	}
	return 0, fmt.Errorf("could not allocate a unique OAuth username: %w", err)
}

func (s *Service) findOAuthUser(ctx context.Context, identity oauthIdentity) (int64, error) {
	var user oauthUser
	err := s.db.WithContext(ctx).Table("users").
		Where("oidc_issuer = ? AND oidc_subject = ?", identity.Issuer, identity.Subject).First(&user).Error
	if err != nil {
		return 0, fmt.Errorf("failed to query OAuth user: %w", err)
	}
	return user.activeID()
}

const legacyOAuthMatch = "email = ? AND password_hash = '' AND oidc_issuer IS NULL AND oidc_subject IS NULL AND deleted_at IS NULL"

// linkLegacyOAuthUser links a unique email match without a password or OIDC identity.
func (s *Service) linkLegacyOAuthUser(ctx context.Context, identity oauthIdentity) (int64, error) {
	if !identity.Claims.emailMayLink() {
		return 0, gorm.ErrRecordNotFound
	}
	users := []oauthUser{}
	err := s.db.WithContext(ctx).Table("users").Where(legacyOAuthMatch, identity.Claims.Email).Limit(2).Find(&users).Error
	if err != nil {
		return 0, fmt.Errorf("failed to query legacy OAuth user: %w", err)
	}
	if len(users) == 0 {
		return 0, gorm.ErrRecordNotFound
	}
	if len(users) != 1 {
		return 0, fmt.Errorf("%w: multiple accounts match this email; contact an administrator", ErrLoginRejected)
	}
	user := users[0]
	if _, err := user.activeID(); err != nil {
		return 0, err
	}
	bound, err := s.bindLegacyOAuthUser(ctx, user.ID, identity)
	if err != nil && !isOAuthConflict(err) {
		return 0, fmt.Errorf("failed to link legacy OAuth user: %w", err)
	}
	if bound {
		return user.ID, nil
	}
	// A concurrent link may have won; never return the stale email match.
	if id, ferr := s.findOAuthUser(ctx, identity); !errors.Is(ferr, gorm.ErrRecordNotFound) {
		return id, ferr
	}
	if err != nil {
		return 0, fmt.Errorf("legacy account link conflicted: %w", err)
	}
	return 0, fmt.Errorf("%w: account changed during login; retry login", ErrLoginRejected)
}

// bindLegacyOAuthUser rechecks eligibility and reports whether it linked the account.
func (s *Service) bindLegacyOAuthUser(ctx context.Context, id int64, identity oauthIdentity) (bool, error) {
	result := s.db.WithContext(ctx).Table("users").Where("id = ? AND suspended_at IS NULL", id).
		Where(legacyOAuthMatch, identity.Claims.Email).
		Updates(map[string]any{"oidc_issuer": identity.Issuer, "oidc_subject": identity.Subject})
	return result.RowsAffected == 1, result.Error
}

// isOAuthConflict includes deadlocks from simultaneous unique-key inserts.
func isOAuthConflict(err error) bool {
	mysqlErr, ok := errors.AsType[*mysql.MySQLError](err)
	return ok && (mysqlErr.Number == 1062 || mysqlErr.Number == 1213)
}

var usernameSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

func sanitizeUsername(name string) string {
	base, domain, found := strings.Cut(name, "@")
	username := usernameSanitizeRe.ReplaceAllString(base, "_")
	if len(username) < 3 && found {
		domain, _, _ = strings.Cut(domain, ".")
		username += "_" + usernameSanitizeRe.ReplaceAllString(domain, "_")
	}
	if username == "" {
		username = "oidc_user"
	}
	return username[:min(len(username), 100)]
}

// ensureUniqueUsername includes deleted rows because their names remain reserved.
func (s *Service) ensureUniqueUsername(ctx context.Context, baseUsername string) (string, error) {
	username := baseUsername
	for counter := 1; ; counter++ {
		var count int64
		if err := s.db.WithContext(ctx).Table("users").Where("username = ?", username).Count(&count).Error; err != nil {
			return "", fmt.Errorf("failed to check OAuth username: %w", err)
		}
		if count == 0 {
			return username, nil
		}
		username = oauthUsernameSuffix(baseUsername, fmt.Sprint(counter))
	}
}

func oauthUsernameSuffix(base, suffix string) string {
	return base[:min(len(base), 100-len(suffix)-1)] + "_" + suffix
}
