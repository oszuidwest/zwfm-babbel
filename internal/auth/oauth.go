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

type oauthClaims struct {
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

type oauthIdentity struct {
	Issuer  string
	Subject string
	Claims  oauthClaims
}

// oauthUser includes the private identity columns and receives the insert ID.
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
		return 0, errors.New("account is deleted")
	}
	if u.SuspendedAt != nil {
		return 0, errors.New("account is suspended")
	}
	return u.ID, nil
}

// findOrCreateOAuthUser binds only verified token issuer/subject pairs to users.
func (s *Service) findOrCreateOAuthUser(ctx context.Context, identity oauthIdentity) (int64, error) {
	// go-oidc already verified a non-empty issuer; the limits match the columns.
	if identity.Subject == "" || len(identity.Subject) > 255 || len(identity.Issuer) > 512 {
		return 0, errors.New("OIDC token is missing sub or has an oversized issuer/subject")
	}
	if id, err := s.findOAuthUser(ctx, identity); !errors.Is(err, gorm.ErrRecordNotFound) {
		return id, err
	}
	if id, err := s.linkLegacyOAuthUser(ctx, identity); !errors.Is(err, gorm.ErrRecordNotFound) {
		return id, err
	}
	base := sanitizeEmailToUsername(cmp.Or(identity.Claims.PreferredUsername, identity.Claims.Email))
	username, err := s.ensureUniqueUsername(ctx, base)
	if err != nil {
		return 0, err
	}
	for range 10 {
		user := oauthUser{
			Username: username, FullName: identity.Claims.Name, Email: identity.Claims.Email,
			Role: "viewer", OIDCIssuer: identity.Issuer, OIDCSubject: identity.Subject,
		}
		err := s.db.WithContext(ctx).Table("users").Create(&user).Error
		if err == nil {
			return user.ID, nil
		}
		if !isOAuthConflict(err) {
			return 0, fmt.Errorf("failed to create OAuth user: %w", err)
		}
		// Another first login may have inserted this identity while we chose a name.
		if id, err := s.findOAuthUser(ctx, identity); !errors.Is(err, gorm.ErrRecordNotFound) {
			return id, err
		}
		// A random suffix avoids repeated collisions between simultaneous signups;
		// the insert itself enforces uniqueness.
		username = oauthUsernameSuffix(base, rand.Text()[:8])
	}
	return 0, errors.New("could not allocate a unique OAuth username; retry login")
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

// linkLegacyOAuthUser only adopts an unambiguous passwordless legacy account.
// Absent email_verified is treated as false, including for Entra ID.
func (s *Service) linkLegacyOAuthUser(ctx context.Context, identity oauthIdentity) (int64, error) {
	if identity.Claims.Email == "" || !identity.Claims.EmailVerified {
		return 0, gorm.ErrRecordNotFound
	}
	users := []oauthUser{}
	err := s.db.WithContext(ctx).Table("users").
		Where("email = ? AND password_hash = ''", identity.Claims.Email).
		Where("oidc_issuer IS NULL AND oidc_subject IS NULL AND deleted_at IS NULL").Limit(2).Find(&users).Error
	if err != nil {
		return 0, fmt.Errorf("failed to query legacy OAuth user: %w", err)
	}
	if len(users) == 0 {
		return 0, gorm.ErrRecordNotFound
	}
	if len(users) != 1 {
		return 0, errors.New("multiple legacy accounts match verified email; contact an administrator")
	}
	user := users[0]
	if _, err := user.activeID(); err != nil {
		return 0, err
	}
	result := s.db.WithContext(ctx).Table("users").Where("id = ?", user.ID).
		Where("oidc_issuer IS NULL AND oidc_subject IS NULL AND deleted_at IS NULL AND suspended_at IS NULL").
		Where("email = ? AND password_hash = ''", identity.Claims.Email).
		Updates(map[string]any{"oidc_issuer": identity.Issuer, "oidc_subject": identity.Subject})
	if result.Error != nil && !isOAuthConflict(result.Error) {
		return 0, fmt.Errorf("failed to link legacy OAuth user: %w", result.Error)
	}
	if result.Error == nil && result.RowsAffected == 1 {
		return user.ID, nil
	}
	// A concurrent link may have won; never return the stale email match.
	if id, err := s.findOAuthUser(ctx, identity); !errors.Is(err, gorm.ErrRecordNotFound) {
		return id, err
	}
	return 0, errors.New("legacy account changed during login; retry login")
}

// isOAuthConflict includes deadlocks from simultaneous unique-key inserts.
func isOAuthConflict(err error) bool {
	mysqlErr, ok := errors.AsType[*mysql.MySQLError](err)
	return ok && (mysqlErr.Number == 1062 || mysqlErr.Number == 1213)
}

// usernameSanitizeRe matches characters that are not allowed in usernames.
var usernameSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// sanitizeEmailToUsername converts an email or preferred username to a base name.
func sanitizeEmailToUsername(email string) string {
	base, domain, found := strings.Cut(email, "@")
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
