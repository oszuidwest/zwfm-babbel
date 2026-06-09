package services

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/datatypes"
)

// UserService enforces account invariants such as unique usernames, password
// policy, role validity, and the last-admin guard.
type UserService struct {
	repo           *repository.UserRepository
	passwordPolicy PasswordPolicy
}

// PasswordPolicy defines the local password requirements for user accounts.
type PasswordPolicy struct {
	MinLength          int
	RequireUppercase   bool
	RequireLowercase   bool
	RequireNumber      bool
	RequireSpecialChar bool
}

// NewUserService returns a user service backed by repo and passwordPolicy.
func NewUserService(repo *repository.UserRepository, passwordPolicy PasswordPolicy) *UserService {
	return &UserService{
		repo:           repo,
		passwordPolicy: passwordPolicy,
	}
}

// Validate checks whether password satisfies the configured policy.
func (p PasswordPolicy) Validate(password string) error {
	if utf8.RuneCountInString(password) < p.MinLength {
		return fmt.Errorf("must be at least %d characters", p.MinLength)
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasNumber = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	return p.firstUnmetRequirement(hasUpper, hasLower, hasNumber, hasSpecial)
}

func (p PasswordPolicy) firstUnmetRequirement(hasUpper, hasLower, hasNumber, hasSpecial bool) error {
	switch {
	case p.RequireUppercase && !hasUpper:
		return errors.New("must contain an uppercase letter")
	case p.RequireLowercase && !hasLower:
		return errors.New("must contain a lowercase letter")
	case p.RequireNumber && !hasNumber:
		return errors.New("must contain a number")
	case p.RequireSpecialChar && !hasSpecial:
		return errors.New("must contain a special character")
	}
	return nil
}

// CreateUserRequest carries the required fields for a local user account.
type CreateUserRequest struct {
	Username string
	FullName string
	Email    string
	Password string
	Role     string
	Metadata *datatypes.JSONMap
}

// UpdateUserRequest carries PATCH-style account fields.
// Email uses nil to skip updates and an empty string to clear the stored email.
type UpdateUserRequest struct {
	Username  string
	FullName  string
	Email     *string
	Password  string
	Role      string
	Metadata  *datatypes.JSONMap
	Suspended *bool
}

// Create validates role, password policy, and uniqueness before storing a
// bcrypt password hash.
func (s *UserService) Create(ctx context.Context, req CreateUserRequest) (*models.User, error) {
	if !isValidRole(req.Role) {
		return nil, apperrors.Validation("User", "role", fmt.Sprintf("invalid role '%s'", req.Role))
	}

	if err := s.passwordPolicy.Validate(req.Password); err != nil {
		return nil, apperrors.Validation("User", "password", err.Error())
	}

	taken, err := s.repo.IsUsernameTaken(ctx, req.Username, nil)
	if err != nil {
		return nil, apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
	}
	if taken {
		return nil, apperrors.Duplicate("User", "username", req.Username)
	}

	if req.Email != "" {
		taken, err = s.repo.IsEmailTaken(ctx, req.Email, nil)
		if err != nil {
			return nil, apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
		}
		if taken {
			return nil, apperrors.Duplicate("User", "email", req.Email)
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, apperrors.Database("User", "hash", err)
	}

	var emailValue *string
	if req.Email != "" {
		emailValue = &req.Email
	}

	user, err := s.repo.Create(ctx, repository.CreateUserParams{
		Username:     req.Username,
		FullName:     req.FullName,
		Email:        emailValue,
		PasswordHash: string(hashedPassword),
		Role:         req.Role,
		Metadata:     req.Metadata,
	})
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateKey) {
			return nil, apperrors.Duplicate("User", "username or email", "")
		}
		return nil, apperrors.TranslateRepoError("User", apperrors.OpCreate, err)
	}

	return user, nil
}

// applyUsernameUpdate validates and applies username update.
func (s *UserService) applyUsernameUpdate(
	ctx context.Context, updates *repository.UserUpdate, username string, excludeID int64,
) error {
	if username == "" {
		return nil
	}
	taken, err := s.repo.IsUsernameTaken(ctx, username, &excludeID)
	if err != nil {
		return apperrors.Database("User", "query", err)
	}
	if taken {
		return apperrors.Duplicate("User", "username", username)
	}
	updates.Username = &username
	return nil
}

// applyEmailUpdate validates and applies email update.
// Nil skips the field; an empty string clears it to NULL.
func (s *UserService) applyEmailUpdate(
	ctx context.Context, u *repository.UserUpdate, email *string, excludeID int64,
) error {
	if email == nil {
		return nil
	}
	if *email == "" {
		u.ClearEmail = true
		return nil
	}
	taken, err := s.repo.IsEmailTaken(ctx, *email, &excludeID)
	if err != nil {
		return apperrors.Database("User", "query", err)
	}
	if taken {
		return apperrors.Duplicate("User", "email", *email)
	}
	u.Email = email
	return nil
}

// applyPasswordUpdate hashes and applies password update.
func (s *UserService) applyPasswordUpdate(updates *repository.UserUpdate, password string) error {
	if password == "" {
		return nil
	}
	if err := s.passwordPolicy.Validate(password); err != nil {
		return apperrors.Validation("User", "password", err.Error())
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return apperrors.Database("User", "hash", err)
	}
	hashedStr := string(hashedPassword)
	now := time.Now()
	zero := 0
	updates.PasswordHash = &hashedStr
	updates.PasswordChangedAt = &now
	updates.FailedLoginAttempts = &zero
	updates.ClearLockedUntil = true
	return nil
}

// applyRoleUpdate validates and applies role update.
func (s *UserService) applyRoleUpdate(updates *repository.UserUpdate, role string) error {
	if role == "" {
		return nil
	}
	if !isValidRole(role) {
		return apperrors.Validation("User", "role", fmt.Sprintf("invalid role '%s'", role))
	}
	updates.Role = &role
	return nil
}

// applyFullNameUpdate applies full name update.
func (s *UserService) applyFullNameUpdate(updates *repository.UserUpdate, fullName string) {
	if fullName != "" {
		updates.FullName = &fullName
	}
}

// applyMetadataUpdate applies metadata update.
func (s *UserService) applyMetadataUpdate(u *repository.UserUpdate, metadata *datatypes.JSONMap) {
	if metadata != nil {
		u.Metadata = metadata
	}
}

// handleSuspendedUpdate handles the suspended state update.
func (s *UserService) handleSuspendedUpdate(ctx context.Context, id int64, suspended *bool) error {
	if suspended == nil {
		return nil
	}
	if err := s.repo.SetSuspended(ctx, id, *suspended); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return apperrors.NotFoundWithID("User", id)
		}
		return apperrors.Database("User", "update", err)
	}
	return nil
}

// hasFieldUpdates reports whether any field updates are present.
func hasFieldUpdates(u *repository.UserUpdate) bool {
	return u.Username != nil || u.FullName != nil ||
		u.Email != nil || u.ClearEmail || u.PasswordHash != nil ||
		u.Role != nil || u.Metadata != nil
}

// executeFieldUpdates applies field updates to the repository.
func (s *UserService) executeFieldUpdates(ctx context.Context, id int64, updates *repository.UserUpdate) error {
	if err := s.repo.Update(ctx, id, updates); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return apperrors.NotFoundWithID("User", id)
		}
		return apperrors.Database("User", "update", err)
	}
	return nil
}

// Update applies account changes and returns the refreshed user.
// Suspended is updated separately so callers can suspend an account without
// sending any other changed fields.
func (s *UserService) Update(ctx context.Context, id int64, req *UpdateUserRequest) (*models.User, error) {
	updates := &repository.UserUpdate{}

	if err := s.applyUsernameUpdate(ctx, updates, req.Username, id); err != nil {
		return nil, err
	}
	if err := s.applyEmailUpdate(ctx, updates, req.Email, id); err != nil {
		return nil, err
	}
	if err := s.applyPasswordUpdate(updates, req.Password); err != nil {
		return nil, err
	}
	if err := s.applyRoleUpdate(updates, req.Role); err != nil {
		return nil, err
	}
	s.applyFullNameUpdate(updates, req.FullName)
	s.applyMetadataUpdate(updates, req.Metadata)

	if err := s.handleSuspendedUpdate(ctx, id, req.Suspended); err != nil {
		return nil, err
	}

	hasUpdates := hasFieldUpdates(updates)
	if !hasUpdates && req.Suspended == nil {
		return nil, apperrors.Validation("User", "", "no fields to update")
	}

	if hasUpdates {
		if err := s.executeFieldUpdates(ctx, id, updates); err != nil {
			return nil, err
		}
	}

	return s.GetByID(ctx, id)
}

// GetByID retrieves a user by their ID.
func (s *UserService) GetByID(ctx context.Context, id int64) (*models.User, error) {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
	}

	return user, nil
}

// SoftDelete permanently deletes a user and their sessions.
// It rejects deletion of the last active admin.
func (s *UserService) SoftDelete(ctx context.Context, id int64) error {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
	}

	if user.Role == models.RoleAdmin {
		adminCount, err := s.repo.CountActiveAdminsExcluding(ctx, id)
		if err != nil {
			return apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
		}

		if adminCount == 0 {
			return apperrors.Validation("User", "", "cannot delete last admin")
		}
	}

	_ = s.repo.DeleteSessions(ctx, id)

	if err := s.repo.Delete(ctx, id); err != nil {
		return apperrors.TranslateRepoError("User", apperrors.OpDelete, err)
	}

	return nil
}

// Suspend prevents a user from logging in and returns the refreshed account.
func (s *UserService) Suspend(ctx context.Context, id int64) (*models.User, error) {
	if err := s.repo.SetSuspended(ctx, id, true); err != nil {
		return nil, apperrors.TranslateRepoError("User", apperrors.OpUpdate, err)
	}

	return s.GetByID(ctx, id)
}

// Unsuspend allows a suspended user to log in again and returns the refreshed
// account.
func (s *UserService) Unsuspend(ctx context.Context, id int64) (*models.User, error) {
	if err := s.repo.SetSuspended(ctx, id, false); err != nil {
		return nil, apperrors.TranslateRepoError("User", apperrors.OpUpdate, err)
	}

	return s.GetByID(ctx, id)
}

// isValidRole reports whether the given role is valid.
func isValidRole(role string) bool {
	validRoles := []string{string(models.RoleAdmin), string(models.RoleEditor), string(models.RoleViewer)}
	return slices.Contains(validRoles, role)
}

// List retrieves a paginated list of users with filtering, sorting, and search support.
func (s *UserService) List(
	ctx context.Context, query *repository.ListQuery,
) (*repository.ListResult[models.User], error) {
	result, err := s.repo.List(ctx, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
	}

	return result, nil
}
