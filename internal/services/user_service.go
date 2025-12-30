// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/datatypes"
)

// UserService handles user-related business logic.
type UserService struct {
	repo repository.UserRepository
}

// NewUserService creates a new user service instance.
func NewUserService(repo repository.UserRepository) *UserService {
	return &UserService{
		repo: repo,
	}
}

// UpdateUserRequest represents the parameters for updating a user.
type UpdateUserRequest struct {
	Username  string
	FullName  string
	Email     *string
	Password  string
	Role      string
	Metadata  *datatypes.JSONMap
	Suspended *bool
}

// Create creates a new user account with the given parameters.
func (s *UserService) Create(ctx context.Context, username, fullName, email, password, role string, metadata *datatypes.JSONMap) (*models.User, error) {
	// Validate role
	if !isValidRole(role) {
		return nil, apperrors.Validation("User", "role", fmt.Sprintf("invalid role '%s'", role))
	}

	// Check username uniqueness
	taken, err := s.repo.IsUsernameTaken(ctx, username, nil)
	if err != nil {
		return nil, apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
	}
	if taken {
		return nil, apperrors.Duplicate("User", "username", username)
	}

	// Check email uniqueness (if provided)
	if email != "" {
		taken, err = s.repo.IsEmailTaken(ctx, email, nil)
		if err != nil {
			return nil, apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
		}
		if taken {
			return nil, apperrors.Duplicate("User", "email", email)
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, apperrors.Database("User", "hash", err)
	}

	// Handle email - empty string should be NULL
	var emailValue *string
	if email != "" {
		emailValue = &email
	}

	// Create user
	user, err := s.repo.Create(ctx, username, fullName, emailValue, string(hashedPassword), role, metadata)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateKey) {
			return nil, apperrors.Duplicate("User", "username or email", "")
		}
		return nil, apperrors.TranslateRepoError("User", apperrors.OpCreate, err)
	}

	return user, nil
}

// applyUsernameUpdate validates and applies username update.
func (s *UserService) applyUsernameUpdate(ctx context.Context, updates *repository.UserUpdate, username string, excludeID int64) error {
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
// If email is nil, the field is not updated.
// If email points to empty string, the email is cleared to NULL.
// Otherwise, the email is validated for uniqueness and updated.
func (s *UserService) applyEmailUpdate(ctx context.Context, u *repository.UserUpdate, email *string, excludeID int64) error {
	if email == nil {
		return nil
	}
	// Empty string means clear email to NULL
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
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return apperrors.Database("User", "hash", err)
	}
	hashedStr := string(hashedPassword)
	updates.PasswordHash = &hashedStr
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

// Update updates an existing user's information and returns the updated user.
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

	// Handle suspended separately
	if err := s.handleSuspendedUpdate(ctx, id, req.Suspended); err != nil {
		return nil, err
	}

	// Check if we have any updates
	hasUpdates := hasFieldUpdates(updates)
	if !hasUpdates && req.Suspended == nil {
		return nil, apperrors.Validation("User", "", "no fields to update")
	}

	// Apply field updates
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

// SoftDelete permanently deletes a user account and their sessions.
// It ensures at least one admin remains in the system.
func (s *UserService) SoftDelete(ctx context.Context, id int64) error {
	// Get the user to check their role
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
	}

	// If user is an admin, check that this is not the last admin
	if user.Role == models.RoleAdmin {
		adminCount, err := s.repo.CountActiveAdminsExcluding(ctx, id)
		if err != nil {
			return apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
		}

		if adminCount == 0 {
			return apperrors.Validation("User", "", "cannot delete last admin")
		}
	}

	// Delete user sessions first (ignore errors - session cleanup is non-critical)
	_ = s.repo.DeleteSessions(ctx, id)

	// Delete user (hard delete as users table doesn't have deleted_at)
	if err := s.repo.Delete(ctx, id); err != nil {
		return apperrors.TranslateRepoError("User", apperrors.OpDelete, err)
	}

	return nil
}

// Suspend prevents a user from logging in by marking their account as suspended.
// Returns the updated user.
func (s *UserService) Suspend(ctx context.Context, id int64) (*models.User, error) {
	if err := s.repo.SetSuspended(ctx, id, true); err != nil {
		return nil, apperrors.TranslateRepoError("User", apperrors.OpUpdate, err)
	}

	return s.GetByID(ctx, id)
}

// Unsuspend reactivates a suspended user account, allowing them to log in again.
// Returns the updated user.
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
func (s *UserService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.User], error) {
	result, err := s.repo.List(ctx, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("User", apperrors.OpQuery, err)
	}

	return result, nil
}
