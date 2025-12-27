// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// UserService handles user-related business logic
type UserService struct {
	repo repository.UserRepository
}

// NewUserService creates a new user service instance
func NewUserService(repo repository.UserRepository) *UserService {
	return &UserService{
		repo: repo,
	}
}

// UpdateUserRequest represents the parameters for updating a user
type UpdateUserRequest struct {
	Username  string
	FullName  string
	Email     *string
	Password  string
	Role      string
	Metadata  string
	Suspended *bool
}

// Create creates a new user account with the given parameters
func (s *UserService) Create(ctx context.Context, username, fullName, email, password, role string) (*models.User, error) {
	const op = "UserService.Create"

	// Validate role
	if !isValidRole(role) {
		return nil, fmt.Errorf("%s: %w: invalid role '%s'", op, ErrInvalidInput, role)
	}

	// Check username uniqueness
	taken, err := s.repo.IsUsernameTaken(ctx, username, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if taken {
		return nil, fmt.Errorf("%s: %w: username '%s'", op, ErrDuplicate, username)
	}

	// Check email uniqueness (if provided)
	if email != "" {
		taken, err = s.repo.IsEmailTaken(ctx, email, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
		}
		if taken {
			return nil, fmt.Errorf("%s: %w: email '%s'", op, ErrDuplicate, email)
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to hash password: %w", op, err)
	}

	// Handle email - empty string should be NULL
	var emailValue *string
	if email != "" {
		emailValue = &email
	}

	// Create user
	user, err := s.repo.Create(ctx, username, fullName, emailValue, string(hashedPassword), role)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateKey) {
			return nil, fmt.Errorf("%s: %w: username or email already exists", op, ErrDuplicate)
		}
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return user, nil
}

// applyUsernameUpdate validates and applies username update.
func (s *UserService) applyUsernameUpdate(ctx context.Context, updates *repository.UserUpdate, username string, excludeID int) error {
	if username == "" {
		return nil
	}
	taken, err := s.repo.IsUsernameTaken(ctx, username, &excludeID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	if taken {
		return fmt.Errorf("%w: username '%s'", ErrDuplicate, username)
	}
	updates.Username = &username
	return nil
}

// applyEmailUpdate validates and applies email update.
func (s *UserService) applyEmailUpdate(ctx context.Context, updates *repository.UserUpdate, email *string, excludeID int) error {
	if email == nil || *email == "" {
		return nil
	}
	taken, err := s.repo.IsEmailTaken(ctx, *email, &excludeID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	if taken {
		return fmt.Errorf("%w: email '%s'", ErrDuplicate, *email)
	}
	updates.Email = &email
	return nil
}

// applyPasswordUpdate hashes and applies password update.
func (s *UserService) applyPasswordUpdate(updates *repository.UserUpdate, password string) error {
	if password == "" {
		return nil
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
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
		return fmt.Errorf("%w: invalid role '%s'", ErrInvalidInput, role)
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
func (s *UserService) applyMetadataUpdate(updates *repository.UserUpdate, metadata string) {
	if metadata != "" {
		metadataPtr := &metadata
		updates.Metadata = &metadataPtr
	}
}

// handleSuspendedUpdate handles the suspended state update.
func (s *UserService) handleSuspendedUpdate(ctx context.Context, id int, suspended *bool) error {
	if suspended == nil {
		return nil
	}
	if err := s.repo.SetSuspended(ctx, id, *suspended); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	return nil
}

// hasFieldUpdates checks if any field updates are present.
func hasFieldUpdates(updates *repository.UserUpdate) bool {
	return updates.Username != nil || updates.FullName != nil ||
		updates.Email != nil || updates.PasswordHash != nil ||
		updates.Role != nil || updates.Metadata != nil
}

// executeFieldUpdates applies field updates to the repository.
func (s *UserService) executeFieldUpdates(ctx context.Context, id int, updates *repository.UserUpdate) error {
	if err := s.repo.Update(ctx, id, updates); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	return nil
}

// Update updates an existing user's information
func (s *UserService) Update(ctx context.Context, id int, req *UpdateUserRequest) error {
	const op = "UserService.Update"

	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	updates := &repository.UserUpdate{}

	if err := s.applyUsernameUpdate(ctx, updates, req.Username, id); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := s.applyEmailUpdate(ctx, updates, req.Email, id); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := s.applyPasswordUpdate(updates, req.Password); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := s.applyRoleUpdate(updates, req.Role); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	s.applyFullNameUpdate(updates, req.FullName)
	s.applyMetadataUpdate(updates, req.Metadata)

	// Handle suspended separately
	if err := s.handleSuspendedUpdate(ctx, id, req.Suspended); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Check if we have any updates
	hasUpdates := hasFieldUpdates(updates)
	if !hasUpdates && req.Suspended == nil {
		return fmt.Errorf("%s: %w: no fields to update", op, ErrInvalidInput)
	}

	// Apply field updates
	if hasUpdates {
		if err := s.executeFieldUpdates(ctx, id, updates); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	return nil
}

// GetByID retrieves a user by their ID
func (s *UserService) GetByID(ctx context.Context, id int) (*models.User, error) {
	const op = "UserService.GetByID"

	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return user, nil
}

// SoftDelete performs a hard delete of a user account (users table doesn't support soft deletes)
// Checks that this is not the last admin user before deletion
func (s *UserService) SoftDelete(ctx context.Context, id int) error {
	const op = "UserService.SoftDelete"

	// Get the user to check their role
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	// If user is an admin, check that this is not the last admin
	if user.Role == models.RoleAdmin {
		adminCount, err := s.repo.CountActiveAdminsExcluding(ctx, id)
		if err != nil {
			return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
		}

		if adminCount == 0 {
			return fmt.Errorf("%s: %w", op, ErrInvalidInput)
		}
	}

	// Delete user sessions first (ignore errors - session cleanup is non-critical)
	_ = s.repo.DeleteSessions(ctx, id)

	// Delete user (hard delete as users table doesn't have deleted_at)
	err = s.repo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return nil
}

// Suspend suspends a user account by setting suspended_at to current time
func (s *UserService) Suspend(ctx context.Context, id int) error {
	const op = "UserService.Suspend"

	// Check if user exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	// Suspend user
	err = s.repo.SetSuspended(ctx, id, true)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return nil
}

// Unsuspend restores a suspended user account by clearing suspended_at
func (s *UserService) Unsuspend(ctx context.Context, id int) error {
	const op = "UserService.Unsuspend"

	// Check if user exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	// Unsuspend user
	err = s.repo.SetSuspended(ctx, id, false)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return nil
}

// isValidRole checks if a role is valid
func isValidRole(role string) bool {
	validRoles := []string{string(models.RoleAdmin), string(models.RoleEditor), string(models.RoleViewer)}
	for _, validRole := range validRoles {
		if role == validRole {
			return true
		}
	}
	return false
}

// DB returns the underlying database for ModernListWithQuery.
func (s *UserService) DB() *sqlx.DB {
	return s.repo.DB()
}
