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

// Update updates an existing user's information
func (s *UserService) Update(ctx context.Context, id int, req *UpdateUserRequest) error {
	const op = "UserService.Update"

	// Check if user exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	// Build updates map
	updates := make(map[string]interface{})

	// Apply each field update
	if err := s.applyUsernameUpdate(ctx, id, req, updates); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := s.applyPasswordUpdate(req, updates); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := s.applyEmailUpdate(ctx, id, req, updates); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := s.applyRoleUpdate(req, updates); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	s.applyFullNameUpdate(req, updates)
	s.applyMetadataUpdate(req, updates)

	// Handle suspended separately using SetSuspended
	if req.Suspended != nil {
		if err := s.repo.SetSuspended(ctx, id, *req.Suspended); err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return fmt.Errorf("%s: %w", op, ErrNotFound)
			}
			return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
		}
	}

	if len(updates) == 0 && req.Suspended == nil {
		return fmt.Errorf("%s: %w: no fields to update", op, ErrInvalidInput)
	}

	if len(updates) > 0 {
		err = s.repo.Update(ctx, id, updates)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return fmt.Errorf("%s: %w", op, ErrNotFound)
			}
			return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
		}
	}

	return nil
}

// applyUsernameUpdate applies username field update if provided
func (s *UserService) applyUsernameUpdate(ctx context.Context, id int, req *UpdateUserRequest, updates map[string]interface{}) error {
	if req.Username == "" {
		return nil
	}

	taken, err := s.repo.IsUsernameTaken(ctx, req.Username, &id)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	if taken {
		return fmt.Errorf("%w: username '%s'", ErrDuplicate, req.Username)
	}

	updates["username"] = req.Username
	return nil
}

// applyPasswordUpdate applies password field update if provided
func (s *UserService) applyPasswordUpdate(req *UpdateUserRequest, updates map[string]interface{}) error {
	if req.Password == "" {
		return nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	updates["password_hash"] = string(hashedPassword)
	// Note: password_changed_at will need to be handled via raw SQL or separate update
	return nil
}

// applyEmailUpdate applies email field update if provided
func (s *UserService) applyEmailUpdate(ctx context.Context, id int, req *UpdateUserRequest, updates map[string]interface{}) error {
	if req.Email == nil || *req.Email == "" {
		return nil
	}

	taken, err := s.repo.IsEmailTaken(ctx, *req.Email, &id)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	if taken {
		return fmt.Errorf("%w: email '%s'", ErrDuplicate, *req.Email)
	}

	updates["email"] = *req.Email
	return nil
}

// applyRoleUpdate applies role field update if provided
func (s *UserService) applyRoleUpdate(req *UpdateUserRequest, updates map[string]interface{}) error {
	if req.Role == "" {
		return nil
	}

	if !isValidRole(req.Role) {
		return fmt.Errorf("%w: invalid role '%s'", ErrInvalidInput, req.Role)
	}

	updates["role"] = req.Role
	return nil
}

// applyFullNameUpdate applies full_name field update if provided
func (s *UserService) applyFullNameUpdate(req *UpdateUserRequest, updates map[string]interface{}) {
	if req.FullName == "" {
		return
	}

	updates["full_name"] = req.FullName
}

// applyMetadataUpdate applies metadata field update if provided
func (s *UserService) applyMetadataUpdate(req *UpdateUserRequest, updates map[string]interface{}) {
	if req.Metadata == "" {
		return
	}

	updates["metadata"] = req.Metadata
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
