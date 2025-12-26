// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// UserService handles user-related business logic
type UserService struct {
	db *sqlx.DB
}

// NewUserService creates a new user service instance
func NewUserService(db *sqlx.DB) *UserService {
	return &UserService{
		db: db,
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
	if err := s.checkUsernameUnique(ctx, username, nil); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Check email uniqueness (if provided)
	if email != "" {
		if err := s.checkEmailUnique(ctx, email, nil); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to hash password: %w", op, err)
	}

	// Handle email - empty string should be NULL
	var emailValue interface{}
	if email == "" {
		emailValue = nil
	} else {
		emailValue = email
	}

	// Create user
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO users (username, full_name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
		username, fullName, emailValue, string(hashedPassword), role,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get last insert id: %w", op, err)
	}

	// Fetch the created user
	user, err := s.GetByID(ctx, int(id))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

// Update updates an existing user's information
func (s *UserService) Update(ctx context.Context, id int, req *UpdateUserRequest) error {
	const op = "UserService.Update"

	// Check if user exists
	_, err := s.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}

	// Apply each field update
	if err := s.applyUsernameUpdate(ctx, id, req, &updates, &args); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := s.applyPasswordUpdate(req, &updates, &args); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := s.applyEmailUpdate(ctx, id, req, &updates, &args); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := s.applyRoleUpdate(req, &updates, &args); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	s.applyFullNameUpdate(req, &updates, &args)
	s.applyMetadataUpdate(req, &updates, &args)
	s.applySuspendedUpdate(req, &updates)

	if len(updates) == 0 {
		return fmt.Errorf("%s: %w: no fields to update", op, ErrInvalidInput)
	}

	// Build and execute query
	query := "UPDATE users SET " + joinStrings(updates, ", ") + " WHERE id = ?"
	args = append(args, id)

	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	return nil
}

// applyUsernameUpdate applies username field update if provided
func (s *UserService) applyUsernameUpdate(ctx context.Context, id int, req *UpdateUserRequest, updates *[]string, args *[]interface{}) error {
	if req.Username == "" {
		return nil
	}

	if err := s.checkUsernameUnique(ctx, req.Username, &id); err != nil {
		return err
	}

	*updates = append(*updates, "username = ?")
	*args = append(*args, req.Username)
	return nil
}

// applyPasswordUpdate applies password field update if provided
func (s *UserService) applyPasswordUpdate(req *UpdateUserRequest, updates *[]string, args *[]interface{}) error {
	if req.Password == "" {
		return nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	*updates = append(*updates, "password_hash = ?, password_changed_at = NOW()")
	*args = append(*args, string(hashedPassword))
	return nil
}

// applyEmailUpdate applies email field update if provided
func (s *UserService) applyEmailUpdate(ctx context.Context, id int, req *UpdateUserRequest, updates *[]string, args *[]interface{}) error {
	if req.Email == nil || *req.Email == "" {
		return nil
	}

	if err := s.checkEmailUnique(ctx, *req.Email, &id); err != nil {
		return err
	}

	*updates = append(*updates, "email = ?")
	*args = append(*args, *req.Email)
	return nil
}

// applyRoleUpdate applies role field update if provided
func (s *UserService) applyRoleUpdate(req *UpdateUserRequest, updates *[]string, args *[]interface{}) error {
	if req.Role == "" {
		return nil
	}

	if !isValidRole(req.Role) {
		return fmt.Errorf("%w: invalid role '%s'", ErrInvalidInput, req.Role)
	}

	*updates = append(*updates, "role = ?")
	*args = append(*args, req.Role)
	return nil
}

// applyFullNameUpdate applies full_name field update if provided
func (s *UserService) applyFullNameUpdate(req *UpdateUserRequest, updates *[]string, args *[]interface{}) {
	if req.FullName == "" {
		return
	}

	*updates = append(*updates, "full_name = ?")
	*args = append(*args, req.FullName)
}

// applyMetadataUpdate applies metadata field update if provided
func (s *UserService) applyMetadataUpdate(req *UpdateUserRequest, updates *[]string, args *[]interface{}) {
	if req.Metadata == "" {
		return
	}

	*updates = append(*updates, "metadata = ?")
	*args = append(*args, req.Metadata)
}

// applySuspendedUpdate applies suspended_at field update if provided
func (s *UserService) applySuspendedUpdate(req *UpdateUserRequest, updates *[]string) {
	if req.Suspended == nil {
		return
	}

	if *req.Suspended {
		*updates = append(*updates, "suspended_at = NOW()")
	} else {
		*updates = append(*updates, "suspended_at = NULL")
	}
}

// GetByID retrieves a user by their ID
func (s *UserService) GetByID(ctx context.Context, id int) (*models.User, error) {
	const op = "UserService.GetByID"

	var user models.User
	err := s.db.GetContext(ctx, &user, "SELECT * FROM users WHERE id = ?", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return &user, nil
}

// SoftDelete performs a hard delete of a user account (users table doesn't support soft deletes)
// Checks that this is not the last admin user before deletion
func (s *UserService) SoftDelete(ctx context.Context, id int) error {
	const op = "UserService.SoftDelete"

	// Get the user to check their role
	user, err := s.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// If user is an admin, check that this is not the last admin
	if user.Role == models.RoleAdmin {
		adminCount, err := s.countActiveAdminsExcluding(ctx, id)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}

		if adminCount == 0 {
			return fmt.Errorf("%s: %w", op, ErrInvalidInput)
		}
	}

	// Delete user sessions first (ignore errors - session cleanup is non-critical)
	_, _ = s.db.ExecContext(ctx, "DELETE FROM user_sessions WHERE user_id = ?", id)

	// Delete user (hard delete as users table doesn't have deleted_at)
	result, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	return nil
}

// Suspend suspends a user account by setting suspended_at to current time
func (s *UserService) Suspend(ctx context.Context, id int) error {
	const op = "UserService.Suspend"

	// Check if user exists
	_, err := s.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Suspend user
	result, err := s.db.ExecContext(ctx, "UPDATE users SET suspended_at = NOW() WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	return nil
}

// Unsuspend restores a suspended user account by clearing suspended_at
func (s *UserService) Unsuspend(ctx context.Context, id int) error {
	const op = "UserService.Unsuspend"

	// Check if user exists
	_, err := s.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Unsuspend user
	result, err := s.db.ExecContext(ctx, "UPDATE users SET suspended_at = NULL WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	return nil
}

// checkUsernameUnique checks if a username is unique
func (s *UserService) checkUsernameUnique(ctx context.Context, username string, excludeID *int) error {
	const op = "UserService.checkUsernameUnique"

	var count int
	query := "SELECT COUNT(*) FROM users WHERE username = ?"
	args := []interface{}{username}

	if excludeID != nil {
		query += " AND id != ?"
		args = append(args, *excludeID)
	}

	err := s.db.GetContext(ctx, &count, query, args...)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	if count > 0 {
		return fmt.Errorf("%s: %w: username '%s'", op, ErrDuplicate, username)
	}

	return nil
}

// checkEmailUnique checks if an email is unique
func (s *UserService) checkEmailUnique(ctx context.Context, email string, excludeID *int) error {
	const op = "UserService.checkEmailUnique"

	var count int
	query := "SELECT COUNT(*) FROM users WHERE email = ?"
	args := []interface{}{email}

	if excludeID != nil {
		query += " AND id != ?"
		args = append(args, *excludeID)
	}

	err := s.db.GetContext(ctx, &count, query, args...)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	if count > 0 {
		return fmt.Errorf("%s: %w: email '%s'", op, ErrDuplicate, email)
	}

	return nil
}

// countActiveAdminsExcluding counts active admin users excluding the given ID
func (s *UserService) countActiveAdminsExcluding(ctx context.Context, excludeID int) (int, error) {
	const op = "UserService.countActiveAdminsExcluding"

	var count int
	err := s.db.GetContext(ctx, &count,
		"SELECT COUNT(*) FROM users WHERE role = ? AND suspended_at IS NULL AND id != ?",
		models.RoleAdmin, excludeID,
	)
	if err != nil {
		return 0, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return count, nil
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

// joinStrings joins strings with a separator (helper for building SQL queries)
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
