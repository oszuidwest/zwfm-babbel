// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// UserUpdate contains optional fields for updating a user.
// Use pointers for optional updates: nil = skip, non-nil = set value.
// Use Clear* flags to explicitly set a field to NULL.
type UserUpdate struct {
	// Regular fields (nil = skip, non-nil = set value)
	Username            *string    `db:"username"`
	FullName            *string    `db:"full_name"`
	Email               *string    `db:"email"`
	PasswordHash        *string    `db:"password_hash"`
	Role                *string    `db:"role"`
	LastLoginAt         *time.Time `db:"last_login_at"`
	LoginCount          *int       `db:"login_count"`
	FailedLoginAttempts *int       `db:"failed_login_attempts"`
	LockedUntil         *time.Time `db:"locked_until"`
	PasswordChangedAt   *time.Time `db:"password_changed_at"`
	Metadata            *string    `db:"metadata"`

	// Explicit NULL setting flags (takes precedence over pointer values)
	ClearEmail       bool
	ClearLockedUntil bool
	ClearMetadata    bool
}

// buildUserUpdateMap converts UserUpdate to a map for GORM's Updates method.
// Handles both regular pointer fields and explicit NULL clearing flags.
func buildUserUpdateMap(u *UserUpdate) map[string]any {
	if u == nil {
		return nil
	}

	m := make(map[string]any)

	// Handle regular pointer fields
	if u.Username != nil {
		m["username"] = *u.Username
	}
	if u.FullName != nil {
		m["full_name"] = *u.FullName
	}
	if u.PasswordHash != nil {
		m["password_hash"] = *u.PasswordHash
	}
	if u.Role != nil {
		m["role"] = *u.Role
	}
	if u.LastLoginAt != nil {
		m["last_login_at"] = *u.LastLoginAt
	}
	if u.LoginCount != nil {
		m["login_count"] = *u.LoginCount
	}
	if u.FailedLoginAttempts != nil {
		m["failed_login_attempts"] = *u.FailedLoginAttempts
	}
	if u.PasswordChangedAt != nil {
		m["password_changed_at"] = *u.PasswordChangedAt
	}

	// Handle nullable fields with Clear* flags (NULL takes precedence)
	if u.ClearEmail {
		m["email"] = nil
	} else if u.Email != nil {
		m["email"] = *u.Email
	}

	if u.ClearLockedUntil {
		m["locked_until"] = nil
	} else if u.LockedUntil != nil {
		m["locked_until"] = *u.LockedUntil
	}

	if u.ClearMetadata {
		m["metadata"] = nil
	} else if u.Metadata != nil {
		m["metadata"] = *u.Metadata
	}

	return m
}

// UserRepository defines the interface for user data access.
type UserRepository interface {
	// CRUD operations
	Create(ctx context.Context, username, fullName string, email *string, passwordHash, role string) (*models.User, error)
	GetByID(ctx context.Context, id int64) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	Update(ctx context.Context, id int64, updates *UserUpdate) error
	Delete(ctx context.Context, id int64) error

	// Query operations
	List(ctx context.Context, query *ListQuery) (*ListResult[models.User], error)
	Exists(ctx context.Context, id int64) (bool, error)
	IsUsernameTaken(ctx context.Context, username string, excludeID *int64) (bool, error)
	IsEmailTaken(ctx context.Context, email string, excludeID *int64) (bool, error)
	CountActiveAdminsExcluding(ctx context.Context, excludeID int64) (int, error)

	// User-specific operations
	SetSuspended(ctx context.Context, id int64, suspended bool) error
	DeleteSessions(ctx context.Context, userID int64) error
}

// userRepository implements UserRepository using GORM.
type userRepository struct {
	*GormRepository[models.User]
}

// NewUserRepository creates a new user repository.
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{
		GormRepository: NewGormRepository[models.User](db),
	}
}

// Create inserts a new user and returns the created record.
func (r *userRepository) Create(ctx context.Context, username, fullName string, email *string, passwordHash, role string) (*models.User, error) {
	user := &models.User{
		Username:     username,
		FullName:     fullName,
		Email:        email,
		PasswordHash: passwordHash,
		Role:         models.UserRole(role),
	}

	err := r.db.WithContext(ctx).Create(user).Error
	if err != nil {
		return nil, ParseDBError(err)
	}

	return user, nil
}

// GetByUsername retrieves a user by username.
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, ParseDBError(err)
	}

	return &user, nil
}

// Update updates a user with the provided field values.
func (r *userRepository) Update(ctx context.Context, id int64, u *UserUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := buildUserUpdateMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	result := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", id).Updates(updateMap)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// IsUsernameTaken checks if username is in use.
func (r *userRepository) IsUsernameTaken(ctx context.Context, username string, excludeID *int64) (bool, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(&models.User{}).Where("username = ?", username)

	if excludeID != nil {
		query = query.Where("id != ?", *excludeID)
	}

	err := query.Count(&count).Error
	if err != nil {
		return false, ParseDBError(err)
	}

	return count > 0, nil
}

// IsEmailTaken checks if email is in use.
func (r *userRepository) IsEmailTaken(ctx context.Context, email string, excludeID *int64) (bool, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(&models.User{}).Where("email = ?", email)

	if excludeID != nil {
		query = query.Where("id != ?", *excludeID)
	}

	err := query.Count(&count).Error
	if err != nil {
		return false, ParseDBError(err)
	}

	return count > 0, nil
}

// CountActiveAdminsExcluding counts non-suspended admins excluding the given ID.
func (r *userRepository) CountActiveAdminsExcluding(ctx context.Context, excludeID int64) (int, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("suspended_at IS NULL").
		Where("role = ?", models.RoleAdmin).
		Where("id != ?", excludeID).
		Count(&count).Error
	if err != nil {
		return 0, ParseDBError(err)
	}

	return int(count), nil
}

// SetSuspended updates the user's suspended status.
func (r *userRepository) SetSuspended(ctx context.Context, id int64, suspended bool) error {
	var updateMap map[string]any
	if suspended {
		updateMap = map[string]any{"suspended_at": time.Now()}
	} else {
		updateMap = map[string]any{"suspended_at": nil}
	}

	result := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", id).Updates(updateMap)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// DeleteSessions removes all sessions for a user.
func (r *userRepository) DeleteSessions(ctx context.Context, userID int64) error {
	// user_sessions is not a GORM model, so we use raw SQL
	err := r.db.WithContext(ctx).Exec("DELETE FROM user_sessions WHERE user_id = ?", userID).Error
	return ParseDBError(err)
}

// userFieldMapping maps API field names to database columns for users.
var userFieldMapping = FieldMapping{
	"id":         "id",
	"username":   "username",
	"full_name":  "full_name",
	"email":      "email",
	"role":       "role",
	"created_at": "created_at",
	"updated_at": "updated_at",
}

// userSearchFields defines which fields are searchable for users.
var userSearchFields = []string{"username", "full_name"}

// List retrieves a paginated list of users with filtering, sorting, and search support.
func (r *userRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.User], error) {
	if query == nil {
		query = NewListQuery()
	}

	db := r.db.WithContext(ctx).Model(&models.User{})

	// Apply soft delete filter based on status
	switch query.Status {
	case "deleted":
		db = db.Unscoped().Where("deleted_at IS NOT NULL")
	case "all":
		db = db.Unscoped()
		// default "active" uses GORM's automatic soft delete filtering
	}

	result, err := ApplyListQuery[models.User](db, query, userFieldMapping, userSearchFields, "username ASC")
	if err != nil {
		return nil, ParseDBError(err)
	}

	return result, nil
}
