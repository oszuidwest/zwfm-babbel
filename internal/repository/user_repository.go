// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository/updates"
	"gorm.io/gorm"
)

// UserUpdate contains optional fields for updating a user.
// Use regular pointers (*T) for non-nullable fields (nil = skip update).
// Use updates.Nullable[T] for nullable fields (skip, set value, or set NULL).
type UserUpdate struct {
	Username            *string                     `db:"username"`
	FullName            *string                     `db:"full_name"`
	Email               updates.Nullable[string]    `db:"email"`
	PasswordHash        *string                     `db:"password_hash"`
	Role                *string                     `db:"role"`
	SuspendedAt         updates.Nullable[time.Time] `db:"suspended_at"`
	DeletedAt           updates.Nullable[time.Time] `db:"deleted_at"`
	LastLoginAt         updates.Nullable[time.Time] `db:"last_login_at"`
	LoginCount          *int                        `db:"login_count"`
	FailedLoginAttempts *int                        `db:"failed_login_attempts"`
	LockedUntil         updates.Nullable[time.Time] `db:"locked_until"`
	PasswordChangedAt   updates.Nullable[time.Time] `db:"password_changed_at"`
	Metadata            updates.Nullable[string]    `db:"metadata"`
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
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
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

	updateMap := updates.ToMap(u)
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
		Scopes(NotSuspended).
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
