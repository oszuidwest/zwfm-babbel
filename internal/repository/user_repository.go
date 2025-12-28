// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// UserUpdate contains optional fields for updating a user.
// Nil pointer fields are not updated.
// For nullable fields (double pointers), outer nil = don't update,
// inner nil = set to NULL, inner value = set to that value.
type UserUpdate struct {
	Username            *string
	FullName            *string
	Email               **string    // Nullable: outer nil = skip, inner nil = set NULL
	PasswordHash        *string
	Role                *string
	SuspendedAt         **time.Time // Nullable: outer nil = skip, inner nil = set NULL
	DeletedAt           **time.Time // Nullable: outer nil = skip, inner nil = set NULL
	LastLoginAt         **time.Time // Nullable: outer nil = skip, inner nil = set NULL
	LoginCount          *int
	FailedLoginAttempts *int
	LockedUntil         **time.Time // Nullable: outer nil = skip, inner nil = set NULL
	PasswordChangedAt   **time.Time // Nullable: outer nil = skip, inner nil = set NULL
	Metadata            **string    // Nullable: outer nil = skip, inner nil = set NULL
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
		return nil, parseGormError(err)
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
		return nil, parseGormError(err)
	}

	return &user, nil
}

// Update updates a user with the provided field values.
func (r *userRepository) Update(ctx context.Context, id int64, updates *UserUpdate) error {
	if updates == nil {
		return nil
	}

	// Build update map from struct fields
	updateMap := make(map[string]any)

	// Non-nullable string fields
	if updates.Username != nil {
		updateMap["username"] = *updates.Username
	}
	if updates.FullName != nil {
		updateMap["full_name"] = *updates.FullName
	}
	if updates.PasswordHash != nil {
		updateMap["password_hash"] = *updates.PasswordHash
	}
	if updates.Role != nil {
		updateMap["role"] = *updates.Role
	}

	// Non-nullable int fields
	if updates.LoginCount != nil {
		updateMap["login_count"] = *updates.LoginCount
	}
	if updates.FailedLoginAttempts != nil {
		updateMap["failed_login_attempts"] = *updates.FailedLoginAttempts
	}

	// Nullable string fields (double pointer)
	if updates.Email != nil {
		if *updates.Email == nil {
			updateMap["email"] = nil
		} else {
			updateMap["email"] = **updates.Email
		}
	}
	if updates.Metadata != nil {
		if *updates.Metadata == nil {
			updateMap["metadata"] = nil
		} else {
			updateMap["metadata"] = **updates.Metadata
		}
	}

	// Nullable time fields (double pointer)
	if updates.SuspendedAt != nil {
		if *updates.SuspendedAt == nil {
			updateMap["suspended_at"] = nil
		} else {
			updateMap["suspended_at"] = **updates.SuspendedAt
		}
	}
	if updates.DeletedAt != nil {
		if *updates.DeletedAt == nil {
			updateMap["deleted_at"] = nil
		} else {
			updateMap["deleted_at"] = **updates.DeletedAt
		}
	}
	if updates.LastLoginAt != nil {
		if *updates.LastLoginAt == nil {
			updateMap["last_login_at"] = nil
		} else {
			updateMap["last_login_at"] = **updates.LastLoginAt
		}
	}
	if updates.LockedUntil != nil {
		if *updates.LockedUntil == nil {
			updateMap["locked_until"] = nil
		} else {
			updateMap["locked_until"] = **updates.LockedUntil
		}
	}
	if updates.PasswordChangedAt != nil {
		if *updates.PasswordChangedAt == nil {
			updateMap["password_changed_at"] = nil
		} else {
			updateMap["password_changed_at"] = **updates.PasswordChangedAt
		}
	}

	// Nothing to update
	if len(updateMap) == 0 {
		return nil
	}

	result := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", id).Updates(updateMap)
	if result.Error != nil {
		return parseGormError(result.Error)
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
		return false, parseGormError(err)
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
		return false, parseGormError(err)
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
		return 0, parseGormError(err)
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
		return parseGormError(result.Error)
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
	return parseGormError(err)
}

// parseGormError converts GORM/MySQL errors to repository errors.
func parseGormError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	// Use the existing ParseDBError for MySQL-specific errors
	return ParseDBError(err)
}
