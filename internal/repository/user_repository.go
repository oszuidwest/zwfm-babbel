// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// UserUpdate contains optional fields for updating a user.
// Use pointers for optional updates: nil = skip, non-nil = set value.
// Use Clear* flags to explicitly set a field to NULL.
type UserUpdate struct {
	// Regular fields (nil = skip, non-nil = set value)
	Username            *string
	FullName            *string
	Email               *string
	PasswordHash        *string
	Role                *string
	LastLoginAt         *time.Time
	LoginCount          *int
	FailedLoginAttempts *int
	LockedUntil         *time.Time
	PasswordChangedAt   *time.Time
	Metadata            *datatypes.JSONMap

	// Explicit NULL setting flags (takes precedence over pointer values)
	ClearEmail       bool
	ClearLockedUntil bool
	ClearMetadata    bool
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

	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, ParseDBError(err)
	}

	return user, nil
}

// GetByUsername retrieves a user by username.
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	db := DBFromContext(ctx, r.db)
	err := db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, ParseDBError(err)
	}

	return &user, nil
}

// Update updates a user. Nil pointer fields are skipped; Clear* flags set fields to NULL.
func (r *userRepository) Update(ctx context.Context, id int64, u *UserUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := BuildUpdateMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	return r.UpdateByID(ctx, id, updateMap)
}

// IsUsernameTaken reports whether the username is already in use.
func (r *userRepository) IsUsernameTaken(ctx context.Context, username string, excludeID *int64) (bool, error) {
	return r.IsFieldValueTaken(ctx, "username", username, excludeID)
}

// IsEmailTaken reports whether the email is already in use.
func (r *userRepository) IsEmailTaken(ctx context.Context, email string, excludeID *int64) (bool, error) {
	return r.IsFieldValueTaken(ctx, "email", email, excludeID)
}

// CountActiveAdminsExcluding counts non-suspended admins excluding the given ID.
func (r *userRepository) CountActiveAdminsExcluding(ctx context.Context, excludeID int64) (int, error) {
	var count int64
	db := DBFromContext(ctx, r.db)
	err := db.WithContext(ctx).
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

	return r.UpdateByID(ctx, id, updateMap)
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

	// Build base query with soft delete filtering
	db := r.db.WithContext(ctx).Model(&models.User{})
	db = ApplySoftDeleteFilter(db, query.Status)

	result, err := ApplyListQuery[models.User](db, query, userFieldMapping, userSearchFields, "username ASC")
	if err != nil {
		return nil, ParseDBError(err)
	}

	return result, nil
}
