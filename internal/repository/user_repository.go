// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
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
var userFieldMapping = map[string]string{
	"id":         "id",
	"username":   "username",
	"full_name":  "full_name",
	"email":      "email",
	"role":       "role",
	"created_at": "created_at",
	"updated_at": "updated_at",
}

// List retrieves a paginated list of users with filtering, sorting, and search support.
func (r *userRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.User], error) {
	if query == nil {
		query = NewListQuery()
	}

	db := r.db.WithContext(ctx).Model(&models.User{})

	// Apply soft delete filter based on status
	// Users have gorm.DeletedAt so GORM handles soft delete automatically
	switch query.Status {
	case "deleted":
		db = db.Unscoped().Where("deleted_at IS NOT NULL")
	case "all":
		db = db.Unscoped()
	default:
		// "active" is default - GORM automatically excludes soft-deleted records
	}

	// Apply search
	if query.Search != "" {
		searchPattern := "%" + query.Search + "%"
		db = db.Where("username LIKE ? OR full_name LIKE ?", searchPattern, searchPattern)
	}

	// Apply filters
	for _, filter := range query.Filters {
		dbField, ok := userFieldMapping[filter.Field]
		if !ok {
			continue
		}

		switch filter.Operator {
		case FilterEquals:
			db = db.Where(dbField+" = ?", filter.Value)
		case FilterNotEquals:
			db = db.Where(dbField+" != ?", filter.Value)
		case FilterGreaterThan:
			db = db.Where(dbField+" > ?", filter.Value)
		case FilterGreaterOrEq:
			db = db.Where(dbField+" >= ?", filter.Value)
		case FilterLessThan:
			db = db.Where(dbField+" < ?", filter.Value)
		case FilterLessOrEq:
			db = db.Where(dbField+" <= ?", filter.Value)
		case FilterLike:
			db = db.Where(dbField+" LIKE ?", filter.Value)
		case FilterIn:
			db = db.Where(dbField+" IN ?", filter.Value)
		}
	}

	// Count total before pagination
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, ParseDBError(err)
	}

	// Apply sorting
	if len(query.Sort) > 0 {
		for _, sf := range query.Sort {
			dbField, ok := userFieldMapping[sf.Field]
			if !ok {
				continue
			}
			direction := "ASC"
			if sf.Direction == SortDesc {
				direction = "DESC"
			}
			db = db.Order(dbField + " " + direction)
		}
	} else {
		db = db.Order("username ASC")
	}

	// Apply pagination
	db = db.Offset(query.Offset).Limit(query.Limit)

	// Execute query
	var users []models.User
	if err := db.Find(&users).Error; err != nil {
		return nil, ParseDBError(err)
	}

	return &ListResult[models.User]{
		Data:   users,
		Total:  total,
		Limit:  query.Limit,
		Offset: query.Offset,
	}, nil
}
