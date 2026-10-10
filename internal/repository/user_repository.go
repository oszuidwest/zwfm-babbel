package repository

import (
	"context"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// UserUpdate contains optional fields for updating a user.
// Nil pointers leave fields unchanged; Clear* flags override pointers with NULL.
type UserUpdate struct {
	Username            *string
	FullName            *string
	Email               *string
	PasswordHash        *string
	Role                *string
	FailedLoginAttempts *int
	// LockedUntil lets BuildUpdateMap resolve ClearLockedUntil to locked_until.
	LockedUntil       *time.Time
	PasswordChangedAt *time.Time
	SuspendedAt       *time.Time
	Metadata          *datatypes.JSONMap

	ClearEmail       bool
	ClearLockedUntil bool
	ClearSuspendedAt bool
}

// CreateUserParams holds the parameters for creating a new user.
type CreateUserParams struct {
	Username     string
	FullName     string
	Email        *string
	PasswordHash string
	Role         string
	Metadata     *datatypes.JSONMap
}

// UserRepository provides user data access using GORM.
type UserRepository struct {
	*GormRepository[models.User]
}

// NewUserRepository creates a new user repository.
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{
		GormRepository: NewGormRepository[models.User](db),
	}
}

// Create inserts a new user and returns the created record.
func (r *UserRepository) Create(ctx context.Context, params CreateUserParams) (*models.User, error) {
	user := &models.User{
		Username:     params.Username,
		FullName:     params.FullName,
		Email:        params.Email,
		PasswordHash: params.PasswordHash,
		Role:         models.UserRole(params.Role),
		Metadata:     params.Metadata,
	}

	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, ParseDBError(err)
	}

	return user, nil
}

// Update updates a user. Nil pointer fields are skipped; Clear* flags set fields to NULL.
func (r *UserRepository) Update(ctx context.Context, id int64, u *UserUpdate) error {
	return updateFields(ctx, id, u, r.UpdateByID)
}

// IsUsernameTaken reports whether the username is already in use.
func (r *UserRepository) IsUsernameTaken(ctx context.Context, username string, excludeID *int64) (bool, error) {
	return r.IsFieldValueTaken(ctx, "username", username, excludeID)
}

// IsEmailTaken reports whether the email is already in use.
func (r *UserRepository) IsEmailTaken(ctx context.Context, email string, excludeID *int64) (bool, error) {
	return r.IsFieldValueTaken(ctx, "email", email, excludeID)
}

// CountActiveAdminsExcluding counts non-suspended admins excluding the given ID.
func (r *UserRepository) CountActiveAdminsExcluding(ctx context.Context, excludeID int64) (int, error) {
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

// DeleteSessions removes all sessions for a user.
func (r *UserRepository) DeleteSessions(ctx context.Context, userID int64) error {
	// user_sessions is not a GORM model, so use raw SQL.
	err := r.db.WithContext(ctx).Exec("DELETE FROM user_sessions WHERE user_id = ?", userID).Error
	return ParseDBError(err)
}

var userFieldMapping = FieldMapping{
	"id":         {Column: "id", Type: filterInteger},
	"username":   {Column: "username", Type: filterString},
	"full_name":  {Column: "full_name", Type: filterString},
	"email":      {Column: "email", Type: filterString, Nullable: true},
	"role":       {Column: "role", Type: filterEnum, Enum: []string{string(models.RoleAdmin), string(models.RoleEditor), string(models.RoleViewer)}},
	"created_at": {Column: "created_at", Type: filterDateTime},
	"updated_at": {Column: "updated_at", Type: filterDateTime},
}

var userSearchFields = []string{"username", "full_name"}

// List retrieves a paginated list of users with filtering, sorting, and search support.
func (r *UserRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.User], error) {
	db := r.db.WithContext(ctx).Model(&models.User{})
	db = ApplySoftDeleteFilter(db, query.Trashed)

	defaultSort := []SortField{{Field: "username", Direction: SortAsc}}
	return ApplyListQuery[models.User](db, query, userFieldMapping, userSearchFields, defaultSort)
}
