package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// UserRepository defines the interface for user data access.
type UserRepository interface {
	// CRUD operations
	Create(ctx context.Context, username, fullName string, email *string, passwordHash, role string) (*models.User, error)
	GetByID(ctx context.Context, id int) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	Update(ctx context.Context, id int, updates map[string]interface{}) error
	Delete(ctx context.Context, id int) error

	// Query operations
	Exists(ctx context.Context, id int) (bool, error)
	IsUsernameTaken(ctx context.Context, username string, excludeID *int) (bool, error)
	IsEmailTaken(ctx context.Context, email string, excludeID *int) (bool, error)
	CountActiveAdminsExcluding(ctx context.Context, excludeID int) (int, error)

	// User-specific operations
	SetSuspended(ctx context.Context, id int, suspended bool) error
	DeleteSessions(ctx context.Context, userID int) error

	// DB returns the underlying database for ModernListWithQuery
	DB() *sqlx.DB
}

// userRepository implements UserRepository.
type userRepository struct {
	*BaseRepository[models.User]
}

// NewUserRepository creates a new user repository.
func NewUserRepository(db *sqlx.DB) UserRepository {
	return &userRepository{
		BaseRepository: NewBaseRepository[models.User](db, "users"),
	}
}

// Create inserts a new user and returns the created record.
func (r *userRepository) Create(ctx context.Context, username, fullName string, email *string, passwordHash, role string) (*models.User, error) {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx,
		"INSERT INTO users (username, full_name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
		username, fullName, email, passwordHash, role,
	)
	if err != nil {
		return nil, ParseDBError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return r.GetByID(ctx, int(id))
}

// GetByUsername retrieves a user by username.
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	q := r.getQueryable(ctx)

	var user models.User
	err := q.GetContext(ctx, &user, "SELECT * FROM users WHERE username = ?", username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, ParseDBError(err)
	}

	return &user, nil
}

// Update updates a user with the provided field values.
func (r *userRepository) Update(ctx context.Context, id int, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}

	q := r.getQueryable(ctx)

	// Build dynamic query
	setClauses := make([]string, 0, len(updates))
	args := make([]interface{}, 0, len(updates)+1)

	for field, value := range updates {
		setClauses = append(setClauses, field+" = ?")
		args = append(args, value)
	}
	args = append(args, id)

	query := fmt.Sprintf("UPDATE users SET %s WHERE id = ?", strings.Join(setClauses, ", "))

	result, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return ParseDBError(err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// IsUsernameTaken checks if username is in use.
func (r *userRepository) IsUsernameTaken(ctx context.Context, username string, excludeID *int) (bool, error) {
	condition := "username = ?"
	args := []interface{}{username}

	if excludeID != nil {
		condition += " AND id != ?"
		args = append(args, *excludeID)
	}

	return r.ExistsBy(ctx, condition, args...)
}

// IsEmailTaken checks if email is in use.
func (r *userRepository) IsEmailTaken(ctx context.Context, email string, excludeID *int) (bool, error) {
	condition := "email = ?"
	args := []interface{}{email}

	if excludeID != nil {
		condition += " AND id != ?"
		args = append(args, *excludeID)
	}

	return r.ExistsBy(ctx, condition, args...)
}

// CountActiveAdminsExcluding counts non-suspended admins excluding the given ID.
func (r *userRepository) CountActiveAdminsExcluding(ctx context.Context, excludeID int) (int, error) {
	q := r.getQueryable(ctx)

	var count int
	err := q.GetContext(ctx, &count,
		"SELECT COUNT(*) FROM users WHERE role = ? AND suspended_at IS NULL AND id != ?",
		models.RoleAdmin, excludeID,
	)
	if err != nil {
		return 0, ParseDBError(err)
	}

	return count, nil
}

// SetSuspended updates the user's suspended status.
func (r *userRepository) SetSuspended(ctx context.Context, id int, suspended bool) error {
	q := r.getQueryable(ctx)

	var query string
	if suspended {
		query = "UPDATE users SET suspended_at = NOW() WHERE id = ?"
	} else {
		query = "UPDATE users SET suspended_at = NULL WHERE id = ?"
	}

	result, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return ParseDBError(err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// DeleteSessions removes all sessions for a user.
func (r *userRepository) DeleteSessions(ctx context.Context, userID int) error {
	q := r.getQueryable(ctx)

	_, err := q.ExecContext(ctx, "DELETE FROM user_sessions WHERE user_id = ?", userID)
	return ParseDBError(err)
}
