// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"

	"gorm.io/gorm"
)

// GormRepository provides common GORM operations for any model type.
type GormRepository[T any] struct {
	db *gorm.DB
}

// NewGormRepository creates a new GORM repository instance.
func NewGormRepository[T any](db *gorm.DB) *GormRepository[T] {
	return &GormRepository[T]{db: db}
}

// DB returns the underlying GORM database connection.
func (r *GormRepository[T]) DB() *gorm.DB {
	return r.db
}

// GetByID retrieves a record by its primary key.
func (r *GormRepository[T]) GetByID(ctx context.Context, id int64) (*T, error) {
	var result T
	err := r.db.WithContext(ctx).First(&result, id).Error
	if err != nil {
		return nil, ParseDBError(err)
	}
	return &result, nil
}

// Exists checks if a record with the given ID exists.
func (r *GormRepository[T]) Exists(ctx context.Context, id int64) (bool, error) {
	var count int64
	var model T
	err := r.db.WithContext(ctx).Model(&model).Where("id = ?", id).Count(&count).Error
	if err != nil {
		return false, ParseDBError(err)
	}
	return count > 0, nil
}

// Delete removes a record by its primary key.
// For models with gorm.DeletedAt, this performs a soft delete.
func (r *GormRepository[T]) Delete(ctx context.Context, id int64) error {
	var model T
	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).Delete(&model, id)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// IsFieldValueTaken checks if a field value is already in use by another record.
// Useful for unique constraints validation before insert/update.
func (r *GormRepository[T]) IsFieldValueTaken(ctx context.Context, field, value string, excludeID *int64) (bool, error) {
	var count int64
	var model T
	query := r.db.WithContext(ctx).Model(&model).Where(field+" = ?", value)
	if excludeID != nil {
		query = query.Where("id != ?", *excludeID)
	}
	if err := query.Count(&count).Error; err != nil {
		return false, ParseDBError(err)
	}
	return count > 0, nil
}

// ApplySoftDeleteFilter applies soft delete filtering to a query based on status.
// - "active" (default): only non-deleted records (GORM default behavior)
// - "deleted": only soft-deleted records
// - "all": include all records regardless of deletion status
func ApplySoftDeleteFilter(db *gorm.DB, status string) *gorm.DB {
	switch status {
	case "deleted":
		return db.Unscoped().Where("deleted_at IS NOT NULL")
	case "all":
		return db.Unscoped()
	default:
		return db // "active" - use GORM's default soft delete filtering
	}
}
