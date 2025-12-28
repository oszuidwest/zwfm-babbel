// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"errors"

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

// WithTx returns a new repository instance using the given transaction.
func (r *GormRepository[T]) WithTx(tx *gorm.DB) *GormRepository[T] {
	return &GormRepository[T]{db: tx}
}

// GetByID retrieves a record by its primary key.
func (r *GormRepository[T]) GetByID(ctx context.Context, id int64) (*T, error) {
	var result T
	err := r.db.WithContext(ctx).First(&result, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// Exists checks if a record with the given ID exists.
func (r *GormRepository[T]) Exists(ctx context.Context, id int64) (bool, error) {
	var count int64
	var model T
	err := r.db.WithContext(ctx).Model(&model).Where("id = ?", id).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Create inserts a new record into the database.
func (r *GormRepository[T]) Create(ctx context.Context, entity *T) error {
	return r.db.WithContext(ctx).Create(entity).Error
}

// Save updates an existing record or creates it if it doesn't exist.
func (r *GormRepository[T]) Save(ctx context.Context, entity *T) error {
	return r.db.WithContext(ctx).Save(entity).Error
}

// Delete removes a record by its primary key.
// For models with gorm.DeletedAt, this performs a soft delete.
func (r *GormRepository[T]) Delete(ctx context.Context, id int64) error {
	var model T
	result := r.db.WithContext(ctx).Delete(&model, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// HardDelete permanently removes a record, bypassing soft delete.
func (r *GormRepository[T]) HardDelete(ctx context.Context, id int64) error {
	var model T
	result := r.db.WithContext(ctx).Unscoped().Delete(&model, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// FindAll retrieves all records of type T.
func (r *GormRepository[T]) FindAll(ctx context.Context) ([]T, error) {
	var results []T
	err := r.db.WithContext(ctx).Find(&results).Error
	return results, err
}

// Count returns the total number of records.
func (r *GormRepository[T]) Count(ctx context.Context) (int64, error) {
	var count int64
	var model T
	err := r.db.WithContext(ctx).Model(&model).Count(&count).Error
	return count, err
}

// IsDuplicateKeyError checks if the error is a duplicate key constraint violation.
func IsDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	// MySQL error code 1062 is for duplicate entry
	return errors.Is(err, ErrDuplicateKey) ||
		(err != nil && (contains(err.Error(), "Duplicate entry") || contains(err.Error(), "1062")))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
