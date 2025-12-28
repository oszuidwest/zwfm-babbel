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
		return false, err
	}
	return count > 0, nil
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
