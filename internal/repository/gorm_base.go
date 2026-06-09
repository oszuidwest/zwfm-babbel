package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// GormRepository provides shared primary-key operations for model repositories.
type GormRepository[T any] struct {
	db *gorm.DB
}

// NewGormRepository returns a generic repository backed by db.
func NewGormRepository[T any](db *gorm.DB) *GormRepository[T] {
	return &GormRepository[T]{db: db}
}

// GetByID retrieves a record by its primary key.
func (r *GormRepository[T]) GetByID(ctx context.Context, id int64) (*T, error) {
	var result T
	db := DBFromContext(ctx, r.db)
	err := db.WithContext(ctx).First(&result, id).Error
	if err != nil {
		return nil, ParseDBError(err)
	}
	return &result, nil
}

// Exists reports whether a record with the given ID exists.
func (r *GormRepository[T]) Exists(ctx context.Context, id int64) (bool, error) {
	var count int64
	var model T
	db := DBFromContext(ctx, r.db)
	err := db.WithContext(ctx).Model(&model).Where("id = ?", id).Count(&count).Error
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

// IsFieldValueTaken reports whether a field value is already in use.
// If excludeID is provided, that record is excluded from the check.
func (r *GormRepository[T]) IsFieldValueTaken(ctx context.Context, field, value string, excludeID *int64) (bool, error) {
	var count int64
	var model T
	db := DBFromContext(ctx, r.db)
	query := db.WithContext(ctx).Model(&model).Where(field+" = ?", value)
	if excludeID != nil {
		query = query.Where("id != ?", *excludeID)
	}
	if err := query.Count(&count).Error; err != nil {
		return false, ParseDBError(err)
	}
	return count > 0, nil
}

// ApplySoftDeleteFilter applies soft delete filtering to a query based on the trashed parameter.
// - "" (default): only non-deleted records (GORM default behavior)
// - "only": only soft-deleted records
// - "with": include all records regardless of deletion status.
func ApplySoftDeleteFilter(db *gorm.DB, trashed string) *gorm.DB {
	switch trashed {
	case "only":
		return db.Unscoped().Where("deleted_at IS NOT NULL")
	case "with":
		return db.Unscoped()
	default:
		return db // empty - use GORM's default soft delete filtering
	}
}

// UpdateByID updates a record by its primary key with the provided updates.
// The updates parameter can be a struct or map[string]any.
func (r *GormRepository[T]) UpdateByID(ctx context.Context, id int64, updates any) error {
	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).Model(new(T)).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// GetByIDWithPreload loads a record and preloads the named GORM relations.
func (r *GormRepository[T]) GetByIDWithPreload(ctx context.Context, id int64, preloads ...string) (*T, error) {
	var result T
	db := DBFromContext(ctx, r.db)
	query := db.WithContext(ctx)
	for _, p := range preloads {
		query = query.Preload(p)
	}
	if err := query.First(&result, id).Error; err != nil {
		return nil, ParseDBError(err)
	}
	return &result, nil
}

// GetByIDWithJoins loads a record and joins the named GORM relations.
func (r *GormRepository[T]) GetByIDWithJoins(ctx context.Context, id int64, joins ...string) (*T, error) {
	var result T
	db := DBFromContext(ctx, r.db)
	query := db.WithContext(ctx)
	for _, j := range joins {
		query = query.Joins(j)
	}
	if err := query.First(&result, id).Error; err != nil {
		return nil, ParseDBError(err)
	}
	return &result, nil
}

// HasRelatedRecords reports whether a record has related records in the specified tables.
// The tables map specifies table names to their foreign key columns referencing this record.
func (r *GormRepository[T]) HasRelatedRecords(ctx context.Context, id int64, tables map[string]string) (bool, error) {
	if len(tables) == 0 {
		return false, nil
	}

	db := DBFromContext(ctx, r.db)

	// Build a UNION query that checks each table for a matching foreign key and
	// stops after the first match.
	var parts []string
	var args []any
	for table, fk := range tables {
		parts = append(parts, fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ?", table, fk))
		args = append(args, id)
	}

	query := strings.Join(parts, " UNION ") + " LIMIT 1"

	var exists int
	err := db.WithContext(ctx).Raw(query, args...).Scan(&exists).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, ParseDBError(err)
	}

	return exists == 1, nil
}
