// Package repository provides data access abstractions.
package repository

import (
	"strings"

	"gorm.io/gorm"
)

// SearchScope returns a GORM scope that applies search across multiple fields.
// Uses OR conditions for multi-field search with LIKE pattern matching.
func SearchScope(searchFields []string, searchTerm string) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if searchTerm == "" || len(searchFields) == 0 {
			return db
		}
		pattern := "%" + searchTerm + "%"
		conditions := make([]string, len(searchFields))
		args := make([]any, len(searchFields))
		for i, field := range searchFields {
			conditions[i] = field + " LIKE ?"
			args[i] = pattern
		}
		return db.Where(strings.Join(conditions, " OR "), args...)
	}
}

// SortScope returns a GORM scope that applies sorting based on SortFields.
// Uses fieldMapping to validate and map field names for SQL injection prevention.
func SortScope(sorts []SortField, fieldMapping FieldMapping, defaultSort string) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if len(sorts) > 0 {
			for _, sf := range sorts {
				dbField, ok := fieldMapping[sf.Field]
				if !ok {
					continue
				}
				direction := "ASC"
				if sf.Direction == SortDesc {
					direction = "DESC"
				}
				db = db.Order(dbField + " " + direction)
			}
		} else if defaultSort != "" {
			db = db.Order(defaultSort)
		}
		return db
	}
}

// PaginationScope returns a GORM scope that applies limit and offset.
func PaginationScope(limit, offset int) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if limit > 0 {
			db = db.Limit(limit)
		}
		if offset > 0 {
			db = db.Offset(offset)
		}
		return db
	}
}
