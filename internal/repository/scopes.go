// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"gorm.io/gorm"
)

// NotSuspended returns a scope that excludes suspended users.
func NotSuspended(db *gorm.DB) *gorm.DB {
	return db.Where("suspended_at IS NULL")
}

// OrderByCreatedDesc returns a scope that orders by created_at descending.
func OrderByCreatedDesc(db *gorm.DB) *gorm.DB {
	return db.Order("created_at DESC")
}

// ByStationID returns a scope that filters by station_id.
func ByStationID(stationID int64) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("station_id = ?", stationID)
	}
}
