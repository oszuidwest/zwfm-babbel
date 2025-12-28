// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"time"

	"gorm.io/gorm"
)

// ActiveStories returns a scope for non-deleted, active stories within their date range.
func ActiveStories(db *gorm.DB) *gorm.DB {
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	return db.Where("deleted_at IS NULL").
		Where("status = ?", "active").
		Where("start_date <= ?", today).
		Where("end_date >= ?", today)
}

// ForWeekday returns a scope that filters by the specified weekday.
func ForWeekday(weekday time.Weekday) func(*gorm.DB) *gorm.DB {
	days := map[time.Weekday]string{
		time.Monday:    "monday",
		time.Tuesday:   "tuesday",
		time.Wednesday: "wednesday",
		time.Thursday:  "thursday",
		time.Friday:    "friday",
		time.Saturday:  "saturday",
		time.Sunday:    "sunday",
	}
	return func(db *gorm.DB) *gorm.DB {
		if col, ok := days[weekday]; ok {
			return db.Where(col+" = ?", true)
		}
		return db
	}
}

// WithPagination returns a scope that applies offset and limit for pagination.
func WithPagination(page, pageSize int) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if page < 1 {
			page = 1
		}
		if pageSize < 1 {
			pageSize = 10
		}
		offset := (page - 1) * pageSize
		return db.Offset(offset).Limit(pageSize)
	}
}

// NotSuspended returns a scope that excludes suspended users.
func NotSuspended(db *gorm.DB) *gorm.DB {
	return db.Where("suspended_at IS NULL")
}

// NotDeleted returns a scope that excludes soft-deleted records.
// Use this for models that don't use gorm.DeletedAt but have a deleted_at column.
func NotDeleted(db *gorm.DB) *gorm.DB {
	return db.Where("deleted_at IS NULL")
}

// WithPreload returns a scope that preloads the specified associations.
func WithPreload(associations ...string) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		for _, assoc := range associations {
			db = db.Preload(assoc)
		}
		return db
	}
}

// OrderByCreatedDesc returns a scope that orders by created_at descending.
func OrderByCreatedDesc(db *gorm.DB) *gorm.DB {
	return db.Order("created_at DESC")
}

// OrderByCreatedAsc returns a scope that orders by created_at ascending.
func OrderByCreatedAsc(db *gorm.DB) *gorm.DB {
	return db.Order("created_at ASC")
}

// OrderByName returns a scope that orders by name ascending.
func OrderByName(db *gorm.DB) *gorm.DB {
	return db.Order("name ASC")
}

// ByStationID returns a scope that filters by station_id.
func ByStationID(stationID int64) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("station_id = ?", stationID)
	}
}

// ByVoiceID returns a scope that filters by voice_id.
func ByVoiceID(voiceID int64) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("voice_id = ?", voiceID)
	}
}

// WithSearch returns a scope that searches across multiple fields.
func WithSearch(search string, fields ...string) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if search == "" || len(fields) == 0 {
			return db
		}
		query := db
		for i, field := range fields {
			if i == 0 {
				query = query.Where(field+" LIKE ?", "%"+search+"%")
			} else {
				query = query.Or(field+" LIKE ?", "%"+search+"%")
			}
		}
		return query
	}
}
