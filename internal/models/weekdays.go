// Package models defines the data models for the Babbel API.
package models

import (
	"encoding/json"
	"fmt"
	"time"
)

// Weekdays represents a bitmask for scheduling stories on specific days of the week.
// The bitmask uses Go's time.Weekday values where Sunday=0, Monday=1, etc.
// Each day is represented by 2^weekday: Sunday=1, Monday=2, Tuesday=4, Wednesday=8,
// Thursday=16, Friday=32, Saturday=64.
//
// Common values:
//   - 127 = All days (1+2+4+8+16+32+64)
//   - 62  = Weekdays Mon-Fri (2+4+8+16+32)
//   - 65  = Weekend Sat+Sun (1+64)
//   - 0   = No days
type Weekdays uint8

// Weekday bitmask constants for each day.
const (
	WeekdaySunday    Weekdays = 1 << time.Sunday    // 1
	WeekdayMonday    Weekdays = 1 << time.Monday    // 2
	WeekdayTuesday   Weekdays = 1 << time.Tuesday   // 4
	WeekdayWednesday Weekdays = 1 << time.Wednesday // 8
	WeekdayThursday  Weekdays = 1 << time.Thursday  // 16
	WeekdayFriday    Weekdays = 1 << time.Friday    // 32
	WeekdaySaturday  Weekdays = 1 << time.Saturday  // 64
)

// WeekdaysAll represents all days of the week (127).
const WeekdaysAll Weekdays = WeekdaySunday | WeekdayMonday | WeekdayTuesday |
	WeekdayWednesday | WeekdayThursday | WeekdayFriday | WeekdaySaturday

// WeekdaysWeekdays represents Monday through Friday (62).
const WeekdaysWeekdays Weekdays = WeekdayMonday | WeekdayTuesday |
	WeekdayWednesday | WeekdayThursday | WeekdayFriday

// WeekdaysWeekend represents Saturday and Sunday (65).
const WeekdaysWeekend Weekdays = WeekdaySaturday | WeekdaySunday

// WeekdaysNone represents no days (0).
const WeekdaysNone Weekdays = 0

// IsActive reports whether the given weekday is set in the bitmask.
func (w Weekdays) IsActive(day time.Weekday) bool {
	return w&(1<<day) != 0
}

// With returns a new Weekdays with the given day added.
func (w Weekdays) With(day time.Weekday) Weekdays {
	return w | (1 << day)
}

// Without returns a new Weekdays with the given day removed.
func (w Weekdays) Without(day time.Weekday) Weekdays {
	return w &^ (1 << day)
}

// Toggle returns a new Weekdays with the given day toggled.
func (w Weekdays) Toggle(day time.Weekday) Weekdays {
	return w ^ (1 << day)
}

// ActiveDays returns a slice of time.Weekday values for all active days.
func (w Weekdays) ActiveDays() []time.Weekday {
	var days []time.Weekday
	for day := time.Sunday; day <= time.Saturday; day++ {
		if w.IsActive(day) {
			days = append(days, day)
		}
	}
	return days
}

// Count returns the number of active days.
func (w Weekdays) Count() int {
	count := 0
	for day := time.Sunday; day <= time.Saturday; day++ {
		if w.IsActive(day) {
			count++
		}
	}
	return count
}

// MarshalJSON implements json.Marshaler to serialize Weekdays as an integer.
func (w Weekdays) MarshalJSON() ([]byte, error) {
	return json.Marshal(uint8(w))
}

// UnmarshalJSON implements json.Unmarshaler to deserialize Weekdays from an integer.
func (w *Weekdays) UnmarshalJSON(data []byte) error {
	var n uint8
	if err := json.Unmarshal(data, &n); err != nil {
		return fmt.Errorf("weekdays must be an integer (0-127): %w", err)
	}
	if n > 127 {
		return fmt.Errorf("weekdays must be 0-127, got %d", n)
	}
	*w = Weekdays(n)
	return nil
}
