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
//   - 127 = All days (1+2+4+8+16+32+64).
//   - 62  = Weekdays Mon-Fri (2+4+8+16+32).
//   - 65  = Weekend Sat+Sun (1+64).
//   - 0   = No days.
type Weekdays uint8

const (
	// WeekdaySunday selects Sunday in a Weekdays bitmask (1).
	WeekdaySunday Weekdays = 1 << time.Sunday
	// WeekdayMonday selects Monday in a Weekdays bitmask (2).
	WeekdayMonday Weekdays = 1 << time.Monday
	// WeekdayTuesday selects Tuesday in a Weekdays bitmask (4).
	WeekdayTuesday Weekdays = 1 << time.Tuesday
	// WeekdayWednesday selects Wednesday in a Weekdays bitmask (8).
	WeekdayWednesday Weekdays = 1 << time.Wednesday
	// WeekdayThursday selects Thursday in a Weekdays bitmask (16).
	WeekdayThursday Weekdays = 1 << time.Thursday
	// WeekdayFriday selects Friday in a Weekdays bitmask (32).
	WeekdayFriday Weekdays = 1 << time.Friday
	// WeekdaySaturday selects Saturday in a Weekdays bitmask (64).
	WeekdaySaturday Weekdays = 1 << time.Saturday
)

// WeekdaysAll represents all days of the week (127).
const WeekdaysAll Weekdays = WeekdaySunday | WeekdayMonday | WeekdayTuesday |
	WeekdayWednesday | WeekdayThursday | WeekdayFriday | WeekdaySaturday

// IsActive reports whether the given weekday is set in the bitmask.
func (w Weekdays) IsActive(day time.Weekday) bool {
	return w&(1<<day) != 0
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
