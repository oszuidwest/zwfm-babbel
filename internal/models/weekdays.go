package models

import "time"

// Weekdays selects days with 1 << time.Weekday: Sunday=1 through Saturday=64.
// Common masks are 127 (all), 62 (Mon–Fri), 65 (weekend), and 0 (none).
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
