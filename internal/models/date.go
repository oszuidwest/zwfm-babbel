package models

import (
	"database/sql/driver"
	"fmt"
	"time"
)

// Date is a calendar day, serialized as YYYY-MM-DD without timezone conversion.
type Date time.Time

// MarshalJSON implements json.Marshaler for a calendar date.
func (d Date) MarshalJSON() ([]byte, error) {
	return time.Time(d).AppendFormat([]byte(`"`), time.DateOnly+`"`), nil
}

// Scan implements sql.Scanner for MySQL DATE values read with parseTime=true.
// The driver returns midnight in the session zone (UTC); Scan keeps the
// calendar day and moves it to local midnight, where parsed dates live.
func (d *Date) Scan(value any) error {
	t, ok := value.(time.Time)
	if !ok {
		return fmt.Errorf("cannot scan %T into Date", value)
	}
	*d = Date(time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local))
	return nil
}

// Value implements driver.Valuer without shifting the calendar day.
func (d Date) Value() (driver.Value, error) {
	return time.Time(d).Format(time.DateOnly), nil
}
