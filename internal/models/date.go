package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// Date is a calendar day, serialized as YYYY-MM-DD without timezone conversion.
type Date time.Time

// MarshalJSON implements json.Marshaler for a calendar date.
func (d Date) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(d).Format(time.DateOnly))
}

// UnmarshalJSON implements json.Unmarshaler for a calendar date.
func (d *Date) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	return d.Scan(value)
}

// Scan implements sql.Scanner for MySQL DATE values.
func (d *Date) Scan(value any) error {
	switch value := value.(type) {
	case time.Time:
		*d = Date(value)
		return nil
	case string:
		parsed, err := time.ParseInLocation(time.DateOnly, value, time.Local)
		if err != nil {
			return err
		}
		*d = Date(parsed)
		return nil
	case []byte:
		return d.Scan(string(value))
	case nil:
		*d = Date{}
		return nil
	default:
		return fmt.Errorf("cannot scan %T into Date", value)
	}
}

// Value implements driver.Valuer without shifting the calendar day.
func (d Date) Value() (driver.Value, error) {
	return time.Time(d).Format(time.DateOnly), nil
}

// GormDataType keeps calendar dates mapped to SQL DATE columns.
func (d Date) GormDataType() string { return "date" }
