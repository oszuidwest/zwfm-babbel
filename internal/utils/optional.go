package utils

import "encoding/json/v2"

// Optional represents a JSON field that distinguishes three states:
//   - Absent:  Set=false, Value=nil  (field not in JSON body)
//   - Null:    Set=true,  Value=nil  (field explicitly set to null)
//   - Present: Set=true,  Value=&v   (field set to a value)
//
// Map IsClearing() to the update's Clear* flag and Value to its field.
type Optional[T any] struct {
	Set   bool
	Value *T
}

// UnmarshalJSON implements json.Unmarshaler using v2 error semantics.
// Only called when the field is present in the JSON body.
func (o *Optional[T]) UnmarshalJSON(data []byte) error {
	o.Set = true
	if string(data) == "null" {
		return nil
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	o.Value = &v
	return nil
}

// IsClearing reports whether the field was explicitly set to null.
func (o Optional[T]) IsClearing() bool {
	return o.Set && o.Value == nil
}
