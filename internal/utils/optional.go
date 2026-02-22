package utils

import "encoding/json"

// Optional represents a JSON field that distinguishes three states:
//   - Absent:  Set=false, Value=nil  (field not in JSON body)
//   - Null:    Set=true,  Value=nil  (field explicitly set to null)
//   - Present: Set=true,  Value=&v   (field set to a value)
//
// This solves the fundamental Go JSON limitation where *T cannot distinguish
// "field absent" from "field is null" — both unmarshal to nil. Use this type
// in update request structs for nullable database columns that support clearing.
//
// Integrates with the repository layer's Clear* flag convention:
//
//	if opt.IsClearing() { updates.ClearField = true }
//	if opt.HasValue()   { updates.Field = opt.Value }
type Optional[T any] struct {
	Set   bool
	Value *T
}

// UnmarshalJSON implements json.Unmarshaler.
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

// MarshalJSON implements json.Marshaler for completeness.
func (o Optional[T]) MarshalJSON() ([]byte, error) {
	if !o.Set || o.Value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*o.Value)
}

// HasValue reports whether the field was present with a non-null value.
func (o Optional[T]) HasValue() bool {
	return o.Set && o.Value != nil
}

// IsClearing reports whether the field was explicitly set to null.
func (o Optional[T]) IsClearing() bool {
	return o.Set && o.Value == nil
}
