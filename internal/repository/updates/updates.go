// Package updates provides type-safe update helpers for GORM repositories.
// It uses reflection to convert update structs to maps, eliminating manual if-chains.
package updates

import (
	"reflect"
)

// Nullable represents a field that can be set to a value, set to NULL, or skipped.
// Use Set() to set a value, SetNull() to set NULL, or leave zero value to skip.
type Nullable[T any] struct {
	Value *T   // The value to set (nil means NULL if IsSet is true)
	IsSet bool // Whether this field should be updated
}

// Set creates a Nullable that sets the field to the given value.
func Set[T any](v T) Nullable[T] {
	return Nullable[T]{Value: &v, IsSet: true}
}

// SetNull creates a Nullable that sets the field to NULL.
func SetNull[T any]() Nullable[T] {
	return Nullable[T]{Value: nil, IsSet: true}
}

// Skip creates a Nullable that skips updating this field.
// This is the zero value, so you can just omit the field.
func Skip[T any]() Nullable[T] {
	return Nullable[T]{Value: nil, IsSet: false}
}

// ToMap converts an update struct to a map[string]any for GORM's Updates method.
// It reads `db` tags from struct fields to determine column names.
//
// Field handling:
//   - Pointer fields (*T): nil = skip, non-nil = set value
//   - Nullable[T] fields: IsSet=false = skip, IsSet=true with nil Value = NULL, otherwise set value
//
// Example:
//
//	type StoryUpdate struct {
//	    Title *string         `db:"title"`
//	    Text  *string         `db:"text"`
//	    Email Nullable[string] `db:"email"`
//	}
//
//	update := &StoryUpdate{Title: ptr("New Title")}
//	m := ToMap(update) // {"title": "New Title"}
func ToMap(update any) map[string]any {
	if update == nil {
		return nil
	}

	v := reflect.ValueOf(update)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return nil
	}

	result := make(map[string]any)
	t := v.Type()

	for i := range t.NumField() {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Get column name from db tag
		columnName := field.Tag.Get("db")
		if columnName == "" || columnName == "-" {
			continue
		}

		// Handle Nullable[T] fields
		if isNullableType(field.Type) {
			if isSet, value := extractNullableValue(fieldValue); isSet {
				result[columnName] = value
			}
			continue
		}

		// Handle pointer fields (*T)
		if field.Type.Kind() == reflect.Ptr {
			if !fieldValue.IsNil() {
				result[columnName] = fieldValue.Elem().Interface()
			}
			continue
		}
	}

	return result
}

// isNullableType checks if the type is a Nullable[T] type.
func isNullableType(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	// Check for IsSet and Value fields which are characteristic of Nullable[T]
	isSetField, hasIsSet := t.FieldByName("IsSet")
	valueField, hasValue := t.FieldByName("Value")
	return hasIsSet && hasValue &&
		isSetField.Type.Kind() == reflect.Bool &&
		valueField.Type.Kind() == reflect.Ptr
}

// extractNullableValue extracts the value from a Nullable[T] field.
// Returns (true, value) if IsSet is true, (false, nil) otherwise.
// If IsSet is true but Value is nil, returns (true, nil) to set NULL.
func extractNullableValue(v reflect.Value) (bool, any) {
	isSetField := v.FieldByName("IsSet")
	if !isSetField.Bool() {
		return false, nil
	}

	valueField := v.FieldByName("Value")
	if valueField.IsNil() {
		return true, nil // Set to NULL
	}

	return true, valueField.Elem().Interface()
}
