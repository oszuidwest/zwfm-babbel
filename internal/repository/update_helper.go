package repository

import (
	"reflect"
	"strings"
	"unicode"
)

// BuildUpdateMap converts a struct with pointer fields and Clear* flags into a GORM update map.
//
// Convention:
//   - Pointer fields: nil = skip, non-nil = update with dereferenced value
//   - Clear* bool fields: true = set corresponding field to NULL (takes precedence)
//   - Column names from gorm:"column:..." tag, or snake_case of field name
//   - Fields tagged gorm:"-" are skipped
//
// Example:
//
//	type StoryUpdate struct {
//	    Title        *string `gorm:"column:title"`
//	    VoiceID      *int64  `gorm:"column:voice_id"`
//	    ClearVoiceID bool    `gorm:"-"`  // Sets voice_id to NULL
//	}
//
//	updateMap := BuildUpdateMap(u)  // Handles all fields automatically
func BuildUpdateMap(update any) map[string]any {
	result := make(map[string]any)

	v := reflect.ValueOf(update)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return result
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return result
	}

	clearFields := collectClearFields(v)

	// Process all fields
	for fieldType, fieldVal := range v.Fields() {
		col, val, ok := processField(fieldVal, fieldType, clearFields)
		if ok {
			result[col] = val
		}
	}

	return result
}

// collectClearFields scans struct for Clear* bool fields set to true.
// Returns a map of target field names that should be set to NULL.
// For example, ClearVoiceID=true results in map["VoiceID"]=true.
func collectClearFields(v reflect.Value) map[string]bool {
	clearFields := make(map[string]bool)

	for field, fieldVal := range v.Fields() {
		if !strings.HasPrefix(field.Name, "Clear") {
			continue
		}
		if field.Type.Kind() != reflect.Bool {
			continue
		}
		if !fieldVal.Bool() {
			continue
		}
		// ClearVoiceID -> VoiceID
		targetName := strings.TrimPrefix(field.Name, "Clear")
		clearFields[targetName] = true
	}

	return clearFields
}

// processField determines if a struct field should be included in the update map.
// Returns the column name, value, and whether the field should be included.
// Returns (col, nil, true) for cleared fields, (col, value, true) for non-nil pointers,
// or ("", nil, false) if the field should be skipped.
func processField(fieldVal reflect.Value, fieldType reflect.StructField, clearFields map[string]bool) (string, any, bool) {
	// Skip Clear* flags themselves
	if strings.HasPrefix(fieldType.Name, "Clear") {
		return "", nil, false
	}

	// Skip gorm:"-" fields
	if shouldSkipGormField(fieldType.Tag.Get("gorm")) {
		return "", nil, false
	}

	// Get column name
	col := getColumnName(fieldType)

	// Check if this field should be cleared to NULL (takes precedence)
	if clearFields[fieldType.Name] {
		return col, nil, true
	}

	// Handle pointer fields - only include if non-nil
	if fieldVal.Kind() == reflect.Pointer && !fieldVal.IsNil() {
		return col, fieldVal.Elem().Interface(), true
	}

	// Handle map fields (like datatypes.JSONMap) - only include if non-nil and non-empty
	if fieldVal.Kind() == reflect.Map && !fieldVal.IsNil() && fieldVal.Len() > 0 {
		return col, fieldVal.Interface(), true
	}

	return "", nil, false
}

// shouldSkipGormField reports whether the gorm tag indicates the field should be skipped.
func shouldSkipGormField(gormTag string) bool {
	return gormTag == "-" || strings.HasPrefix(gormTag, "-,") || strings.Contains(gormTag, ",-")
}

// getColumnName extracts the column name from struct field tags or derives it from field name.
func getColumnName(fieldType reflect.StructField) string {
	if col := extractColumnFromTag(fieldType.Tag.Get("gorm")); col != "" {
		return col
	}
	return toSnakeCase(fieldType.Name)
}

// extractColumnFromTag extracts the column name from a GORM tag like `gorm:"column:voice_id"`.
func extractColumnFromTag(tag string) string {
	for part := range strings.SplitSeq(tag, ";") {
		part = strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(part, "column:"); ok {
			return after
		}
	}
	return ""
}

// toSnakeCase converts CamelCase to snake_case.
func toSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) {
			result.WriteByte('_')
		}
		result.WriteRune(unicode.ToLower(r))
	}
	return result.String()
}
