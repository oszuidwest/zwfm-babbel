package repository

import (
	"reflect"
	"strings"

	"gorm.io/gorm/schema"
)

// BuildUpdateMap converts pointer, map, and Clear* fields to GORM updates.
// Nil pointers and empty maps are skipped; ClearX takes precedence and stores
// NULL. GORM column tags override the default snake_case name.
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

	for fieldType, fieldVal := range v.Fields() {
		col, val, ok := processField(fieldVal, fieldType, clearFields)
		if ok {
			result[col] = val
		}
	}

	return result
}

// collectClearFields returns the targets of enabled Clear* fields.
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
		targetName := strings.TrimPrefix(field.Name, "Clear")
		clearFields[targetName] = true
	}

	return clearFields
}

// processField returns the update column/value for one field.
// Cleared fields return (col, nil, true); non-nil pointers return
// (col, value, true); skipped fields return ("", nil, false).
func processField(fieldVal reflect.Value, fieldType reflect.StructField, clearFields map[string]bool) (string, any, bool) {
	if strings.HasPrefix(fieldType.Name, "Clear") {
		return "", nil, false
	}

	if shouldSkipGormField(fieldType.Tag.Get("gorm")) {
		return "", nil, false
	}

	col := getColumnName(fieldType)

	if clearFields[fieldType.Name] {
		return col, nil, true
	}

	if fieldVal.Kind() == reflect.Pointer && !fieldVal.IsNil() {
		return col, fieldVal.Elem().Interface(), true
	}

	if fieldVal.Kind() == reflect.Map && !fieldVal.IsNil() && fieldVal.Len() > 0 {
		return col, fieldVal.Interface(), true
	}

	return "", nil, false
}

func shouldSkipGormField(gormTag string) bool {
	return gormTag == "-" || strings.HasPrefix(gormTag, "-,") || strings.Contains(gormTag, ",-")
}

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

// toSnakeCase converts a Go field name to its database column name using
// GORM's default naming strategy (e.g. "VoiceID" becomes "voice_id").
func toSnakeCase(s string) string {
	return schema.NamingStrategy{}.ColumnName("", s)
}
