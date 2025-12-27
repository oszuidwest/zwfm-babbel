// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"fmt"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"reflect"
	"strings"
	"time"
)

// InitializeValidators registers custom validation rules with Gin's binding engine.
// Must be called during application startup to enable custom validation tags.
// Panics if validator registration fails, as this is a critical configuration error.
func InitializeValidators() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		// Register notblank validator - ensures string is not empty or whitespace-only
		if err := v.RegisterValidation("notblank", notBlankValidator); err != nil {
			panic(fmt.Sprintf("Failed to register notblank validator: %v", err))
		}

		// Register story status validator
		if err := v.RegisterValidation("story_status", storyStatusValidator); err != nil {
			panic(fmt.Sprintf("Failed to register story_status validator: %v", err))
		}

		// Register date after validator for comparing dates
		if err := v.RegisterValidation("dateafter", dateAfterValidator); err != nil {
			panic(fmt.Sprintf("Failed to register dateafter validator: %v", err))
		}

		// Register date format validator
		if err := v.RegisterValidation("dateformat", dateFormatValidator); err != nil {
			panic(fmt.Sprintf("Failed to register dateformat validator: %v", err))
		}
	}
}

// notBlankValidator validates that a string field is not empty or whitespace-only.
// More strict than the standard required validator which allows whitespace.
func notBlankValidator(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	return strings.TrimSpace(value) != ""
}

// storyStatusValidator validates that a story status is one of the allowed values.
// Ensures story status integrity by restricting to: draft, active, expired.
func storyStatusValidator(fl validator.FieldLevel) bool {
	status := models.StoryStatus(fl.Field().String())
	return status.IsValid()
}

// parseDateField extracts a time.Time value from a reflect.Value that may be
// a time.Time, string, *string, or *time.Time. Returns the parsed time, whether
// the field is empty, whether parsing was successful, and whether to fail validation.
func parseDateField(field reflect.Value) (parsedTime time.Time, isEmpty bool, ok bool, failValidation bool) {
	// Check if the field is valid before processing
	if !field.IsValid() {
		return time.Time{}, true, true, false
	}

	switch {
	case field.Type() == reflect.TypeOf(time.Time{}):
		timeVal, valid := field.Interface().(time.Time)
		if !valid {
			return time.Time{}, false, false, true
		}
		return timeVal, false, true, false

	case field.Kind() == reflect.String:
		dateStr := field.String()
		if dateStr == "" {
			return time.Time{}, true, true, false
		}
		t, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return time.Time{}, false, false, true
		}
		return t, false, true, false

	case field.Kind() == reflect.Ptr && !field.IsNil():
		if field.Elem().Kind() == reflect.String {
			dateStr := field.Elem().String()
			if dateStr == "" {
				return time.Time{}, true, true, false
			}
			t, err := time.Parse("2006-01-02", dateStr)
			if err != nil {
				return time.Time{}, false, false, true
			}
			return t, false, true, false
		}
		return time.Time{}, false, false, false // Unknown pointer type, skip

	case field.Kind() == reflect.Ptr && field.IsNil():
		return time.Time{}, true, true, false

	default:
		return time.Time{}, false, false, false // Unknown type, skip
	}
}

// dateAfterValidator validates that a date field is after another date field in the same struct.
// Usage: `validate:"dateafter=StartDate"`
func dateAfterValidator(fl validator.FieldLevel) bool {
	compareField := fl.Parent().FieldByName(fl.Param())
	if !compareField.IsValid() {
		return true // Comparison field doesn't exist, validation passes
	}

	currentTime, currentEmpty, currentOK, currentFail := parseDateField(fl.Field())
	if currentFail {
		return false
	}
	if !currentOK || currentEmpty {
		return true
	}

	compareTime, compareEmpty, compareOK, _ := parseDateField(compareField)
	if !compareOK || compareEmpty {
		return true
	}

	return currentTime.After(compareTime) || currentTime.Equal(compareTime)
}

// dateFormatValidator validates date strings are in YYYY-MM-DD format.
func dateFormatValidator(fl validator.FieldLevel) bool {
	dateStr := fl.Field().String()
	if dateStr == "" {
		return true // Empty strings are valid for optional fields
	}

	_, err := time.Parse("2006-01-02", dateStr)
	return err == nil
}
