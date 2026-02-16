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

// dateParseResult holds the result of parsing a date field.
type dateParseResult struct {
	Time           time.Time
	IsEmpty        bool
	FailValidation bool
}

// parseDateField attempts to parse a date from a reflect.Value.
// Returns the parsed result and whether the parse was successful.
func parseDateField(field reflect.Value) (dateParseResult, bool) {
	result := dateParseResult{}

	// Check if the field is valid before processing
	if !field.IsValid() {
		result.IsEmpty = true
		return result, true
	}

	switch {
	case field.Type() == reflect.TypeFor[time.Time]():
		timeVal, ok := field.Interface().(time.Time)
		if !ok {
			result.FailValidation = true
			return result, true
		}
		result.Time = timeVal
		return result, true

	case field.Kind() == reflect.String:
		dateStr := field.String()
		if dateStr == "" {
			result.IsEmpty = true
			return result, true
		}
		t, err := time.ParseInLocation("2006-01-02", dateStr, time.Local)
		if err != nil {
			result.FailValidation = true
			return result, true
		}
		result.Time = t
		return result, true

	case field.Kind() == reflect.Pointer && !field.IsNil():
		if field.Elem().Kind() == reflect.String {
			dateStr := field.Elem().String()
			if dateStr == "" {
				result.IsEmpty = true
				return result, true
			}
			t, err := time.ParseInLocation("2006-01-02", dateStr, time.Local)
			if err != nil {
				result.FailValidation = true
				return result, true
			}
			result.Time = t
			return result, true
		}
		return result, false // Unknown pointer type, skip

	case field.Kind() == reflect.Pointer && field.IsNil():
		result.IsEmpty = true
		return result, true

	default:
		return result, false // Unknown type, skip
	}
}

// dateAfterValidator validates that a date field is after another date field in the same struct.
// Usage: `validate:"dateafter=StartDate"`.
func dateAfterValidator(fl validator.FieldLevel) bool {
	compareField := fl.Parent().FieldByName(fl.Param())
	if !compareField.IsValid() {
		return true // Comparison field doesn't exist, validation passes
	}

	currentResult, currentOK := parseDateField(fl.Field())
	if currentResult.FailValidation {
		return false
	}
	if !currentOK || currentResult.IsEmpty {
		return true
	}

	compareResult, compareOK := parseDateField(compareField)
	if !compareOK || compareResult.IsEmpty {
		return true
	}

	return currentResult.Time.After(compareResult.Time) || currentResult.Time.Equal(compareResult.Time)
}

// dateFormatValidator validates date strings are in YYYY-MM-DD format.
func dateFormatValidator(fl validator.FieldLevel) bool {
	dateStr := fl.Field().String()
	if dateStr == "" {
		return true // Empty strings are valid for optional fields
	}

	_, err := time.ParseInLocation("2006-01-02", dateStr, time.Local)
	return err == nil
}
