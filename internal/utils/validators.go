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

// dateAfterValidator validates that a date field is after another date field in the same struct
// Usage: `validate:"dateafter=StartDate"`
func dateAfterValidator(fl validator.FieldLevel) bool {
	field := fl.Field()
	param := fl.Param()

	// Get the field to compare against
	parent := fl.Parent()
	compareField := parent.FieldByName(param)

	if !compareField.IsValid() {
		return true // If comparison field doesn't exist, validation passes
	}

	// Handle both time.Time and string fields, including pointers
	var currentTime, compareTime time.Time
	var err error
	var currentEmpty, compareEmpty bool

	// Parse current field
	switch {
	case field.Type() == reflect.TypeOf(time.Time{}):
		timeVal, ok := field.Interface().(time.Time)
		if !ok {
			return false // Failed to convert to time.Time
		}
		currentTime = timeVal
	case field.Kind() == reflect.String:
		dateStr := field.String()
		if dateStr == "" {
			currentEmpty = true
		} else {
			currentTime, err = time.Parse("2006-01-02", dateStr)
			if err != nil {
				return false // Invalid date format
			}
		}
	case field.Kind() == reflect.Ptr && !field.IsNil():
		// Handle pointer to string (for optional fields)
		if field.Elem().Kind() == reflect.String {
			dateStr := field.Elem().String()
			if dateStr == "" {
				currentEmpty = true
			} else {
				currentTime, err = time.Parse("2006-01-02", dateStr)
				if err != nil {
					return false // Invalid date format
				}
			}
		}
	case field.Kind() == reflect.Ptr && field.IsNil():
		currentEmpty = true
	default:
		return true // Unknown type, skip validation
	}

	// Parse comparison field
	switch {
	case compareField.Type() == reflect.TypeOf(time.Time{}):
		timeVal, ok := compareField.Interface().(time.Time)
		if !ok {
			return true // Failed to convert, skip validation
		}
		compareTime = timeVal
	case compareField.Kind() == reflect.String:
		dateStr := compareField.String()
		if dateStr == "" {
			compareEmpty = true
		} else {
			compareTime, err = time.Parse("2006-01-02", dateStr)
			if err != nil {
				return true // Invalid comparison date format, skip validation
			}
		}
	case compareField.Kind() == reflect.Ptr && !compareField.IsNil():
		// Handle pointer to string (for optional fields)
		if compareField.Elem().Kind() == reflect.String {
			dateStr := compareField.Elem().String()
			if dateStr == "" {
				compareEmpty = true
			} else {
				compareTime, err = time.Parse("2006-01-02", dateStr)
				if err != nil {
					return true // Invalid comparison date format, skip validation
				}
			}
		}
	case compareField.Kind() == reflect.Ptr && compareField.IsNil():
		compareEmpty = true
	default:
		return true // Unknown type, skip validation
	}

	// If either date is empty, skip validation (handled by required validation if needed)
	if currentEmpty || compareEmpty {
		return true
	}

	// Check if current date is after or equal to comparison date
	return currentTime.After(compareTime) || currentTime.Equal(compareTime)
}

// dateFormatValidator validates date strings are in YYYY-MM-DD format
func dateFormatValidator(fl validator.FieldLevel) bool {
	dateStr := fl.Field().String()
	if dateStr == "" {
		return true // Empty strings are valid for optional fields
	}

	_, err := time.Parse("2006-01-02", dateStr)
	return err == nil
}
