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

// InitializeValidators registers the validation tags used by request structs.
// It must run during application startup and panics if Gin is not using the
// go-playground validator engine.
func InitializeValidators() {
	v, ok := binding.Validator.Engine().(*validator.Validate)
	if !ok {
		panic(fmt.Sprintf("Validator engine is not *validator.Validate, got %T", binding.Validator.Engine()))
	}

	// Optional[string] exposes its inner value to binding tags; absent/null
	// fields return "" so omitempty can skip validation.
	v.RegisterCustomTypeFunc(func(field reflect.Value) any {
		if opt, ok := reflect.TypeAssert[Optional[string]](field); ok && opt.HasValue() {
			return *opt.Value
		}
		return ""
	}, Optional[string]{})

	if err := v.RegisterValidation("notblank", notBlankValidator); err != nil {
		panic(fmt.Sprintf("Failed to register notblank validator: %v", err))
	}

	if err := v.RegisterValidation("story_status", storyStatusValidator); err != nil {
		panic(fmt.Sprintf("Failed to register story_status validator: %v", err))
	}

	if err := v.RegisterValidation("dateafter", dateAfterValidator); err != nil {
		panic(fmt.Sprintf("Failed to register dateafter validator: %v", err))
	}

	if err := v.RegisterValidation("dateformat", dateFormatValidator); err != nil {
		panic(fmt.Sprintf("Failed to register dateformat validator: %v", err))
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

// parseDateField parses supported date field shapes for custom validators.
// The boolean return is false for unsupported field types.
func parseDateField(field reflect.Value) (dateParseResult, bool) {
	if !field.IsValid() || (field.Kind() == reflect.Pointer && field.IsNil()) {
		return dateParseResult{IsEmpty: true}, true
	}
	if field.Type() == reflect.TypeFor[time.Time]() {
		timeVal, ok := reflect.TypeAssert[time.Time](field)
		return dateParseResult{Time: timeVal, FailValidation: !ok}, true
	}
	if field.Kind() == reflect.Pointer {
		field = field.Elem()
	}
	if field.Kind() != reflect.String {
		return dateParseResult{}, false // Unknown type, skip
	}
	if field.String() == "" {
		return dateParseResult{IsEmpty: true}, true
	}
	t, err := time.ParseInLocation(time.DateOnly, field.String(), time.Local)
	return dateParseResult{Time: t, FailValidation: err != nil}, true
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

	_, err := time.ParseInLocation(time.DateOnly, dateStr, time.Local)
	return err == nil
}
