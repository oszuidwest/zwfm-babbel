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

// dateAfterValidator validates that a YYYY-MM-DD string field is on or after
// another date field in the same struct. An empty field or a missing or
// unparsable comparison field passes; an unparsable field fails.
// Usage: `validate:"dateafter=StartDate"`.
func dateAfterValidator(fl validator.FieldLevel) bool {
	endStr := fl.Field().String()
	if endStr == "" {
		return true
	}
	end, err := time.ParseInLocation(time.DateOnly, endStr, time.Local)
	if err != nil {
		return false
	}
	start, err := time.ParseInLocation(time.DateOnly, fl.Parent().FieldByName(fl.Param()).String(), time.Local)
	return err != nil || !end.Before(start)
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
