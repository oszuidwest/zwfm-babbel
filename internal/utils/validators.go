package utils

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// InitializeValidators registers the validation tags used by request structs
// and reports fields by their JSON names. It must run before the first request
// is validated, because the validator caches struct metadata, and panics if
// Gin is not using the go-playground validator engine.
func InitializeValidators() {
	v, ok := binding.Validator.Engine().(*validator.Validate)
	if !ok {
		panic(fmt.Sprintf("Validator engine is not *validator.Validate, got %T", binding.Validator.Engine()))
	}

	// Validation still resolves fields by Go name; only reported names change.
	v.RegisterTagNameFunc(func(field reflect.StructField) string {
		name, _ := jsonFieldName(field)
		return name
	})

	if err := v.RegisterValidation("notblank", notBlankValidator); err != nil {
		panic(fmt.Sprintf("Failed to register notblank validator: %v", err))
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

// dateFormatValidator validates date strings are in YYYY-MM-DD format. Absent
// optional dates are skipped by omitempty, so a present empty string fails.
func dateFormatValidator(fl validator.FieldLevel) bool {
	_, err := time.ParseInLocation(time.DateOnly, fl.Field().String(), time.Local)
	return err == nil
}
