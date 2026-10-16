// Package logger provides structured logging utilities using slog.
package logger

import (
	"log/slog"
	"os"
)

// Initialize installs the slog default used by this package's logging helpers.
func Initialize(level string, development bool) error {
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if level == "debug" {
		opts.Level = slog.LevelDebug
	}

	if development {
		opts.AddSource = true
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	slog.SetDefault(slog.New(handler))
	return nil
}

// Info logs informational messages with slog key-value attributes.
func Info(message string, args ...any) {
	slog.Info(message, args...)
}

// Error logs error messages with slog key-value attributes.
func Error(message string, args ...any) {
	slog.Error(message, args...)
}

// Debug logs debug messages with slog key-value attributes.
func Debug(message string, args ...any) {
	slog.Debug(message, args...)
}

// Warn logs warning messages with slog key-value attributes.
func Warn(message string, args ...any) {
	slog.Warn(message, args...)
}

// WithFields returns a logger with the given structured attributes.
func WithFields(fields map[string]any) *slog.Logger {
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return slog.Default().With(args...)
}
