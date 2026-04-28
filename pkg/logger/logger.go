// Package logger provides structured logging utilities using slog.
package logger

import (
	"log/slog"
	"os"
)

var logger *slog.Logger

// init ensures a default logger is always available, even before Initialize() is called.
func init() {
	logger = slog.Default()
}

// Initialize sets up the logging system with the specified level and mode.
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

	logger = slog.New(handler)
	slog.SetDefault(logger)
	return nil
}

// Info logs informational messages with slog key-value attributes.
func Info(message string, args ...any) {
	logger.Info(message, args...)
}

// Error logs error messages with slog key-value attributes.
func Error(message string, args ...any) {
	logger.Error(message, args...)
}

// Fatal logs fatal error messages with slog key-value attributes and terminates the program.
func Fatal(message string, args ...any) {
	logger.Error(message, args...)
	os.Exit(1)
}

// Debug logs debug messages with slog key-value attributes.
func Debug(message string, args ...any) {
	logger.Debug(message, args...)
}

// Warn logs warning messages with slog key-value attributes.
func Warn(message string, args ...any) {
	logger.Warn(message, args...)
}

// Sync flushes any buffered log entries.
// This is a no-op for slog but kept for API compatibility.
func Sync() {}

// WithFields returns a new logger with the given fields added to its context.
// The returned logger can be used for structured logging with additional context.
func WithFields(fields map[string]any) *slog.Logger {
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return logger.With(args...)
}
