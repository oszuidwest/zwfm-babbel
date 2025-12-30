// Package logger provides structured logging utilities using slog.
package logger

import (
	"fmt"
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

// Info logs informational messages with Printf-style formatting.
func Info(message string, args ...any) {
	logger.Info(fmt.Sprintf(message, args...))
}

// Error logs error messages with Printf-style formatting.
func Error(message string, args ...any) {
	logger.Error(fmt.Sprintf(message, args...))
}

// Fatal logs fatal error messages and terminates the program.
func Fatal(message string, args ...any) {
	logger.Error(fmt.Sprintf(message, args...))
	os.Exit(1)
}

// Debug logs debug messages with Printf-style formatting.
func Debug(message string, args ...any) {
	logger.Debug(fmt.Sprintf(message, args...))
}

// Warn logs warning messages with Printf-style formatting.
func Warn(message string, args ...any) {
	logger.Warn(fmt.Sprintf(message, args...))
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
