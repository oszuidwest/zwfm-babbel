// Package logger provides structured logging utilities using slog.
package logger

import (
	"fmt"
	"log/slog"
	"os"
)

var logger *slog.Logger

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
	if logger == nil {
		panic("logger: not initialized - call Initialize() first")
	}
	logger.Info(fmt.Sprintf(message, args...))
}

// Error logs error messages with Printf-style formatting.
func Error(message string, args ...any) {
	if logger == nil {
		panic("logger: not initialized - call Initialize() first")
	}
	logger.Error(fmt.Sprintf(message, args...))
}

// Fatal logs fatal error messages and terminates the program.
func Fatal(message string, args ...any) {
	if logger == nil {
		panic("logger: not initialized - call Initialize() first")
	}
	logger.Error(fmt.Sprintf(message, args...))
	os.Exit(1)
}

// Debug logs debug messages with Printf-style formatting.
func Debug(message string, args ...any) {
	if logger == nil {
		panic("logger: not initialized - call Initialize() first")
	}
	logger.Debug(fmt.Sprintf(message, args...))
}

// Warn logs warning messages with Printf-style formatting.
func Warn(message string, args ...any) {
	if logger == nil {
		panic("logger: not initialized - call Initialize() first")
	}
	logger.Warn(fmt.Sprintf(message, args...))
}

// Sync flushes any buffered log entries (no-op for slog).
func Sync() {}
