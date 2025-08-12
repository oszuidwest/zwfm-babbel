// Package logger provides structured logging utilities.
//
// This package sets up different loggers for different message types
// and provides simple logging functions with consistent formatting.
package logger

import (
	"io"
	"log"
	"os"
)

var (
	// InfoLogger handles informational messages.
	InfoLogger *log.Logger
	// ErrorLogger handles error messages.
	ErrorLogger *log.Logger
	// DebugLogger handles debug messages.
	DebugLogger *log.Logger
)

// Initialize sets up simple loggers.
func Initialize(level string, development bool) error {
	// Configure based on level and development mode
	flags := log.Ldate | log.Ltime
	if development {
		flags |= log.Lshortfile
	}

	InfoLogger = log.New(os.Stdout, "INFO: ", flags)
	ErrorLogger = log.New(os.Stderr, "ERROR: ", flags)

	// Only enable debug logger if level is "debug"
	if level == "debug" {
		DebugLogger = log.New(os.Stdout, "DEBUG: ", flags)
	} else {
		// Create a no-op logger for non-debug mode
		DebugLogger = log.New(io.Discard, "", 0)
	}

	return nil
}

// Info logs informational messages.
func Info(message string, args ...interface{}) {
	if InfoLogger != nil {
		InfoLogger.Printf(message, args...)
	}
}

// Error logs error messages.
func Error(message string, args ...interface{}) {
	if ErrorLogger != nil {
		ErrorLogger.Printf(message, args...)
	}
}

// Fatal logs fatal messages and terminates the program.
func Fatal(message string, args ...interface{}) {
	if ErrorLogger != nil {
		ErrorLogger.Printf(message, args...)
	}
	os.Exit(1)
}

// Sync flushes any buffered log entries (no-op for standard logger).
func Sync() {
	// No-op for standard log package
}
