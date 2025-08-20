// Package logger provides structured logging utilities.
package logger

import (
	"io"
	"log"
	"os"
)

var (
	InfoLogger  *log.Logger
	ErrorLogger *log.Logger
	DebugLogger *log.Logger
)

// Initialize sets up the logging system with the specified level and mode.
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

// Info logs informational messages to stdout.
func Info(message string, args ...interface{}) {
	if InfoLogger != nil {
		InfoLogger.Printf(message, args...)
	}
}

// Error logs error messages to stderr.
func Error(message string, args ...interface{}) {
	if ErrorLogger != nil {
		ErrorLogger.Printf(message, args...)
	}
}

// Fatal logs fatal error messages to stderr and terminates the program.
func Fatal(message string, args ...interface{}) {
	if ErrorLogger != nil {
		ErrorLogger.Printf(message, args...)
	}
	os.Exit(1)
}

// Sync flushes any buffered log entries.
func Sync() {
	// No-op for standard log package
}
