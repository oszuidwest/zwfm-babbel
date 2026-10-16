// Package testutil holds helpers shared by tests. Only _test.go files import
// it, so it is never linked into the binary.
package testutil

import (
	"bytes"
	"log"
	"log/slog"
	"testing"
)

// CaptureLogs sends the slog default to a JSON buffer for one test, keeping
// records at level and above. It swaps process-wide loggers, so do not use it
// in parallel tests.
//
// It is a variable rather than a function because deadcode only follows the
// binaries and would report a function used solely by tests.
var CaptureLogs = func(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous, previousWriter, previousFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})))
	// SetDefault also redirects the log package, and restoring the built-in
	// default handler does not undo that.
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
	return &buf
}
