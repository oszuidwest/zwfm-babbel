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
// records at level and above. It swaps process-wide loggers, so it panics in a
// parallel test. The guard does not reach subtests of the capturing test, so
// those must not call t.Parallel either.
//
// It is a variable rather than a function because deadcode, which runs without
// -test, reports functions that no binary reaches but not function literals.
var CaptureLogs = func(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	// Nothing reads this variable: Setenv panics if the test or an ancestor
	// called t.Parallel, and makes a later t.Parallel call panic.
	t.Setenv("BABBEL_TEST_CAPTURE_LOGS", "1")
	var buf bytes.Buffer
	previous, previousWriter, previousFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})))
	// SetDefault also points the log package at the new handler and clears its
	// flags; restoring the built-in default handler undoes neither.
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
	return &buf
}
