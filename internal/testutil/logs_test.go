package testutil

import (
	"bytes"
	"log"
	"log/slog"
	"strings"
	"testing"
)

func TestCaptureLogsRestoresLoggers(t *testing.T) {
	previousWriter, previousFlags := log.Writer(), log.Flags()
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
	var stdlib bytes.Buffer
	log.SetOutput(&stdlib)
	log.SetFlags(log.Lshortfile)
	previous := slog.Default()

	t.Run("capture", func(t *testing.T) {
		logs := CaptureLogs(t, slog.LevelInfo)
		slog.Debug("dropped")
		slog.Info("kept")
		log.Print("from log")
		if got := logs.String(); strings.Contains(got, "dropped") || !strings.Contains(got, `"msg":"kept"`) || !strings.Contains(got, "from log") {
			t.Fatalf("logs = %s, want Info records from slog and log only", got)
		}
	})

	t.Run("parallel", func(t *testing.T) {
		CaptureLogs(t, slog.LevelInfo)
		defer func() {
			if recover() == nil {
				t.Error("t.Parallel after CaptureLogs did not panic")
			}
		}()
		t.Parallel()
	})

	if slog.Default() != previous || log.Writer() != &stdlib || log.Flags() != log.Lshortfile {
		t.Fatalf("loggers not restored: writer %T, flags %d", log.Writer(), log.Flags())
	}
}
