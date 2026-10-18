package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// Cancelling an upload after its rename must not roll back the row behind
// the live jingle. Conversion still uses the cancellable request context.
func TestStationVoiceService_JingleCommitsAfterRequestCancel(t *testing.T) {
	t.Parallel()
	service, stationVoice := newJingleTestService(t, &jingleAudioRepository{})
	alerts := &capturingAlerter{}
	service.alerts = alerts
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	service.txManager = cancelAfterPublish{TxManager: &jingleContextTxManager{}, t: t,
		finalPath: utils.JinglePath(service.config, stationVoice.StationID, stationVoice.VoiceID), cancel: cancel}
	input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=880:duration=1")
	if err := service.ProcessJingle(ctx, stationVoice, input); err != nil {
		t.Fatalf("ProcessJingle = %v, want success after the request was cancelled", err)
	}
	if ctx.Err() == nil {
		t.Fatal("request was not cancelled during publication")
	}
	if len(alerts.events) != 0 || !slices.Equal(alerts.resolved, []string{"stationvoice:unrecorded-audio:3"}) {
		t.Fatalf("alerts = %+v, resolved = %v; want only the publication recovery", alerts.events, alerts.resolved)
	}
}

// Every commit failure after the rename must name the live file immediately,
// including timeouts, whose handler response otherwise omits the cause.
func TestStationVoiceService_JingleCommitFailureReportsLiveFile(t *testing.T) {
	for _, cause := range []error{errors.New("commit connection lost"), context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			service, stationVoice := newJingleTestService(t, &jingleAudioRepository{})
			service.txManager = &jingleTxManager{err: cause}
			alerts := &capturingAlerter{}
			service.alerts = alerts
			logs := testutil.CaptureLogs(t, slog.LevelInfo)
			path := utils.JinglePath(service.config, stationVoice.StationID, stationVoice.VoiceID)
			input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=880:duration=1")
			if err := service.ProcessJingle(t.Context(), stationVoice, input); !errors.Is(err, cause) {
				t.Fatalf("ProcessJingle = %v, want %v", err, cause)
			}
			if len(alerts.events) != 1 || alerts.events[0].Key != "stationvoice:unrecorded-audio:3" ||
				alerts.events[0].RequiresThreshold || !strings.Contains(alerts.events[0].Details, path) ||
				!strings.Contains(alerts.events[0].Details, cause.Error()) || len(alerts.resolved) != 0 {
				t.Fatalf("alerts = %+v, resolved = %v; want one immediate alert naming the path and cause", alerts.events, alerts.resolved)
			}
			found := false
			for line := range bytes.Lines(logs.Bytes()) {
				var record map[string]any
				if err := json.Unmarshal(line, &record); err != nil {
					t.Fatal(err)
				}
				if record["level"] == "ERROR" && record["path"] == path && record["station_voice_id"] == float64(stationVoice.ID) &&
					strings.Contains(fmt.Sprint(record["error"]), cause.Error()) {
					found = true
				}
			}
			if !found {
				t.Fatalf("logs = %s, want an Error record naming the row, path and cause", logs)
			}
			// A later successful upload resolves precisely this incident.
			service.txManager = &jingleTxManager{}
			if err := service.ProcessJingle(t.Context(), stationVoice, input); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(alerts.resolved, []string{"stationvoice:unrecorded-audio:3"}) {
				t.Fatalf("resolved = %v, want the publication recovery", alerts.resolved)
			}
		})
	}
}

// jingleContextTxManager supplies the fake repository's transaction marker
// and models database/sql rolling back when its context is cancelled.
type jingleContextTxManager struct{}

func (*jingleContextTxManager) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	if err := fn(context.WithValue(ctx, jingleTxKey{}, true)); err != nil {
		return err
	}
	return ctx.Err()
}
