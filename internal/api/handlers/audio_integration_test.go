//go:build integration

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

// A purged bulletin's file is gone on purpose, so its audio returns 404
// without the missing-storage warning.
func TestGetBulletinAudioIntegration_PurgedBulletinDoesNotWarn(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	station := models.Station{Name: fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano()), MaxStoriesPerBlock: 5}
	if err := db.Create(&station).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&station).Error; err != nil {
			t.Errorf("delete station: %v", err)
		}
	})
	bulletin := models.Bulletin{StationID: station.ID, Filename: "purged.wav", AudioFile: "purged.wav"}
	if err := db.Create(&bulletin).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&bulletin).Error; err != nil {
			t.Errorf("delete bulletin: %v", err)
		}
	})
	if err := repository.NewBulletinRepository(db).MarkFilePurged(t.Context(), bulletin.ID); err != nil {
		t.Fatal(err)
	}
	h := NewHandlers(HandlersDeps{
		AudioRepo: repository.NewAudioRepository(db),
		Config:    &config.Config{Audio: config.AudioConfig{OutputPath: t.TempDir()}},
	})
	logs := testutil.CaptureLogs(t, slog.LevelWarn)
	c, recorder := newProblemContext(t)
	id := strconv.FormatInt(bulletin.ID, 10)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/bulletins/"+id+"/audio", nil)
	c.Params = gin.Params{{Key: "id", Value: id}}

	h.GetBulletinAudio(c)

	if recorder.Code != http.StatusNotFound || logs.Len() != 0 {
		t.Fatalf("status = %d, logs = %s; want 404 without logs", recorder.Code, logs)
	}
}
