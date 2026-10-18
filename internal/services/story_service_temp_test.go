package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

type inspectInputTx func() error

func (fn inspectInputTx) WithTransaction(context.Context, func(context.Context) error) error {
	return fn()
}

func TestGeneratedSpeechUsesOwnedTempDirectory(t *testing.T) {
	audioService := newPublishAudioTestService(t)
	input := lavfiFixture(t, audioService.config.Audio.FFmpegPath, "sine=frequency=440:duration=1")
	data, err := os.ReadFile(input) //nolint:gosec // Generated fixture in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	service := newGenerateTTSTestService(storyForTTSTest("News"), &models.TTSSettings{}, nil, &fakeSpeechGenerator{data: data})
	service.config, service.audioSvc = audioService.config, audioService.audioSvc
	dir := t.TempDir()
	service.config.Audio.TempPath = dir
	stop := errors.New("stop after conversion before publication")
	observed := false
	service.txManager = inspectInputTx(func() error {
		observed = true
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "tts_story_99_") || filepath.Ext(entries[0].Name()) != ".opus" {
			t.Errorf("owned input directory = %v, %v", entries, err)
		}
		return stop
	})
	if err := service.GenerateTTS(t.Context(), 99, true, nil); !errors.Is(err, stop) || !observed {
		t.Fatalf("GenerateTTS = %v, observed = %v", err, observed)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("input cleanup = %v, %v", entries, err)
	}
}
