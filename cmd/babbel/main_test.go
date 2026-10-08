package main

import (
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestServerWriteTimeout(t *testing.T) {
	tests := []struct {
		name            string
		generation, tts time.Duration
		want            time.Duration
	}{
		{name: "automation budget dominates", generation: 120 * time.Second, tts: 60 * time.Second, want: 6 * time.Minute},
		{name: "tts budget dominates", generation: 30 * time.Second, tts: 3 * time.Minute, want: 5 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Automation: config.AutomationConfig{GenerationTimeout: tt.generation},
				TTS:        config.TTSConfig{RequestTimeout: tt.tts},
			}
			if got := newServer(cfg, nil).WriteTimeout; got != tt.want {
				t.Fatalf("WriteTimeout = %s, want %s", got, tt.want)
			}
		})
	}
}
